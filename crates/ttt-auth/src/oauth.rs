use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use http::header::{HeaderName, HeaderValue};
use tokio::sync::Mutex;
use tracing::{info, warn};
use ttt_core::{GatewayError, OAuthPreset, TokenRequestFormat};

use crate::client::OAuthHttpClient;
use crate::store::{StoredOAuthToken, TokenStore};
use crate::Credential;

/// Immutable snapshot of an OAuth token pair stored in `ArcSwap`.
#[derive(Debug, Clone)]
pub struct OAuthTokenState {
    pub generation: u64,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<u64>,
    /// Pre-formatted header value for O(1) zero-alloc hot-path reads.
    pub header_value: HeaderValue,
}

/// Static OAuth client metadata needed for token refresh and login.
#[derive(Debug, Clone)]
pub struct OAuthClientMeta {
    pub account_id: String,
    pub preset: Option<OAuthPreset>,
    pub token_url: Option<String>,
    pub authorize_url: Option<String>,
    pub device_code_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub token_format: TokenRequestFormat,
    pub proactive_refresh_leeway_secs: u64,
}

/// Refreshed token payload returned by a refresh callback or OAuth token endpoint.
#[derive(Debug, Clone)]
pub struct RefreshedToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<u64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

/// Lock-free OAuth token manager with Singleflight refresh coalescing and encrypted persistence.
pub struct OAuthTokenManager {
    header_name: HeaderName,
    prefix: Option<String>,
    meta: OAuthClientMeta,
    state: Arc<ArcSwap<OAuthTokenState>>,
    refresh_lock: Mutex<()>,
    http_client: OAuthHttpClient,
    store: Option<Arc<dyn TokenStore>>,
}

impl OAuthTokenManager {
    pub fn new(
        header_name: &str,
        prefix: Option<String>,
        meta: OAuthClientMeta,
        initial_access_token: Option<String>,
        initial_refresh_token: Option<String>,
        initial_expires_at: Option<u64>,
        store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        let header_name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|e| {
            GatewayError::Config(format!("invalid oauth header name '{header_name}': {e}"))
        })?;

        // Prefer persisted encrypted token store (contains latest rotated tokens),
        // falling back to bootstrap values from config.
        let stored = match &store {
            Some(s) => s.get(&meta.account_id)?,
            None => None,
        };

        let (access_token, refresh_token, expires_at) = match stored {
            Some(tok) => (
                tok.access_token,
                tok.refresh_token.or(initial_refresh_token),
                tok.expires_at.or(initial_expires_at),
            ),
            None => (
                initial_access_token.unwrap_or_default(),
                initial_refresh_token,
                initial_expires_at,
            ),
        };

        let header_value = if access_token.is_empty() {
            HeaderValue::from_static("")
        } else {
            build_header_value(prefix.as_deref(), &access_token)?
        };

        let initial = OAuthTokenState {
            generation: 1,
            access_token,
            refresh_token,
            expires_at,
            header_value,
        };

        Ok(Self {
            header_name,
            prefix,
            meta,
            state: Arc::new(ArcSwap::from_pointee(initial)),
            refresh_lock: Mutex::new(()),
            http_client: OAuthHttpClient::new(),
            store,
        })
    }

    /// Lock-free read of the current credential and its generation number.
    #[inline]
    pub fn acquire(&self) -> (u64, Credential) {
        let guard = self.state.load();
        (
            guard.generation,
            Credential {
                header_name: self.header_name.clone(),
                header_value: guard.header_value.clone(),
            },
        )
    }

    pub fn current_state(&self) -> Arc<OAuthTokenState> {
        self.state.load_full()
    }

    /// Returns whether the current token is missing, expired, or within `leeway_secs` of expiring.
    pub fn needs_proactive_refresh(&self) -> bool {
        let guard = self.state.load();
        if guard.access_token.is_empty() {
            return self.can_refresh();
        }
        match guard.expires_at {
            Some(exp) => {
                now_epoch_secs().saturating_add(self.meta.proactive_refresh_leeway_secs) >= exp
            }
            None => false,
        }
    }

    pub fn client_meta(&self) -> &OAuthClientMeta {
        &self.meta
    }

    pub fn can_refresh(&self) -> bool {
        if self.meta.token_url.is_none() {
            return false;
        }
        let guard = self.state.load();
        let has_refresh_token = guard.refresh_token.is_some();
        let has_client_creds =
            self.meta.client_id.is_some() && self.meta.client_secret.is_some();
        has_refresh_token || has_client_creds
    }

    /// Atomically replace the active token in memory and persist it encrypted to disk.
    pub fn update_token(&self, refreshed: RefreshedToken) -> Result<u64, GatewayError> {
        let current = self.state.load();
        let next_gen = current.generation.wrapping_add(1);
        let header_value = build_header_value(self.prefix.as_deref(), &refreshed.access_token)?;

        let merged_refresh = refreshed
            .refresh_token
            .or_else(|| current.refresh_token.clone());

        let next = OAuthTokenState {
            generation: next_gen,
            access_token: refreshed.access_token.clone(),
            refresh_token: merged_refresh.clone(),
            expires_at: refreshed.expires_at,
            header_value,
        };
        self.state.store(Arc::new(next));

        if let Some(store) = &self.store {
            let record = StoredOAuthToken {
                access_token: refreshed.access_token,
                refresh_token: merged_refresh,
                expires_at: refreshed.expires_at,
                token_type: refreshed.token_type,
                scope: refreshed.scope,
                extra: HashMap::new(),
            };
            if let Err(err) = store.put(&self.meta.account_id, record) {
                warn!(
                    account_id = %self.meta.account_id,
                    error = %err,
                    "refreshed OAuth token in memory, but failed to persist to encrypted store"
                );
            }
        }

        Ok(next_gen)
    }

    /// Perform an HTTP token refresh (either `refresh_token` or `client_credentials`)
    /// coalesced via Singleflight so concurrent 401s only trigger one upstream refresh.
    pub async fn refresh_via_http(
        &self,
        failed_generation: u64,
    ) -> Result<Credential, GatewayError> {
        let client = self.http_client.clone();
        self.refresh_singleflight(failed_generation, |meta, maybe_rt| async move {
            let token_url = meta.token_url.as_deref().ok_or_else(|| {
                GatewayError::Auth(format!(
                    "oauth account '{}' missing token_url for refresh",
                    meta.account_id
                ))
            })?;

            if let Some(rt) = maybe_rt {
                info!(
                    account_id = %meta.account_id,
                    format = ?meta.token_format,
                    "refreshing OAuth access token via refresh_token grant"
                );
                client
                    .refresh_token(
                        token_url,
                        meta.token_format,
                        &rt,
                        meta.client_id.as_deref(),
                        meta.client_secret.as_deref(),
                        &meta.scopes,
                    )
                    .await
            } else if let (Some(cid), Some(secret)) =
                (meta.client_id.as_deref(), meta.client_secret.as_deref())
            {
                info!(
                    account_id = %meta.account_id,
                    "acquiring OAuth access token via client_credentials grant"
                );
                client
                    .client_credentials(token_url, meta.token_format, cid, secret, &meta.scopes)
                    .await
            } else {
                Err(GatewayError::Auth(format!(
                    "oauth account '{}' has neither refresh_token nor client_credentials",
                    meta.account_id
                )))
            }
        })
        .await
    }

    /// Coalesced (Singleflight) token refresh triggered by a 401 or proactive background refresh.
    pub async fn refresh_singleflight<F, Fut>(
        &self,
        failed_generation: u64,
        refresh_fn: F,
    ) -> Result<Credential, GatewayError>
    where
        F: FnOnce(OAuthClientMeta, Option<String>) -> Fut,
        Fut: Future<Output = Result<RefreshedToken, GatewayError>>,
    {
        let _guard = self.refresh_lock.lock().await;

        // Double-check after acquiring the lock: another caller may have already refreshed.
        let current = self.state.load();
        if current.generation != failed_generation {
            return Ok(Credential {
                header_name: self.header_name.clone(),
                header_value: current.header_value.clone(),
            });
        }

        let refreshed = refresh_fn(self.meta.clone(), current.refresh_token.clone()).await?;
        self.update_token(refreshed)?;

        let updated = self.state.load();
        Ok(Credential {
            header_name: self.header_name.clone(),
            header_value: updated.header_value.clone(),
        })
    }
}

fn build_header_value(prefix: Option<&str>, token: &str) -> Result<HeaderValue, GatewayError> {
    let formatted = match prefix {
        Some(p) => format!("{p}{token}"),
        None => token.to_string(),
    };
    let mut hv = HeaderValue::from_str(&formatted)
        .map_err(|e| GatewayError::Auth(format!("invalid oauth token header value: {e}")))?;
    hv.set_sensitive(true);
    Ok(hv)
}

#[inline]
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_refreshes() {
        let meta = OAuthClientMeta {
            account_id: "test-acct".into(),
            preset: Some(OAuthPreset::ClaudeCode),
            token_url: Some("https://auth.example.com/oauth/token".into()),
            authorize_url: None,
            device_code_url: None,
            client_id: Some("cid".into()),
            client_secret: None,
            scopes: vec![],
            redirect_uri: None,
            token_format: TokenRequestFormat::Json,
            proactive_refresh_leeway_secs: 300,
        };

        let mgr = Arc::new(
            OAuthTokenManager::new(
                "authorization",
                Some("Bearer ".into()),
                meta,
                Some("old-token".into()),
                Some("rt-1".into()),
                None,
                None,
            )
            .unwrap(),
        );

        let (gen0, cred0) = mgr.acquire();
        assert_eq!(cred0.header_value.to_str().unwrap(), "Bearer old-token");

        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&mgr);
            let calls = Arc::clone(&refresh_calls);
            handles.push(tokio::spawn(async move {
                m.refresh_singleflight(gen0, |_meta, _rt| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    Ok(RefreshedToken {
                        access_token: "new-token".into(),
                        refresh_token: Some("rt-2".into()),
                        expires_at: None,
                        token_type: Some("Bearer".into()),
                        scope: None,
                    })
                })
                .await
                .unwrap()
            }));
        }

        for h in handles {
            let cred = h.await.unwrap();
            assert_eq!(cred.header_value.to_str().unwrap(), "Bearer new-token");
        }
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
    }
}
