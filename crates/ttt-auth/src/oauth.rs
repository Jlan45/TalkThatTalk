use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use http::header::{HeaderName, HeaderValue};
use tokio::sync::Mutex;
use tracing::{info, warn};
use ttt_core::{GatewayError, OAuthPreset, TokenRequestFormat, UpstreamAuthConfig};

use crate::Credential;
use crate::client::OAuthHttpClient;
use crate::store::{StoredOAuthToken, TokenStore};

/// Immutable snapshot of an OAuth token pair stored in `ArcSwap`.
#[derive(Debug, Clone)]
pub struct OAuthTokenState {
    pub generation: u64,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<u64>,
    pub antigravity_project_id: Option<String>,
    pub reauthorization_required: bool,
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

impl RefreshedToken {
    pub(crate) fn into_stored(self) -> StoredOAuthToken {
        StoredOAuthToken {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at: self.expires_at,
            token_type: self.token_type,
            scope: self.scope,
            extra: HashMap::new(),
        }
    }
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

        let antigravity_project_id = stored
            .as_ref()
            .and_then(StoredOAuthToken::antigravity_project_id)
            .map(str::to_owned);
        let reauthorization_required = stored
            .as_ref()
            .is_some_and(StoredOAuthToken::requires_reauthorization);
        let (access_token, refresh_token, expires_at) = match stored {
            Some(_) if reauthorization_required => (String::new(), None, None),
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
            antigravity_project_id,
            reauthorization_required,
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
        if guard.reauthorization_required {
            return false;
        }
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
        if guard.reauthorization_required {
            return false;
        }
        let has_refresh_token = guard.refresh_token.is_some();
        if self.meta.preset == Some(OAuthPreset::Antigravity) {
            return has_refresh_token
                && self.meta.client_id.is_some()
                && UpstreamAuthConfig::oauth_client_secret(
                    self.meta.preset,
                    self.meta.client_secret.as_deref(),
                )
                .is_ok();
        }
        let has_client_creds = self.meta.client_id.is_some() && self.meta.client_secret.is_some();
        has_refresh_token || has_client_creds
    }

    pub async fn install_login(&self, record: StoredOAuthToken) -> Result<(), GatewayError> {
        let _guard = self.refresh_lock.lock().await;
        self.replace_token(record, true)
    }

    fn replace_token(
        &self,
        record: StoredOAuthToken,
        require_persistence: bool,
    ) -> Result<(), GatewayError> {
        let next = OAuthTokenState {
            generation: self.state.load().generation.wrapping_add(1),
            access_token: record.access_token.clone(),
            refresh_token: record.refresh_token.clone(),
            expires_at: record.expires_at,
            antigravity_project_id: record.antigravity_project_id().map(str::to_owned),
            reauthorization_required: record.requires_reauthorization(),
            header_value: if record.access_token.is_empty() {
                HeaderValue::from_static("")
            } else {
                build_header_value(self.prefix.as_deref(), &record.access_token)?
            },
        };
        if let Some(store) = &self.store
            && let Err(err) = store.put(&self.meta.account_id, record)
        {
            if require_persistence {
                return Err(err);
            }
            warn!(account_id = %self.meta.account_id, error = %err, "failed to persist refreshed OAuth token");
        }
        self.state.store(Arc::new(next));
        Ok(())
    }

    pub async fn antigravity_session(
        &self,
        endpoint: &str,
    ) -> Result<Arc<OAuthTokenState>, GatewayError> {
        let current = self.current_state();
        if current.antigravity_project_id.is_some() {
            return Ok(current);
        }
        if self.needs_proactive_refresh() && self.can_refresh() {
            self.refresh_via_http(current.generation).await?;
        }

        let _guard = self.refresh_lock.lock().await;
        let current = self.current_state();
        if current.antigravity_project_id.is_some() {
            return Ok(current);
        }
        if current.access_token.is_empty() {
            return Err(GatewayError::Auth("请先授权 Antigravity 渠道".into()));
        }
        let project = self
            .http_client
            .discover_antigravity_project(endpoint, &current.access_token)
            .await?;
        if let Some(store) = &self.store {
            let mut record =
                store
                    .get(&self.meta.account_id)?
                    .unwrap_or_else(|| StoredOAuthToken {
                        access_token: current.access_token.clone(),
                        refresh_token: current.refresh_token.clone(),
                        expires_at: current.expires_at,
                        token_type: None,
                        scope: None,
                        extra: HashMap::new(),
                    });
            if record.access_token == current.access_token {
                record.set_antigravity_project_id(project.clone());
                store.put(&self.meta.account_id, record)?;
            }
        }
        let updated = Arc::new(OAuthTokenState {
            antigravity_project_id: Some(project),
            ..(*current).clone()
        });
        self.state.store(updated.clone());
        Ok(updated)
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
            let client_secret = UpstreamAuthConfig::oauth_client_secret(
                meta.preset,
                meta.client_secret.as_deref(),
            )?;

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
                        client_secret,
                        &meta.scopes,
                    )
                    .await
            } else if meta.preset == Some(OAuthPreset::Antigravity) {
                Err(GatewayError::Auth(
                    "Antigravity 缺少 refresh token，请重新授权".into(),
                ))
            } else if let (Some(cid), Some(secret)) = (meta.client_id.as_deref(), client_secret) {
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
        if current.reauthorization_required {
            return Err(GatewayError::OAuthReauthorizationRequired);
        }
        if current.generation != failed_generation {
            return Ok(Credential {
                header_name: self.header_name.clone(),
                header_value: current.header_value.clone(),
            });
        }

        let mut record = match refresh_fn(self.meta.clone(), current.refresh_token.clone()).await {
            Ok(token) => token.into_stored(),
            Err(GatewayError::OAuthReauthorizationRequired) => {
                self.replace_token(
                    StoredOAuthToken {
                        access_token: String::new(),
                        refresh_token: None,
                        expires_at: None,
                        token_type: None,
                        scope: None,
                        extra: HashMap::from([("reauthorization_required".into(), "true".into())]),
                    },
                    false,
                )?;
                return Err(GatewayError::OAuthReauthorizationRequired);
            }
            Err(error) => return Err(error),
        };
        record.refresh_token = record
            .refresh_token
            .or_else(|| current.refresh_token.clone());
        if let Some(project) = &current.antigravity_project_id {
            record.set_antigravity_project_id(project.clone());
        }
        self.replace_token(record, false)?;

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
    async fn revoked_refresh_is_persisted_until_new_login() {
        let path =
            std::env::temp_dir().join(format!("ttt-revoked-oauth-{}.enc", std::process::id()));
        let store = Arc::new(crate::EncryptedTokenStore::with_key(&path, [43; 32]));
        let make_manager = || {
            OAuthTokenManager::new(
                "authorization",
                Some("Bearer ".into()),
                OAuthClientMeta {
                    account_id: "upstream:user:3:up_revoked".into(),
                    preset: Some(OAuthPreset::ClaudeCode),
                    token_url: Some("https://example.invalid/oauth/token".into()),
                    authorize_url: None,
                    device_code_url: None,
                    client_id: Some("local".into()),
                    client_secret: None,
                    scopes: Vec::new(),
                    redirect_uri: None,
                    token_format: TokenRequestFormat::Json,
                    proactive_refresh_leeway_secs: 300,
                },
                Some("initial-token".into()),
                Some("initial-refresh".into()),
                None,
                Some(store.clone()),
            )
            .unwrap()
        };
        let mgr = make_manager();
        let rejected = mgr
            .refresh_singleflight(mgr.current_state().generation, |_, _| async {
                Err(GatewayError::OAuthReauthorizationRequired)
            })
            .await;
        assert!(matches!(
            rejected,
            Err(GatewayError::OAuthReauthorizationRequired)
        ));
        assert!(!mgr.can_refresh());
        assert!(!mgr.needs_proactive_refresh());
        let reloaded = make_manager();
        assert!(reloaded.current_state().reauthorization_required);
        assert!(reloaded.current_state().access_token.is_empty());
        reloaded
            .install_login(
                RefreshedToken {
                    access_token: "new-token".into(),
                    refresh_token: Some("new-refresh".into()),
                    expires_at: None,
                    token_type: None,
                    scope: None,
                }
                .into_stored(),
            )
            .await
            .unwrap();
        let reloaded = make_manager();
        assert!(reloaded.can_refresh());
        assert_eq!(reloaded.current_state().access_token, "new-token");
        std::fs::remove_file(path).unwrap();
    }

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
