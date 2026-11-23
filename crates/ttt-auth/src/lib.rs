pub mod api_key;
pub mod client;
pub mod oauth;
pub mod pkce;
pub mod store;

use std::sync::Arc;

use http::header::{HeaderName, HeaderValue};
use ttt_core::{GatewayError, UpstreamAuthConfig};

pub use api_key::ApiKeyPool;
pub use client::{DeviceCodeResponse, OAuthHttpClient, TokenEndpointResponse};
pub use oauth::{OAuthClientMeta, OAuthTokenManager, OAuthTokenState, RefreshedToken};
pub use pkce::{build_authorize_url, generate_state, parse_authorization_input, PkceChallenge};
pub use store::{EncryptedTokenStore, StoredOAuthToken, TokenStore};

/// Pre-encoded HTTP authentication header ready for zero-allocation injection.
#[derive(Debug, Clone)]
pub struct Credential {
    pub header_name: HeaderName,
    pub header_value: HeaderValue,
}

/// Identifies which slot or token generation was used for a request,
/// enabling per-key 429 cooldown or OAuth 401 Singleflight refresh.
#[derive(Debug, Clone, Copy)]
pub enum CredentialHandle {
    ApiKeySlot(usize),
    OAuthGeneration(u64),
}

/// Static-dispatch upstream authentication provider supporting both API Base and OAuth modes.
pub enum AuthProvider {
    ApiKey(ApiKeyPool),
    OAuth(Box<OAuthTokenManager>),
}

impl AuthProvider {
    pub fn from_config(
        upstream_name: &str,
        cfg: &UpstreamAuthConfig,
        token_store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        match cfg {
            UpstreamAuthConfig::ApiKey {
                keys,
                header_name,
                prefix,
            } => Ok(Self::ApiKey(ApiKeyPool::new(
                header_name,
                prefix.as_deref(),
                keys,
            )?)),
            UpstreamAuthConfig::OAuth {
                preset,
                access_token,
                refresh_token,
                expires_at,
                authorize_url,
                device_code_url,
                token_url,
                scopes,
                redirect_uri,
                token_request_format,
                account_id,
                proactive_refresh_leeway_secs,
                header_name,
                prefix,
                ..
            } => {
                let defaults = preset.and_then(|p| p.defaults());
                let (client_id, client_secret) = cfg.oauth_credentials();
                let token_format =
                    UpstreamAuthConfig::effective_token_format(*preset, *token_request_format);
                let resolved_scopes = if scopes.is_empty() {
                    defaults
                        .map(|d| d.scopes.iter().map(|s| (*s).to_string()).collect())
                        .unwrap_or_default()
                } else {
                    scopes.clone()
                };
                let meta = OAuthClientMeta {
                    account_id: account_id
                        .clone()
                        .unwrap_or_else(|| upstream_name.to_string()),
                    preset: *preset,
                    token_url: token_url
                        .clone()
                        .or_else(|| defaults.map(|d| d.token_url.to_string())),
                    authorize_url: authorize_url
                        .clone()
                        .or_else(|| defaults.map(|d| d.authorize_url.to_string())),
                    device_code_url: device_code_url.clone(),
                    client_id,
                    client_secret,
                    scopes: resolved_scopes,
                    redirect_uri: redirect_uri
                        .clone()
                        .or_else(|| defaults.map(|d| d.redirect_uri.to_string())),
                    token_format,
                    proactive_refresh_leeway_secs: *proactive_refresh_leeway_secs,
                };
                Ok(Self::OAuth(Box::new(OAuthTokenManager::new(
                    header_name,
                    prefix.clone(),
                    meta,
                    access_token.clone(),
                    refresh_token.clone(),
                    *expires_at,
                    token_store,
                )?)))
            }
        }
    }

    /// Lock-free acquisition of an upstream credential.
    #[inline]
    pub fn acquire(&self) -> (CredentialHandle, Credential) {
        match self {
            Self::ApiKey(pool) => {
                let (idx, cred) = pool.acquire();
                (CredentialHandle::ApiKeySlot(idx), cred)
            }
            Self::OAuth(mgr) => {
                let (generation, cred) = mgr.acquire();
                (CredentialHandle::OAuthGeneration(generation), cred)
            }
        }
    }

    /// Notify the provider that a credential encountered 429 rate-limiting.
    pub fn on_rate_limited(&self, handle: CredentialHandle, cooldown_secs: u64) {
        if let (Self::ApiKey(pool), CredentialHandle::ApiKeySlot(idx)) = (self, handle) {
            pool.mark_cooldown(idx, cooldown_secs);
        }
    }

    pub fn oauth_manager(&self) -> Option<&OAuthTokenManager> {
        match self {
            Self::OAuth(mgr) => Some(mgr),
            Self::ApiKey(_) => None,
        }
    }

    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::OAuth(_) => "oauth",
        }
    }
}
