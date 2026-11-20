use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{header, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::{Map, Value};
use ttt_core::{GatewayError, TokenRequestFormat};
use url::form_urlencoded;

use crate::oauth::RefreshedToken;

/// Raw OAuth 2.0 token response (RFC 6749 §5.1).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenEndpointResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl TokenEndpointResponse {
    pub fn into_refreshed(self) -> RefreshedToken {
        let expires_at = self
            .expires_in
            .map(|secs| now_epoch_secs().saturating_add(secs));
        RefreshedToken {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            expires_at,
            token_type: self.token_type,
            scope: self.scope,
        }
    }
}

/// RFC 8628 Device Authorization response.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default = "default_device_expires")]
    pub expires_in: u64,
    #[serde(default = "default_device_interval")]
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Lightweight Hyper/Rustls OAuth 2.0 HTTP client supporting both Form and JSON token endpoints.
#[derive(Clone)]
pub struct OAuthHttpClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl OAuthHttpClient {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(Duration::from_secs(10)));

        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .build(https);

        Self { client }
    }

    /// Exchange an Authorization Code + PKCE verifier for tokens.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_code(
        &self,
        token_url: &str,
        format: TokenRequestFormat,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: Option<&str>,
        state: Option<&str>,
    ) -> Result<RefreshedToken, GatewayError> {
        let mut params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("code_verifier", code_verifier.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", client_id.to_string()),
        ];
        if let Some(secret) = client_secret {
            params.push(("client_secret", secret.to_string()));
        }
        if let Some(st) = state {
            params.push(("state", st.to_string()));
        }

        let resp: TokenEndpointResponse = self.post_params(token_url, format, &params).await?;
        Ok(resp.into_refreshed())
    }

    /// Refresh an access token using RFC 6749 `grant_type=refresh_token`.
    pub async fn refresh_token(
        &self,
        token_url: &str,
        format: TokenRequestFormat,
        refresh_token: &str,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        scopes: &[String],
    ) -> Result<RefreshedToken, GatewayError> {
        let mut params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
        ];
        if let Some(cid) = client_id {
            params.push(("client_id", cid.to_string()));
        }
        if let Some(secret) = client_secret {
            params.push(("client_secret", secret.to_string()));
        }
        if !scopes.is_empty() {
            params.push(("scope", scopes.join(" ")));
        }

        let resp: TokenEndpointResponse = self.post_params(token_url, format, &params).await?;
        Ok(resp.into_refreshed())
    }

    /// Acquire a token via RFC 6749 §4.4 Client Credentials grant.
    pub async fn client_credentials(
        &self,
        token_url: &str,
        format: TokenRequestFormat,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
    ) -> Result<RefreshedToken, GatewayError> {
        let mut params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id.to_string()),
            ("client_secret", client_secret.to_string()),
        ];
        if !scopes.is_empty() {
            params.push(("scope", scopes.join(" ")));
        }

        let resp: TokenEndpointResponse = self.post_params(token_url, format, &params).await?;
        Ok(resp.into_refreshed())
    }

    /// Step 1 of RFC 8628 Device Code Flow: request `device_code` and `user_code`.
    pub async fn request_device_code(
        &self,
        device_code_url: &str,
        format: TokenRequestFormat,
        client_id: &str,
        scopes: &[String],
    ) -> Result<DeviceCodeResponse, GatewayError> {
        let mut params = vec![("client_id", client_id.to_string())];
        if !scopes.is_empty() {
            params.push(("scope", scopes.join(" ")));
        }
        self.post_params(device_code_url, format, &params).await
    }

    /// Step 2 of RFC 8628 Device Code Flow: poll token endpoint until approved or expired.
    pub async fn poll_device_token(
        &self,
        token_url: &str,
        format: TokenRequestFormat,
        client_id: &str,
        device: &DeviceCodeResponse,
    ) -> Result<RefreshedToken, GatewayError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(device.expires_in);
        let mut interval = Duration::from_secs(device.interval.max(2));

        let params = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code", device.device_code.clone()),
            ("client_id", client_id.to_string()),
        ];

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(GatewayError::Auth("device code authorization timed out".into()));
            }
            tokio::time::sleep(interval).await;

            let (status, body) = self.post_raw(token_url, format, &params).await?;
            if status.is_success() {
                let parsed: TokenEndpointResponse = serde_json::from_slice(&body).map_err(|e| {
                    GatewayError::Auth(format!("invalid device token JSON response: {e}"))
                })?;
                return Ok(parsed.into_refreshed());
            }

            if let Ok(err_body) = serde_json::from_slice::<OAuthErrorBody>(&body) {
                match err_body.error.as_deref() {
                    Some("authorization_pending") => continue,
                    Some("slow_down") => {
                        interval += Duration::from_secs(5);
                        continue;
                    }
                    Some(other) => {
                        let desc = err_body.error_description.unwrap_or_default();
                        return Err(GatewayError::Auth(format!(
                            "device flow error '{other}': {desc}"
                        )));
                    }
                    None => {}
                }
            }

            return Err(GatewayError::Auth(format!(
                "device token endpoint returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            )));
        }
    }

    async fn post_params<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        format: TokenRequestFormat,
        params: &[(&str, String)],
    ) -> Result<T, GatewayError> {
        let (status, body) = self.post_raw(url, format, params).await?;
        if !status.is_success() {
            return Err(GatewayError::Auth(format!(
                "oauth endpoint {url} returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        serde_json::from_slice(&body)
            .map_err(|e| GatewayError::Auth(format!("failed to parse oauth JSON response: {e}")))
    }

    async fn post_raw(
        &self,
        url: &str,
        format: TokenRequestFormat,
        params: &[(&str, String)],
    ) -> Result<(http::StatusCode, Bytes), GatewayError> {
        let (content_type, payload) = match format {
            TokenRequestFormat::Form => {
                let mut ser = form_urlencoded::Serializer::new(String::new());
                for (k, v) in params {
                    ser.append_pair(k, v);
                }
                (
                    "application/x-www-form-urlencoded",
                    Bytes::from(ser.finish()),
                )
            }
            TokenRequestFormat::Json => {
                let mut obj = Map::with_capacity(params.len());
                for (k, v) in params {
                    obj.insert((*k).to_string(), Value::String(v.clone()));
                }
                let json_bytes = serde_json::to_vec(&obj).map_err(|e| {
                    GatewayError::Internal(format!("failed to serialize oauth JSON body: {e}"))
                })?;
                ("application/json", Bytes::from(json_bytes))
            }
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, "application/json")
            .body(Full::new(payload))
            .map_err(|e| GatewayError::Auth(format!("failed to build oauth request: {e}")))?;

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| GatewayError::Auth(format!("oauth HTTP request failed: {e}")))?;

        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| GatewayError::Auth(format!("failed to read oauth response body: {e}")))?
            .to_bytes();

        Ok((status, body))
    }
}

impl Default for OAuthHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn default_device_expires() -> u64 {
    600
}

fn default_device_interval() -> u64 {
    5
}

#[inline]
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
