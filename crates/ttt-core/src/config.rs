use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub pool: PoolConfig,

    #[serde(default)]
    pub telemetry: TelemetryConfig,

    #[serde(default, alias = "storage")]
    pub oauth_storage: OAuthStorageConfig,

    /// Optional bootstrap upstreams (deprecated in TOML; persisted in SQLite at runtime).
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStorageConfig {
    /// Path to embedded SQLite database storing upstreams, client keys, and request logs.
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Path to AES-256-GCM encrypted OAuth token store file.
    #[serde(default = "default_token_store_path")]
    pub store_path: String,

    /// Environment variable containing a base64-encoded 32-byte master key.
    /// If unset, a local 0600 key file next to `store_path` is used or created automatically.
    #[serde(default = "default_master_key_env")]
    pub master_key_env: String,
}

impl Default for OAuthStorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            store_path: default_token_store_path(),
            master_key_env: default_master_key_env(),
        }
    }
}

/// Gateway client API key with optional Provider (upstream) and Model level access controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientKeyConfig {
    pub key: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// When enabled, only upstreams listed in `allowed_upstreams` may be routed.
    #[serde(default)]
    pub restrict_upstreams: bool,
    #[serde(default)]
    pub allowed_upstreams: Vec<String>,
    /// When enabled, only models listed in `allowed_models` may be requested.
    #[serde(default)]
    pub restrict_models: bool,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Owning user ID (`None` = admin/global key; `Some(id)` = owned by that user).
    #[serde(default)]
    pub owner_user_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Disable Nagle algorithm for lower SSE latency.
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,

    /// Maximum seconds to wait for in-flight SSE connections on shutdown.
    #[serde(default = "default_shutdown_secs")]
    pub graceful_shutdown_secs: u64,

    /// Legacy simple client API keys (unrestricted). Prefer `client_keys` for scoped policies.
    #[serde(default)]
    pub client_api_keys: Vec<String>,

    /// Scoped client API keys supporting provider/model restriction toggles.
    #[serde(default)]
    pub client_keys: Vec<ClientKeyConfig>,

    /// Optional admin API key protecting `/api/v1/*` management endpoints.
    /// When unset, management endpoints are open (suitable for local development).
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// Maximum request body size (bytes) eligible for lightweight model extraction/rewriting.
    /// Larger bodies bypass inspection and stream directly to the default upstream.
    #[serde(default = "default_max_inspect_bytes")]
    pub max_inspect_body_bytes: usize,
}

impl ServerConfig {
    /// Merge `client_keys` and legacy `client_api_keys` into a unified list (deduped by key).
    pub fn effective_client_keys(&self) -> Vec<ClientKeyConfig> {
        let mut out = self.client_keys.clone();
        for raw in &self.client_api_keys {
            if !out.iter().any(|k| k.key == *raw) {
                out.push(ClientKeyConfig {
                    key: raw.clone(),
                    name: String::new(),
                    enabled: true,
                    restrict_upstreams: false,
                    allowed_upstreams: Vec::new(),
                    restrict_models: false,
                    allowed_models: Vec::new(),
                    owner_user_id: None,
                });
            }
        }
        out
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            tcp_nodelay: true,
            graceful_shutdown_secs: default_shutdown_secs(),
            client_api_keys: Vec::new(),
            client_keys: Vec::new(),
            admin_api_key: None,
            max_inspect_body_bytes: default_max_inspect_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    #[serde(default = "default_max_idle_per_host")]
    pub max_idle_per_host: usize,

    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    #[serde(default = "default_true")]
    pub http2_adaptive_window: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_idle_timeout_secs(),
            max_idle_per_host: default_max_idle_per_host(),
            connect_timeout_ms: default_connect_timeout_ms(),
            http2_adaptive_window: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Bounded channel capacity for zero-copy side-channel tap events.
    #[serde(default = "default_tap_capacity")]
    pub tap_channel_capacity: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            tap_channel_capacity: default_tap_capacity(),
        }
    }
}

/// Core wire protocol families implemented in the fixed L1 framework (`ttt-protocol`).
/// Specific providers (DeepSeek, OpenRouter, Codex, Claude Code, Gemini, vLLM, etc.)
/// are composed declaratively in TOML on top of these families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProtocolFamily {
    /// OpenAI Chat Completions (`/v1/chat/completions`)
    #[default]
    #[serde(rename = "openai", alias = "openai_chat", alias = "open_ai")]
    OpenAi,
    /// OpenAI Responses / Codex (`/v1/responses`)
    #[serde(rename = "openai_responses", alias = "codex")]
    OpenAiResponses,
    /// Anthropic Messages / Claude Code (`/v1/messages`)
    #[serde(rename = "anthropic", alias = "claude")]
    Anthropic,
    /// Google Gemini (`/v1beta/models/{model}:generateContent`)
    #[serde(rename = "gemini")]
    Gemini,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    /// Legacy/primary base URL. Prefer `protocol_endpoints` for multi-protocol providers.
    #[serde(default)]
    pub base_url: String,
    /// Primary/fallback wire protocol family (defaults to `openai`).
    #[serde(default)]
    pub protocol: ProtocolFamily,
    /// Native multi-protocol endpoint map (`ProtocolFamily -> base_url`).
    /// Requests matching any key here bypass protocol translation and run zero-copy.
    #[serde(default)]
    pub protocol_endpoints: HashMap<ProtocolFamily, String>,
    pub auth: UpstreamAuthConfig,

    /// Model names routed to this upstream. Supports "*" wildcard.
    #[serde(default = "default_wildcard_models")]
    pub models: Vec<String>,

    /// Optional model alias rewrite table (client_model -> upstream_model).
    #[serde(default)]
    pub model_mapping: HashMap<String, String>,

    /// Static extra headers injected into all upstream requests.
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,

    /// Per-protocol extra headers injected only when routing to that specific protocol.
    #[serde(default)]
    pub protocol_headers: HashMap<ProtocolFamily, HashMap<String, String>>,

    /// Routing weight for weighted round-robin.
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Cooldown duration (seconds) when upstream returns 429 without Retry-After.
    #[serde(default = "default_cooldown_secs")]
    pub default_cooldown_secs: u64,

    /// Maximum pre-first-byte retries on transient upstream failures.
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,

    /// Owning user ID (`None` = global shared provider; `Some(id)` = private user provider).
    #[serde(default)]
    pub owner_user_id: Option<i64>,

    /// Optional outbound proxy name (configured in SQLite `proxies` table via embedded `leaf`).
    #[serde(default)]
    pub proxy: Option<String>,
}

/// Supported outbound proxy protocols backed by embedded `eycorsican/leaf` (and native HTTP CONNECT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Shadowsocks,
    Trojan,
    Vmess,
    Vless,
}

/// Declarative outbound proxy node stored encrypted in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub name: String,
    pub protocol: ProxyProtocol,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    /// Password (HTTP / SOCKS5 / Shadowsocks / Trojan) or UUID (VMess / VLESS).
    #[serde(default)]
    pub password: Option<String>,
    /// Cipher / security method (e.g. `aes-256-gcm`, `chacha20-ietf-poly1305`, `auto`).
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::Config("proxy name cannot be empty".into()));
        }
        if self.server.trim().is_empty() {
            return Err(GatewayError::Config(format!(
                "proxy '{}' server cannot be empty",
                self.name
            )));
        }
        if self.port == 0 {
            return Err(GatewayError::Config(format!(
                "proxy '{}' port must be > 0",
                self.name
            )));
        }
        match self.protocol {
            ProxyProtocol::Shadowsocks => {
                if self.password.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(GatewayError::Config(format!(
                        "shadowsocks proxy '{}' requires a password",
                        self.name
                    )));
                }
            }
            ProxyProtocol::Trojan => {
                if self.password.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(GatewayError::Config(format!(
                        "trojan proxy '{}' requires a password",
                        self.name
                    )));
                }
            }
            ProxyProtocol::Vmess | ProxyProtocol::Vless => {
                if self.password.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(GatewayError::Config(format!(
                        "{:?} proxy '{}' requires a UUID in password",
                        self.protocol, self.name
                    )));
                }
            }
            ProxyProtocol::Http | ProxyProtocol::Socks5 => {}
        }
        Ok(())
    }
}

/// Built-in OAuth 2.0 protocol presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthPreset {
    /// OpenAI Codex style: Authorization Code + PKCE (or Device Code), form-urlencoded token endpoint.
    Codex,
    /// Anthropic Claude Code style: Authorization Code + PKCE, JSON token endpoint, supports `code#state`.
    ClaudeCode,
    /// Generic RFC 6749 / 7636 / 8628 provider.
    Custom,
}

/// Built-in public PKCE endpoint defaults for official OAuth presets.
#[derive(Debug, Clone, Copy)]
pub struct OAuthPresetDefaults {
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub client_id: &'static str,
    pub redirect_uri: &'static str,
    pub scopes: &'static [&'static str],
}

impl OAuthPreset {
    pub fn defaults(self) -> Option<OAuthPresetDefaults> {
        match self {
            Self::Codex => Some(OAuthPresetDefaults {
                authorize_url: "https://auth.openai.com/oauth/authorize",
                token_url: "https://auth.openai.com/oauth/token",
                client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
                redirect_uri: "http://localhost:1455/auth/callback",
                scopes: &["openid", "profile", "email", "offline_access"],
            }),
            Self::ClaudeCode => Some(OAuthPresetDefaults {
                authorize_url: "https://claude.ai/oauth/authorize",
                token_url: "https://console.anthropic.com/v1/oauth/token",
                client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
                redirect_uri: "https://console.anthropic.com/oauth/code/callback",
                scopes: &["org:create_api_key", "user:profile", "user:inference"],
            }),
            Self::Custom => None,
        }
    }
}

/// Wire format expected by the upstream OAuth token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenRequestFormat {
    Form,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum UpstreamAuthConfig {
    /// API Base mode: static API key pool with customizable header name & prefix.
    ApiKey {
        keys: Vec<String>,
        #[serde(default = "default_auth_header")]
        header_name: String,
        #[serde(default = "default_bearer_prefix")]
        prefix: Option<String>,
    },
    /// Native OAuth 2.0 mode: lock-free token state with PKCE/Device/ClientCredentials & auto-refresh.
    #[serde(rename = "oauth", alias = "o_auth")]
    OAuth {
        /// Optional protocol preset (`codex`, `claude_code`, `custom`).
        #[serde(default)]
        preset: Option<OAuthPreset>,
        /// Optional static/bootstrap access token. When omitted, loaded from the encrypted token store.
        #[serde(default)]
        access_token: Option<String>,
        #[serde(default)]
        refresh_token: Option<String>,
        /// Unix timestamp (seconds) when access_token expires.
        #[serde(default)]
        expires_at: Option<u64>,
        /// Authorization endpoint URL (for PKCE login).
        #[serde(default)]
        authorize_url: Option<String>,
        /// Device authorization endpoint URL (for RFC 8628 Device Code Flow).
        #[serde(default)]
        device_code_url: Option<String>,
        /// Token exchange & refresh endpoint URL.
        #[serde(default)]
        token_url: Option<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default)]
        redirect_uri: Option<String>,
        /// Override wire format (`form` or `json`). Defaults based on `preset`.
        #[serde(default)]
        token_request_format: Option<TokenRequestFormat>,
        /// Account key inside the encrypted token store (defaults to upstream name).
        #[serde(default)]
        account_id: Option<String>,
        /// Seconds before expiration to trigger proactive background refresh.
        #[serde(default = "default_refresh_leeway_secs")]
        proactive_refresh_leeway_secs: u64,
        #[serde(default = "default_auth_header")]
        header_name: String,
        #[serde(default = "default_bearer_prefix")]
        prefix: Option<String>,
    },
}

impl UpstreamAuthConfig {
    pub fn effective_token_format(
        preset: Option<OAuthPreset>,
        explicit: Option<TokenRequestFormat>,
    ) -> TokenRequestFormat {
        if let Some(fmt) = explicit {
            return fmt;
        }
        match preset {
            Some(OAuthPreset::ClaudeCode) => TokenRequestFormat::Json,
            Some(OAuthPreset::Codex) | Some(OAuthPreset::Custom) | None => TokenRequestFormat::Form,
        }
    }
}

impl UpstreamConfig {
    /// Join `base_url` with an endpoint entry.
    /// If `endpoint` is already a full `http(s)://` URL, returns it as-is;
    /// otherwise returns `base_url + endpoint`.
    pub fn join_base_and_endpoint(base_url: &str, endpoint: &str) -> String {
        let ep = endpoint.trim();
        if ep.starts_with("http://") || ep.starts_with("https://") {
            return ep.to_string();
        }
        let base = base_url.trim().trim_end_matches('/');
        if ep.is_empty() || ep == "/" {
            return base.to_string();
        }
        if ep.starts_with('/') {
            format!("{base}{ep}")
        } else {
            format!("{base}/{ep}")
        }
    }

    /// Unified view of all native protocol endpoints configured on this upstream
    /// resolved to full URLs (`base_url + endpoint`).
    pub fn effective_endpoints(&self) -> HashMap<ProtocolFamily, String> {
        let mut map = HashMap::new();
        for (proto, ep) in &self.protocol_endpoints {
            let resolved = Self::join_base_and_endpoint(&self.base_url, ep);
            if !resolved.is_empty() {
                map.insert(*proto, resolved);
            }
        }
        if map.is_empty() && !self.base_url.trim().is_empty() {
            map.insert(self.protocol, self.base_url.trim().to_string());
        }
        map
    }

    /// Primary protocol family used as fallback when an incoming protocol is not natively listed.
    pub fn primary_protocol(&self) -> ProtocolFamily {
        let map = self.effective_endpoints();
        if map.contains_key(&self.protocol) {
            self.protocol
        } else {
            map.keys().next().copied().unwrap_or(self.protocol)
        }
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::Config("upstream name cannot be empty".into()));
        }
        let endpoints = self.effective_endpoints();
        if endpoints.is_empty() {
            return Err(GatewayError::Config(format!(
                "upstream '{}' requires base_url and/or protocol_endpoints",
                self.name
            )));
        }
        for (proto, url) in &endpoints {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(GatewayError::Config(format!(
                    "upstream '{}' resolved URL '{}' for {:?} must start with http:// or https://",
                    self.name, url, proto
                )));
            }
        }
        if self.weight == 0 {
            return Err(GatewayError::Config(format!(
                "upstream '{}' weight must be >= 1",
                self.name
            )));
        }
        match &self.auth {
            UpstreamAuthConfig::ApiKey { keys, .. } => {
                if keys.is_empty() {
                    return Err(GatewayError::Config(format!(
                        "upstream '{}' api_key mode requires at least one key",
                        self.name
                    )));
                }
            }
            UpstreamAuthConfig::OAuth {
                preset,
                access_token,
                refresh_token,
                token_url,
                client_id,
                client_secret,
                ..
            } => {
                let has_preset_defaults = preset.and_then(OAuthPreset::defaults).is_some();
                let has_bootstrap = access_token
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                let has_refresh_or_m2m = token_url.is_some()
                    && (refresh_token.is_some()
                        || (client_id.is_some() && client_secret.is_some()));
                let has_store_binding = token_url.is_some() || client_id.is_some();
                if !has_preset_defaults
                    && !has_bootstrap
                    && !has_refresh_or_m2m
                    && !has_store_binding
                {
                    return Err(GatewayError::Config(format!(
                        "upstream '{}' oauth mode requires preset, access_token, or OAuth endpoint metadata",
                        self.name
                    )));
                }
            }
        }
        Ok(())
    }
}

impl GatewayConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| GatewayError::Config(format!("failed to read config file: {e}")))?;
        let cfg: Self = toml::from_str(&content)
            .map_err(|e| GatewayError::Config(format!("failed to parse TOML config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        for up in &self.upstreams {
            up.validate()?;
        }
        Ok(())
    }
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_db_path() -> String {
    "data/talkthattalk.db".to_string()
}

fn default_token_store_path() -> String {
    "data/oauth-tokens.enc".to_string()
}

fn default_master_key_env() -> String {
    "TTT_MASTER_KEY".to_string()
}

fn default_true() -> bool {
    true
}

fn default_shutdown_secs() -> u64 {
    30
}

fn default_max_inspect_bytes() -> usize {
    4 * 1024 * 1024 // 4 MiB
}

fn default_idle_timeout_secs() -> u64 {
    90
}

fn default_max_idle_per_host() -> usize {
    64
}

fn default_connect_timeout_ms() -> u64 {
    5_000
}

fn default_tap_capacity() -> usize {
    4096
}

fn default_wildcard_models() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_weight() -> u32 {
    1
}

fn default_cooldown_secs() -> u64 {
    30
}

fn default_max_retries() -> usize {
    1
}

fn default_refresh_leeway_secs() -> u64 {
    300
}

fn default_auth_header() -> String {
    "authorization".to_string()
}

fn default_bearer_prefix() -> Option<String> {
    Some("Bearer ".to_string())
}
