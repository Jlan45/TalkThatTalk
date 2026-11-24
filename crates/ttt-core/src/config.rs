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

    #[serde(default)]
    pub routing: RoutingConfig,

    /// Optional bootstrap upstreams (deprecated in TOML; persisted in SQLite at runtime).
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
}

/// Routing, session affinity, and fault-cooldown policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Enable session and context-prefix affinity routing (default: true).
    #[serde(default = "default_true")]
    pub affinity_enabled: bool,

    /// Additional custom session header names (checked before built-in agent headers).
    #[serde(default)]
    pub session_headers: Vec<String>,

    /// Fall back to canonical context-prefix fingerprinting when no explicit session key exists.
    #[serde(default = "default_true")]
    pub prefix_fallback_enabled: bool,

    /// Maximum canonical prefix bytes hashed for context-prefix fingerprinting.
    #[serde(default = "default_prefix_max_bytes")]
    pub prefix_max_bytes: usize,

    /// Minimum extracted prefix bytes required to activate prefix affinity.
    #[serde(default = "default_prefix_min_bytes")]
    pub prefix_min_bytes: usize,

    /// Soft-sticky TTL (seconds) for keeping sessions on a healthy failover upstream.
    #[serde(default = "default_sticky_failover_ttl_secs")]
    pub sticky_failover_ttl_secs: u64,

    /// Base short-cooldown seconds for transient 5xx / connect errors (exponential backoff up to 60s).
    #[serde(default = "default_failure_cooldown_base_secs")]
    pub failure_cooldown_base_secs: u64,

    /// Demote upstreams whose background quota probe reports `Exhausted`.
    #[serde(default = "default_true")]
    pub quota_aware: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            affinity_enabled: true,
            session_headers: Vec::new(),
            prefix_fallback_enabled: true,
            prefix_max_bytes: default_prefix_max_bytes(),
            prefix_min_bytes: default_prefix_min_bytes(),
            sticky_failover_ttl_secs: default_sticky_failover_ttl_secs(),
            failure_cooldown_base_secs: default_failure_cooldown_base_secs(),
            quota_aware: true,
        }
    }
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
    /// Google Antigravity / Cloud Code Assist (`/v1internal:generateContent`)
    #[serde(rename = "antigravity")]
    Antigravity,
}

/// Built-in provider prompt cache & outbound session compatibility profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PromptCacheMode {
    /// Auto-detect from OAuth preset and endpoint host (default).
    #[default]
    Auto,
    /// OpenAI / Azure OpenAI / Codex style (`session_id` header on Responses, preserves `prompt_cache_key`).
    OpenAi,
    /// Strict OpenAI-compatible providers (such as DeepSeek): strip `prompt_cache_key`
    /// and `prompt_cache_retention` before forwarding so upstream does not return 400.
    StripOpenAiCacheFields,
    /// Volcengine Ark: preserve the routing affinity key and strip OpenAI-specific retention.
    VolcengineArk,
    /// xAI Grok API (`x-grok-conv-id` outbound sticky header).
    XaiGrok,
    /// OpenRouter API (`x-session-id` outbound sticky header).
    OpenRouter,
    /// OpenCode Go / Zen (`x-opencode-session` outbound sticky header with per-request fallback).
    #[serde(rename = "opencode")]
    OpenCode,
    /// Pure passthrough without automatic session header injection or cache field stripping.
    Passthrough,
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

    /// Optional outbound proxy name (configured in the SQLite `proxies` table).
    #[serde(default)]
    pub proxy: Option<String>,

    /// Optional quota / usage monitoring configuration (Claude Code, Codex, or custom HTTP JSON).
    #[serde(default)]
    pub quota: Option<QuotaMonitorConfig>,

    /// Optional outbound HTTP header name used to forward the normalized session ID
    /// (e.g. `"session_id"`, `"x-session-id"`). Defaults to `"session_id"` on Codex / Responses upstreams.
    #[serde(default)]
    pub session_header_out: Option<String>,

    /// When true, strip other incoming agent session headers before forwarding upstream,
    /// retaining only the resolved outbound session header.
    #[serde(default)]
    pub strip_other_session_headers: bool,

    /// Built-in provider prompt cache compatibility mode (`auto`, `open_ai`,
    /// `strip_open_ai_cache_fields`, `volcengine_ark`, `xai_grok`, `open_router`, `passthrough`).
    #[serde(default)]
    pub prompt_cache_mode: PromptCacheMode,
}

/// Supported quota monitoring probe types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuotaProbeKind {
    /// Auto-detect based on the OAuth preset or a known API endpoint.
    #[default]
    Auto,
    /// Anthropic Claude Code OAuth usage endpoint (`/api/oauth/usage`).
    ClaudeCode,
    /// OpenAI Codex ChatGPT usage endpoint (`/backend-api/wham/usage`).
    Codex,
    /// Google Antigravity available models & quota endpoint (`/v1internal:fetchAvailableModels`).
    Antigravity,
    /// OpenCode Go rolling, weekly, and monthly usage limits.
    #[serde(rename = "opencode_go")]
    OpenCodeGo,
    /// Generic declarative HTTP JSON endpoint with dot-path extraction.
    CustomHttp,
}

fn default_quota_poll_interval_secs() -> u64 {
    300
}

/// Per-upstream quota monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaMonitorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub probe: QuotaProbeKind,
    /// Polling interval in seconds (clamped to >= 60s to avoid upstream rate limits).
    #[serde(default = "default_quota_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Optional `ChatGPT-Account-Id` header for Codex workspace/team usage queries.
    #[serde(default)]
    pub chatgpt_account_id: Option<String>,
    /// Custom HTTP probe URL (for `custom_http` mode).
    #[serde(default)]
    pub custom_url: Option<String>,
    /// Custom HTTP headers (supports `{{api_key}}` placeholder).
    #[serde(default)]
    pub custom_headers: HashMap<String, String>,
    /// Dot-separated JSON path for remaining amount (e.g. `data.remain_quota`).
    #[serde(default)]
    pub remaining_path: Option<String>,
    /// Dot-separated JSON path for used amount.
    #[serde(default)]
    pub used_path: Option<String>,
    /// Dot-separated JSON path for total amount.
    #[serde(default)]
    pub total_path: Option<String>,
    /// Multiplier applied to extracted raw numbers (e.g. `0.000002` for 500k = $1).
    #[serde(default)]
    pub scale: Option<f64>,
    /// Currency label for monetary probes (defaults to `USD`).
    #[serde(default)]
    pub currency: Option<String>,
}

/// Overall health status of an upstream's quota snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaStatus {
    Healthy,
    Low,
    Exhausted,
    Error,
}

/// Normalized quota dimension supporting both window-based (Claude/Codex) and monetary balances.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuotaDimension {
    WindowUtilization {
        window: String,
        used_percent: f64,
        resets_at: Option<i64>,
    },
    Monetary {
        currency: String,
        remaining: Option<f64>,
        used: Option<f64>,
        total: Option<f64>,
    },
}

/// Latest probed quota snapshot for an upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaSnapshot {
    pub upstream: String,
    pub probe: QuotaProbeKind,
    pub status: QuotaStatus,
    #[serde(default)]
    pub dimensions: Vec<QuotaDimension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub available_models: Vec<String>,
    #[serde(default)]
    pub plan_type: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    pub fetched_at: i64,
}

pub const ANTIGRAVITY_USER_AGENT: &str = "antigravity/1.15.8 linux/amd64";

/// Supported outbound proxy protocols backed by ClashRS and native HTTP CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Shadowsocks,
    Trojan,
    Vmess,
    Vless,
    Anytls,
    Hysteria2,
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
    /// Password or UUID (VMess / VLESS).
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_options: Option<ClashProxyOptions>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashProxyOptions {
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub alter_id: u16,
    pub flow: Option<String>,
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub ws_max_early_data: Option<u16>,
    pub ws_early_data_header: Option<String>,
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
            ProxyProtocol::Shadowsocks
            | ProxyProtocol::Trojan
            | ProxyProtocol::Anytls
            | ProxyProtocol::Hysteria2 => {
                if self.password.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(GatewayError::Config(format!(
                        "{:?} proxy '{}' requires a password",
                        self.protocol, self.name
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
    /// Google Antigravity style: Google OAuth 2.0 Authorization Code + PKCE, form-urlencoded token endpoint.
    Antigravity,
    /// Generic RFC 6749 / 7636 / 8628 provider.
    Custom,
}

/// Built-in public PKCE endpoint defaults for official OAuth presets.
#[derive(Debug, Clone, Copy)]
pub struct OAuthPresetDefaults {
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub client_id: Option<&'static str>,
    pub redirect_uri: &'static str,
    pub scopes: &'static [&'static str],
}

impl OAuthPreset {
    pub fn authorization_params(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Antigravity => &[("access_type", "offline"), ("prompt", "consent")],
            _ => &[],
        }
    }

    pub fn defaults(self) -> Option<OAuthPresetDefaults> {
        match self {
            Self::Codex => Some(OAuthPresetDefaults {
                authorize_url: "https://auth.openai.com/oauth/authorize",
                token_url: "https://auth.openai.com/oauth/token",
                client_id: Some("app_EMoamEEZ73f0CkXaXp7hrann"),
                redirect_uri: "http://localhost:1455/auth/callback",
                scopes: &["openid", "profile", "email", "offline_access"],
            }),
            Self::ClaudeCode => Some(OAuthPresetDefaults {
                authorize_url: "https://claude.ai/oauth/authorize",
                token_url: "https://console.anthropic.com/v1/oauth/token",
                client_id: Some("9d1c250a-e61b-44d9-88ed-5944d1962f5e"),
                redirect_uri: "https://console.anthropic.com/oauth/code/callback",
                scopes: &["org:create_api_key", "user:profile", "user:inference"],
            }),
            Self::Antigravity => Some(OAuthPresetDefaults {
                authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
                token_url: "https://oauth2.googleapis.com/token",
                client_id: None,
                redirect_uri: "http://localhost:51121/oauth-callback",
                scopes: &[
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/cclog",
                    "https://www.googleapis.com/auth/experimentsandconfigs",
                ],
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
    pub fn oauth_credentials(&self) -> (Option<String>, Option<String>) {
        let Self::OAuth {
            preset,
            authorize_url,
            token_url,
            client_id,
            client_secret,
            ..
        } = self
        else {
            return (None, None);
        };
        let defaults = preset.and_then(OAuthPreset::defaults);
        if *preset == Some(OAuthPreset::Antigravity)
            && client_secret
                .as_deref()
                .is_none_or(|secret| secret.trim().is_empty())
            && let Some(defaults) = defaults
            && authorize_url.as_deref().unwrap_or(defaults.authorize_url) == defaults.authorize_url
            && token_url.as_deref().unwrap_or(defaults.token_url) == defaults.token_url
        {
            if let (Ok(id), Ok(secret)) = (
                std::env::var("ANTIGRAVITY_CLIENT_ID"),
                std::env::var("ANTIGRAVITY_CLIENT_SECRET"),
            ) && !id.trim().is_empty()
                && !secret.trim().is_empty()
                && client_id
                    .as_deref()
                    .is_none_or(|explicit| explicit == id.trim())
            {
                return (Some(id.trim().to_owned()), Some(secret.trim().to_owned()));
            }
        }
        (
            client_id
                .clone()
                .or_else(|| defaults.and_then(|d| d.client_id).map(str::to_owned)),
            client_secret.clone(),
        )
    }

    pub fn oauth_client_secret(
        preset: Option<OAuthPreset>,
        secret: Option<&str>,
    ) -> Result<Option<&str>, GatewayError> {
        let secret = secret.map(str::trim).filter(|value| !value.is_empty());
        if preset == Some(OAuthPreset::Antigravity) && secret.is_none() {
            return Err(GatewayError::Config(
                "请为 Antigravity 配置配套的 Google OAuth Client ID 和 Client Secret，或设置服务端的 ANTIGRAVITY_CLIENT_ID 和 ANTIGRAVITY_CLIENT_SECRET".into(),
            ));
        }
        Ok(secret)
    }

    pub fn effective_token_format(
        preset: Option<OAuthPreset>,
        explicit: Option<TokenRequestFormat>,
    ) -> TokenRequestFormat {
        if let Some(fmt) = explicit {
            return fmt;
        }
        match preset {
            Some(OAuthPreset::ClaudeCode) => TokenRequestFormat::Json,
            Some(OAuthPreset::Codex)
            | Some(OAuthPreset::Antigravity)
            | Some(OAuthPreset::Custom)
            | None => TokenRequestFormat::Form,
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

fn default_prefix_max_bytes() -> usize {
    4096
}

fn default_prefix_min_bytes() -> usize {
    64
}

fn default_sticky_failover_ttl_secs() -> u64 {
    300
}

fn default_failure_cooldown_base_secs() -> u64 {
    3
}
