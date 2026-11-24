use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use ttt_auth::{
    build_authorize_url, generate_state, parse_authorization_input, OAuthHttpClient, PkceChallenge,
    TokenStore,
};
use ttt_core::{
    ClientKeyConfig, GatewayError, OAuthPreset, PromptCacheMode, ProtocolFamily, ProxyConfig,
    QuotaMonitorConfig, QuotaSnapshot, UpstreamAuthConfig, UpstreamConfig,
};
use ttt_proxy::{AccessPolicy, ProxyBody, ProxyEngine};

use crate::db::{GatewayDb, UserRecord};
use crate::metrics::MetricsStore;
use crate::proxy_subscription::fetch_subscription;
use crate::quota::{QuotaMonitor, fetch_antigravity_models, resolve_probe_kind};

struct PendingPkceSession {
    upstream: Option<String>,
    verifier: String,
    redirect_uri: String,
    client_id: String,
    created_at_secs: u64,
}

/// Sanitized upstream view returned to the management UI (never leaks secrets).
#[derive(Debug, Serialize)]
pub struct UpstreamView {
    pub name: String,
    pub base_url: String,
    pub protocol: ProtocolFamily,
    pub protocol_endpoints: HashMap<ProtocolFamily, String>,
    pub auth_mode: &'static str,
    pub models: Vec<String>,
    pub model_mapping: HashMap<String, String>,
    pub extra_headers: HashMap<String, String>,
    pub protocol_headers: HashMap<ProtocolFamily, HashMap<String, String>>,
    pub weight: u32,
    pub default_cooldown_secs: u64,
    pub max_retries: usize,
    pub cooling_down: bool,
    pub api_key_count: Option<usize>,
    pub auth_header_name: Option<String>,
    pub auth_header_prefix: Option<String>,
    pub oauth: Option<OAuthStatusView>,
    pub owner_user_id: Option<i64>,
    pub owner_username: Option<String>,
    pub scope: &'static str,
    pub can_manage: bool,
    pub proxy: Option<String>,
    pub quota_config: Option<QuotaMonitorConfig>,
    pub can_probe_quota: bool,
    pub quota: Option<QuotaSnapshot>,
    pub session_header_out: Option<String>,
    pub strip_other_session_headers: bool,
    pub prompt_cache_mode: PromptCacheMode,
}

#[derive(Debug, Deserialize)]
struct TestProxyPayload {
    #[serde(default)]
    target_url: Option<String>,
}

#[derive(Deserialize)]
struct ImportProxyPayload {
    url: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthStatusView {
    pub preset: Option<OAuthPreset>,
    pub account_id: String,
    pub token_present: bool,
    pub refresh_token_present: bool,
    pub expires_at: Option<u64>,
    pub expires_in_secs: Option<i64>,
    pub can_login_pkce: bool,
    pub can_refresh: bool,
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub has_client_secret: bool,
    pub project_id_pending: bool,
}

#[derive(Debug, Deserialize)]
struct OAuthCallbackPayload {
    input: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct DeleteKeyPayload {
    key: String,
}

#[derive(Debug, Deserialize)]
struct UpsertKeyPayload {
    key: String,
    #[serde(default)]
    name: String,
    #[serde(default = "default_true_flag")]
    enabled: bool,
}

fn default_true_flag() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct SettingsPayload {
    #[serde(default)]
    admin_api_key: Option<String>,
    #[serde(default)]
    allow_registration: Option<bool>,
    #[serde(default)]
    default_user_restrict_upstreams: Option<bool>,
    #[serde(default)]
    default_user_allowed_upstreams: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AdminSetupPayload {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AdminLoginPayload {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserPayload {
    username: String,
    password: String,
    #[serde(default = "default_user_role")]
    role: String,
    #[serde(default = "default_true_flag")]
    enabled: bool,
    #[serde(default = "default_true_flag")]
    allow_private_upstreams: bool,
    #[serde(default)]
    restrict_upstreams: bool,
    #[serde(default)]
    allowed_upstreams: Vec<String>,
    #[serde(default)]
    restrict_models: bool,
    #[serde(default)]
    allowed_models: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserPayload {
    #[serde(default = "default_user_role")]
    role: String,
    #[serde(default = "default_true_flag")]
    enabled: bool,
    #[serde(default = "default_true_flag")]
    allow_private_upstreams: bool,
    #[serde(default)]
    restrict_upstreams: bool,
    #[serde(default)]
    allowed_upstreams: Vec<String>,
    #[serde(default)]
    restrict_models: bool,
    #[serde(default)]
    allowed_models: Vec<String>,
    #[serde(default)]
    password: Option<String>,
}

fn default_user_role() -> String {
    "user".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminSession {
    token: String,
    #[serde(default)]
    user_id: i64,
    username: String,
    #[serde(default = "default_admin_role")]
    role: String,
    expires_at_secs: u64,
}

fn default_admin_role() -> String {
    "admin".to_string()
}

#[derive(Debug, Clone)]
struct CallerIdentity {
    user_id: Option<i64>,
    username: String,
    role: String,
    allow_private_upstreams: bool,
    restrict_upstreams: bool,
    allowed_upstreams: Vec<String>,
    restrict_models: bool,
    allowed_models: Vec<String>,
}

impl CallerIdentity {
    fn from_user(user: UserRecord) -> Self {
        Self {
            user_id: Some(user.id),
            username: user.username,
            role: user.role,
            allow_private_upstreams: user.allow_private_upstreams,
            restrict_upstreams: user.restrict_upstreams,
            allowed_upstreams: user.allowed_upstreams,
            restrict_models: user.restrict_models,
            allowed_models: user.allowed_models,
        }
    }

    fn into_access_policy(self) -> AccessPolicy {
        let unrestricted = self.is_admin();
        AccessPolicy::new(
            self.user_id,
            (!unrestricted && self.restrict_upstreams).then_some(self.allowed_upstreams),
            (!unrestricted && self.restrict_models).then_some(self.allowed_models),
        )
    }

    fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    fn can_create_private_upstream(&self) -> bool {
        self.is_admin() || self.allow_private_upstreams
    }

    fn can_manage_upstream(&self, owner_user_id: Option<i64>) -> bool {
        self.is_admin() || (owner_user_id.is_some() && owner_user_id == self.user_id)
    }
}

#[derive(Debug, Deserialize)]
struct FetchModelsPayload {
    base_url: String,
    #[serde(default = "default_models_path")]
    models_path: String,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default = "default_fetch_auth_header")]
    header_name: String,
    #[serde(default = "default_fetch_prefix")]
    prefix: Option<String>,
    #[serde(default)]
    extra_headers: HashMap<String, String>,
}

fn default_models_path() -> String {
    "/models".to_string()
}

fn default_fetch_auth_header() -> String {
    "authorization".to_string()
}

fn default_fetch_prefix() -> Option<String> {
    Some("Bearer ".to_string())
}

/// Control-plane management API handler mounted at `/api/v1/*`.
/// All dynamic provider, OAuth token, client-key, settings, and log state is stored in SQLite (`GatewayDb`).
pub struct ControlPlane {
    admin_api_key: Mutex<Option<String>>,
    sessions: Mutex<HashMap<String, AdminSession>>,
    db: Arc<GatewayDb>,
    engine: Arc<ProxyEngine>,
    metrics: Arc<MetricsStore>,
    quota_monitor: Arc<QuotaMonitor>,
    pkce_sessions: Mutex<HashMap<String, PendingPkceSession>>,
    proxy_updates: Mutex<()>,
    oauth_http: OAuthHttpClient,
}

impl ControlPlane {
    pub fn new(
        admin_api_key: Option<String>,
        db: Arc<GatewayDb>,
        engine: Arc<ProxyEngine>,
        metrics: Arc<MetricsStore>,
    ) -> Self {
        let effective_admin = db
            .get_setting("admin_api_key")
            .ok()
            .flatten()
            .or(admin_api_key);

        // Seamless migration: if users table is empty but legacy single-admin password exists,
        // promote it into the first admin account in `users`.
        if db.count_users().unwrap_or(0) == 0
            && let Ok(Some(legacy_hash)) = db.get_setting("admin_password_hash")
            && !legacy_hash.is_empty()
        {
            let legacy_user = db
                .get_setting("admin_username")
                .ok()
                .flatten()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "admin".to_string());
            let _ = db.create_user(&legacy_user, &legacy_hash, "admin", true, true, false, &[], false, &[]);
        }

        let restored_sessions = load_sessions_from_db(&db);
        if let Ok(saved_proxies) = db.list_proxies()
            && !saved_proxies.is_empty()
            && let Err(err) = engine.reload_proxies(&saved_proxies)
        {
            tracing::warn!(error = %err, "failed to restore Clash proxies");
        }
        let quota_monitor = Arc::new(QuotaMonitor::new(Arc::clone(&db), Arc::clone(&engine)));
        Arc::clone(&quota_monitor).spawn_background_loop();
        Self {
            admin_api_key: Mutex::new(effective_admin),
            sessions: Mutex::new(restored_sessions),
            db,
            engine,
            metrics,
            quota_monitor,
            pkce_sessions: Mutex::new(HashMap::new()),
            proxy_updates: Mutex::new(()),
            oauth_http: OAuthHttpClient::new(),
        }
    }

    pub async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, std::convert::Infallible> {
        if req.method() == Method::OPTIONS {
            return Ok(cors_preflight());
        }

        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Public authentication endpoints (must be accessible before login)
        match (method.clone(), path.as_str()) {
            (Method::GET, "/api/v1/auth/status") => {
                return Ok(self.auth_status(req.headers()).await);
            }
            (Method::POST, "/api/v1/auth/setup") => {
                return Ok(self.auth_setup(req).await);
            }
            (Method::POST, "/api/v1/auth/register") => {
                return Ok(self.auth_register(req).await);
            }
            (Method::POST, "/api/v1/auth/login") => {
                return Ok(self.auth_login(req).await);
            }
            _ => {}
        }

        let auth_initialized = self.is_auth_initialized().await;
        let caller = if auth_initialized {
            match self.authenticate_request(req.headers()).await {
                Some(id) => id,
                None => {
                    return Ok(json_error(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized: please sign in",
                    ));
                }
            }
        } else {
            CallerIdentity {
                user_id: None,
                username: "admin".to_string(),
                role: "admin".to_string(),
                allow_private_upstreams: true,
                restrict_upstreams: false,
                allowed_upstreams: Vec::new(),
                restrict_models: false,
                allowed_models: Vec::new(),
            }
        };

        let resp = match (method, path.as_str()) {
            (Method::POST, "/api/v1/auth/logout") => self.auth_logout(req.headers()).await,
            (Method::PUT, "/api/v1/auth/password") => self.auth_change_password(&caller, req).await,
            (Method::GET, "/api/v1/playground/models")
            | (Method::POST, "/api/v1/playground/chat/completions") => {
                if !auth_initialized {
                    return Ok(json_error(StatusCode::UNAUTHORIZED, "请先登录控制台"));
                }
                self.engine.handle_playground(req, caller.into_access_policy()).await
            }
            (Method::GET, "/api/v1/stats") => {
                if caller.is_admin() {
                    let snap = self.metrics.snapshot();
                    json_ok(&snap)
                } else if let Some(uid) = caller.user_id {
                    match self.db.load_recent_logs_for_user(uid, 500) {
                        Ok(entries) => {
                            let snap = self.metrics.snapshot_from_entries(entries);
                            json_ok(&snap)
                        }
                        Err(err) => {
                            json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string())
                        }
                    }
                } else {
                    let snap = self.metrics.snapshot_from_entries(Vec::new());
                    json_ok(&snap)
                }
            }
            (Method::GET, "/api/v1/requests/active") => {
                let active = if caller.is_admin() {
                    self.metrics.active_requests(None)
                } else if let Some(uid) = caller.user_id {
                    self.metrics.active_requests(Some(uid))
                } else {
                    Default::default()
                };
                let mut response = json_ok(&active);
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                response
            }
            (Method::GET, "/api/v1/keys") => self.list_client_keys(&caller),
            (Method::POST, "/api/v1/keys") => self.upsert_client_key(&caller, req, true).await,
            (Method::PUT, "/api/v1/keys") => self.upsert_client_key(&caller, req, false).await,
            (Method::DELETE, "/api/v1/keys") => self.delete_client_key(&caller, req).await,
            // Outbound proxies
            (Method::GET, "/api/v1/proxies") => self.list_proxies(),
            (Method::POST, "/api/v1/proxies") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                self.create_proxy(req).await
            }
            (Method::POST, "/api/v1/proxies/import") => {
                if !auth_initialized || !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                self.import_proxies(req).await
            }
            (Method::POST, p) if p.starts_with("/api/v1/proxies/") && p.ends_with("/test") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                let name =
                    percent_decode(&p["/api/v1/proxies/".len()..p.len() - "/test".len()]);
                self.test_proxy(&name, req).await
            }
            (Method::PUT, p) if p.starts_with("/api/v1/proxies/") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                let name = percent_decode(&p["/api/v1/proxies/".len()..]);
                self.update_proxy(&name, req).await
            }
            (Method::DELETE, p) if p.starts_with("/api/v1/proxies/") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                let name = percent_decode(&p["/api/v1/proxies/".len()..]);
                self.delete_proxy(&name).await
            }
            // Admin-only routes below
            (Method::GET, "/api/v1/users") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                self.list_users()
            }
            (Method::POST, "/api/v1/users") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                self.create_user(req).await
            }
            (Method::PUT, p) if p.starts_with("/api/v1/users/") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                let id_str = &p["/api/v1/users/".len()..];
                self.update_user(&caller, id_str, req).await
            }
            (Method::DELETE, p) if p.starts_with("/api/v1/users/") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                let id_str = &p["/api/v1/users/".len()..];
                self.delete_user(&caller, id_str).await
            }
            (Method::GET, "/api/v1/settings") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                self.get_settings().await
            }
            (Method::PUT, "/api/v1/settings") => {
                if !caller.is_admin() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "需要管理员权限"));
                }
                self.update_settings(req).await
            }
            (Method::GET, "/api/v1/upstreams") => self.list_upstreams(&caller),
            (Method::POST, "/api/v1/upstreams") => self.create_upstream(&caller, req).await,
            (Method::POST, "/api/v1/upstreams/fetch-models") => {
                if !caller.can_create_private_upstream() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "当前账号未开启自建渠道权限"));
                }
                self.fetch_models_adhoc(req).await
            }
            (Method::GET, p)
                if p.starts_with("/api/v1/upstreams/") && p.ends_with("/models") =>
            {
                let name = percent_decode(&p["/api/v1/upstreams/".len()..p.len() - "/models".len()]);
                let models_path = extract_query_param(req.uri().query(), "models_path")
                    .unwrap_or_else(default_models_path);
                self.fetch_models_for_upstream(&caller, &name, &models_path).await
            }
            (Method::POST, p)
                if p.starts_with("/api/v1/upstreams/") && p.ends_with("/quota/refresh") =>
            {
                let name =
                    percent_decode(&p["/api/v1/upstreams/".len()..p.len() - "/quota/refresh".len()]);
                self.refresh_upstream_quota(&caller, &name).await
            }
            (Method::PUT, p) if p.starts_with("/api/v1/upstreams/") => {
                let name = percent_decode(&p["/api/v1/upstreams/".len()..]);
                self.update_upstream(&caller, &name, req).await
            }
            (Method::DELETE, p) if p.starts_with("/api/v1/upstreams/") => {
                let name = percent_decode(&p["/api/v1/upstreams/".len()..]);
                self.delete_upstream(&caller, &name)
            }
            (Method::POST, p)
                if p.starts_with("/api/v1/oauth/preset/") && p.ends_with("/authorize") =>
            {
                if !caller.can_create_private_upstream() {
                    return Ok(json_error(StatusCode::FORBIDDEN, "当前账号未开启自建渠道权限"));
                }
                let preset_str =
                    &p["/api/v1/oauth/preset/".len()..p.len() - "/authorize".len()];
                self.oauth_preset_authorize(preset_str).await
            }
            (Method::POST, p)
                if p.starts_with("/api/v1/oauth/") && p.ends_with("/authorize") =>
            {
                let name = percent_decode(&p["/api/v1/oauth/".len()..p.len() - "/authorize".len()]);
                if !self.caller_can_manage_upstream_name(&caller, &name) {
                    return Ok(json_error(StatusCode::FORBIDDEN, "无权操作该渠道"));
                }
                self.oauth_authorize(&name).await
            }
            (Method::POST, p)
                if p.starts_with("/api/v1/oauth/") && p.ends_with("/callback") =>
            {
                let name = percent_decode(&p["/api/v1/oauth/".len()..p.len() - "/callback".len()]);
                if !self.caller_can_manage_upstream_name(&caller, &name) {
                    return Ok(json_error(StatusCode::FORBIDDEN, "无权操作该渠道"));
                }
                self.oauth_callback(&name, req).await
            }
            (Method::POST, p)
                if p.starts_with("/api/v1/oauth/") && p.ends_with("/refresh") =>
            {
                let name = percent_decode(&p["/api/v1/oauth/".len()..p.len() - "/refresh".len()]);
                if !self.caller_can_manage_upstream_name(&caller, &name) {
                    return Ok(json_error(StatusCode::FORBIDDEN, "无权操作该渠道"));
                }
                self.oauth_refresh(&name).await
            }
            _ => json_error(StatusCode::NOT_FOUND, "management endpoint not found"),
        };

        Ok(resp)
    }

    fn caller_can_manage_upstream_name(&self, caller: &CallerIdentity, name: &str) -> bool {
        if caller.is_admin() {
            return true;
        }
        self.db
            .list_upstreams()
            .ok()
            .and_then(|list| list.into_iter().find(|u| u.name == name))
            .map(|u| caller.can_manage_upstream(u.owner_user_id))
            .unwrap_or(false)
    }

    fn list_upstreams(&self, caller: &CallerIdentity) -> Response<ProxyBody> {
        let upstreams = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };

        let user_map: HashMap<i64, String> = self
            .db
            .list_users()
            .unwrap_or_default()
            .into_iter()
            .map(|(u, _)| (u.id, u.username))
            .collect();

        let nodes = self.engine.router().all_nodes();
        let quota_map = self.quota_monitor.snapshot_map();
        let now_ms = now_epoch_ms();
        let now_s = now_ms / 1000;

        let mut views = Vec::with_capacity(upstreams.len());
        for up in &upstreams {
            // Regular users see allowed global upstreams (owner_user_id = None) + their own private upstreams.
            if !caller.is_admin() {
                if up.owner_user_id.is_some() {
                    if up.owner_user_id != caller.user_id {
                        continue;
                    }
                } else if caller.restrict_upstreams
                    && !caller.allowed_upstreams.iter().any(|n| n == &up.name)
                {
                    continue;
                }
            }
            let live_node = nodes.iter().find(|n| n.name == up.name);
            let cooling_down = live_node.map(|n| n.is_cooling_down(now_ms)).unwrap_or(false);
            let can_manage = caller.can_manage_upstream(up.owner_user_id);

            let (auth_mode, api_key_count, auth_header_name, auth_header_prefix, oauth_view) =
                match &up.auth {
                    UpstreamAuthConfig::ApiKey {
                        keys,
                        header_name,
                        prefix,
                    } => (
                        "api_key",
                        Some(keys.len()),
                        Some(header_name.clone()),
                        prefix.clone(),
                        None,
                    ),
                    UpstreamAuthConfig::OAuth {
                        preset,
                        authorize_url,
                        redirect_uri,
                        client_id,
                        client_secret,
                        account_id,
                        header_name,
                        prefix,
                        ..
                    } => {
                        let acct = account_id.clone().unwrap_or_else(|| up.name.clone());
                        let (token_present, refresh_present, expires_at, can_refresh, has_project) =
                            if let Some(mgr) = live_node.and_then(|n| n.auth.oauth_manager()) {
                                let st = mgr.current_state();
                                (
                                    !st.access_token.is_empty(),
                                    st.refresh_token.is_some(),
                                    st.expires_at,
                                    mgr.can_refresh(),
                                    st.antigravity_project_id.is_some(),
                                )
                            } else {
                                (false, false, None, false, false)
                            };
                        let expires_in_secs = expires_at.map(|e| (e as i64) - (now_s as i64));
                        let (effective_client_id, has_client_secret) =
                            if can_manage && *preset == Some(OAuthPreset::Antigravity) {
                                let (id, secret) = up.auth.oauth_credentials();
                                (id, secret.is_some())
                            } else {
                                (
                                    None,
                                    can_manage
                                        && client_secret
                                            .as_deref()
                                            .is_some_and(|secret| !secret.trim().is_empty()),
                                )
                            };
                        (
                            "oauth",
                            None,
                            Some(header_name.clone()),
                            prefix.clone(),
                            Some(OAuthStatusView {
                                preset: *preset,
                                account_id: acct,
                                token_present,
                                refresh_token_present: refresh_present,
                                expires_at,
                                expires_in_secs,
                                can_login_pkce: preset.and_then(OAuthPreset::defaults).is_some()
                                    || (authorize_url.is_some()
                                        && redirect_uri.is_some()
                                        && client_id.is_some()),
                                can_refresh,
                                project_id_pending: *preset == Some(OAuthPreset::Antigravity)
                                    && token_present
                                    && !has_project,
                                client_id: if can_manage { client_id.clone() } else { None },
                                effective_client_id,
                                redirect_uri: if can_manage { redirect_uri.clone() } else { None },
                                has_client_secret,
                            }),
                        )
                    }
                };

            let primary_proto = up.primary_protocol();
            let raw_endpoints = if up.protocol_endpoints.is_empty() {
                up.effective_endpoints()
            } else {
                up.protocol_endpoints.clone()
            };
            let display_base = if !up.base_url.trim().is_empty() {
                up.base_url.clone()
            } else {
                raw_endpoints
                    .get(&primary_proto)
                    .cloned()
                    .unwrap_or_default()
            };

            let owner_username = up
                .owner_user_id
                .and_then(|uid| user_map.get(&uid).cloned());
            let scope = if up.owner_user_id.is_some() {
                "private"
            } else {
                "global"
            };
            views.push(UpstreamView {
                name: up.name.clone(),
                base_url: display_base,
                protocol: primary_proto,
                protocol_endpoints: raw_endpoints,
                auth_mode,
                models: up.models.clone(),
                model_mapping: up.model_mapping.clone(),
                extra_headers: up.extra_headers.clone(),
                protocol_headers: up.protocol_headers.clone(),
                weight: up.weight,
                default_cooldown_secs: up.default_cooldown_secs,
                max_retries: up.max_retries,
                cooling_down,
                api_key_count,
                auth_header_name,
                auth_header_prefix,
                oauth: oauth_view,
                owner_user_id: up.owner_user_id,
                owner_username,
                scope,
                can_manage,
                proxy: up.proxy.clone(),
                quota_config: up.quota.clone(),
                can_probe_quota: resolve_probe_kind(up).is_some(),
                quota: quota_map.get(&up.name).cloned(),
                session_header_out: up.session_header_out.clone(),
                strip_other_session_headers: up.strip_other_session_headers,
                prompt_cache_mode: up.prompt_cache_mode,
            });
        }

        let antigravity_oauth_defaults = if caller.can_create_private_upstream() {
            let (client_id, client_secret) = OAuthPreset::antigravity_default_credentials();
            client_id.map(|id| json!({ "client_id": id, "has_client_secret": client_secret.is_some() }))
        } else {
            None
        };
        json_ok(&json!({
            "upstreams": views,
            "antigravity_oauth_defaults": antigravity_oauth_defaults,
        }))
    }

    async fn create_upstream(
        &self,
        caller: &CallerIdentity,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        if !caller.can_create_private_upstream() {
            return json_error(StatusCode::FORBIDDEN, "当前账号未开启自建渠道权限");
        }
        let mut new_up: UpstreamConfig = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        // Non-admin users always create private upstreams owned by themselves.
        if !caller.is_admin() {
            new_up.owner_user_id = caller.user_id;
        }
        if let Err(err) = new_up.validate() {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }

        let existing = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        if existing.iter().any(|u| u.name == new_up.name) {
            return json_error(
                StatusCode::CONFLICT,
                &format!("upstream '{}' already exists", new_up.name),
            );
        }

        let mut next = existing;
        next.push(new_up.clone());
        if let Err(err) = self.engine.router().reload(&next) {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }
        if let Err(err) = self.db.upsert_upstream(&new_up) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }

        json_status(
            StatusCode::CREATED,
            &json!({ "status": "created", "name": new_up.name }),
        )
    }

    async fn update_upstream(
        &self,
        caller: &CallerIdentity,
        name: &str,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let mut updated: UpstreamConfig = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        updated.name = name.to_string();

        let mut next = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(pos) = next.iter().position(|u| u.name == name) else {
            return json_error(StatusCode::NOT_FOUND, &format!("upstream '{name}' not found"));
        };
        if !caller.can_manage_upstream(next[pos].owner_user_id) {
            return json_error(StatusCode::FORBIDDEN, "无权编辑该渠道");
        }
        // Preserve ownership on update.
        if !caller.is_admin() || updated.owner_user_id.is_none() {
            updated.owner_user_id = next[pos].owner_user_id;
        }

        // Preserve existing secrets/OAuth fields when left empty during edit.
        match (&mut updated.auth, &next[pos].auth) {
            (
                UpstreamAuthConfig::ApiKey { keys, .. },
                UpstreamAuthConfig::ApiKey {
                    keys: existing_keys,
                    ..
                },
            ) => {
                if keys.is_empty() {
                    *keys = existing_keys.clone();
                }
            }
            (
                UpstreamAuthConfig::OAuth {
                    preset,
                    access_token,
                    refresh_token,
                    expires_at,
                    authorize_url,
                    device_code_url,
                    token_url,
                    client_id,
                    client_secret,
                    scopes,
                    redirect_uri,
                    token_request_format,
                    ..
                },
                UpstreamAuthConfig::OAuth {
                    access_token: old_at,
                    refresh_token: old_rt,
                    expires_at: old_exp,
                    authorize_url: old_auth_url,
                    device_code_url: old_dev_url,
                    token_url: old_tok_url,
                    client_id: old_cid,
                    client_secret: old_csec,
                    scopes: old_scopes,
                    redirect_uri: old_redir,
                    token_request_format: old_fmt,
                    ..
                },
            ) => {
                if *preset == Some(OAuthPreset::Antigravity)
                    && let Some(new_id) = client_id.as_deref()
                    && Some(new_id) != old_cid.as_deref()
                    && old_csec.as_deref().is_some_and(|secret| !secret.trim().is_empty())
                    && client_secret
                        .as_deref()
                        .is_none_or(|secret| secret.trim().is_empty())
                {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "更换 Google OAuth Client ID 时请同时填写配套的 Client Secret",
                    );
                }
                if access_token.is_none() {
                    *access_token = old_at.clone();
                }
                if refresh_token.is_none() {
                    *refresh_token = old_rt.clone();
                }
                if expires_at.is_none() {
                    *expires_at = *old_exp;
                }
                if authorize_url.is_none() {
                    *authorize_url = old_auth_url.clone();
                }
                if device_code_url.is_none() {
                    *device_code_url = old_dev_url.clone();
                }
                if token_url.is_none() {
                    *token_url = old_tok_url.clone();
                }
                if client_id.is_none() {
                    *client_id = old_cid.clone();
                }
                if client_secret.is_none() {
                    *client_secret = old_csec.clone();
                }
                if scopes.is_empty() {
                    *scopes = old_scopes.clone();
                }
                if redirect_uri.is_none() {
                    *redirect_uri = old_redir.clone();
                }
                if token_request_format.is_none() {
                    *token_request_format = *old_fmt;
                }
            }
            _ => {}
        }

        if let Err(err) = updated.validate() {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }

        next[pos] = updated.clone();
        if let Err(err) = self.engine.router().reload(&next) {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }
        if let Err(err) = self.db.upsert_upstream(&updated) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }

        json_ok(&json!({ "status": "updated", "name": name }))
    }

    fn delete_upstream(&self, caller: &CallerIdentity, name: &str) -> Response<ProxyBody> {
        let mut next = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(pos) = next.iter().position(|u| u.name == name) else {
            return json_error(StatusCode::NOT_FOUND, &format!("upstream '{name}' not found"));
        };
        if !caller.can_manage_upstream(next[pos].owner_user_id) {
            return json_error(StatusCode::FORBIDDEN, "无权删除该渠道");
        }

        next.remove(pos);
        if let Err(err) = self.engine.router().reload(&next) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
        if let Err(err) = self.db.delete_upstream(name) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
        self.quota_monitor.remove_upstream(name);

        json_ok(&json!({ "status": "deleted", "name": name }))
    }

    async fn refresh_upstream_quota(
        &self,
        caller: &CallerIdentity,
        name: &str,
    ) -> Response<ProxyBody> {
        let upstreams = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(up) = upstreams.into_iter().find(|u| u.name == name) else {
            return json_error(StatusCode::NOT_FOUND, &format!("upstream '{name}' not found"));
        };
        if !caller.is_admin() && up.owner_user_id != caller.user_id && up.owner_user_id.is_some() {
            return json_error(StatusCode::FORBIDDEN, "无权访问该渠道额度");
        }
        let snap = self.quota_monitor.refresh_upstream(&up).await;
        json_ok(&json!({ "quota": snap }))
    }

    async fn oauth_preset_authorize(&self, preset_str: &str) -> Response<ProxyBody> {
        let preset = match preset_str {
            "codex" => OAuthPreset::Codex,
            "claude_code" => OAuthPreset::ClaudeCode,
            "antigravity" => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "请先保存 Antigravity 渠道，再从渠道发起授权",
                );
            }
            _ => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported official OAuth preset (expected 'codex', 'claude_code', or 'antigravity')",
                );
            }
        };
        let Some(defaults) = preset.defaults() else {
            return json_error(StatusCode::BAD_REQUEST, "preset has no built-in OAuth defaults");
        };
        let Some(client_id) = defaults.client_id else {
            return json_error(StatusCode::BAD_REQUEST, "preset has no built-in OAuth client");
        };

        let scopes: Vec<String> = defaults.scopes.iter().map(|s| (*s).to_string()).collect();
        let pkce = PkceChallenge::generate();
        let state = generate_state();
        let url = match build_authorize_url(
            defaults.authorize_url,
            client_id,
            defaults.redirect_uri,
            &scopes,
            &state,
            &pkce,
            &[],
        ) {
            Ok(u) => u,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
        };

        let mut sessions = self.pkce_sessions.lock().await;
        let now = now_epoch_secs();
        sessions.retain(|_, s| now.saturating_sub(s.created_at_secs) < 600);
        sessions.insert(
            state.clone(),
            PendingPkceSession {
                upstream: None,
                verifier: pkce.verifier,
                redirect_uri: defaults.redirect_uri.to_string(),
                client_id: client_id.to_string(),
                created_at_secs: now,
            },
        );

        json_ok(&json!({
            "authorize_url": url,
            "state": state,
        }))
    }

    async fn oauth_authorize(&self, upstream_name: &str) -> Response<ProxyBody> {
        let upstreams = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(up) = upstreams.iter().find(|u| u.name == upstream_name) else {
            return json_error(
                StatusCode::NOT_FOUND,
                &format!("upstream '{upstream_name}' not found"),
            );
        };

        let UpstreamAuthConfig::OAuth {
            preset,
            authorize_url,
            redirect_uri,
            scopes,
            ..
        } = &up.auth
        else {
            return json_error(StatusCode::BAD_REQUEST, "upstream is not in OAuth mode");
        };
        let (client_id, client_secret) = up.auth.oauth_credentials();
        if let Err(err) = UpstreamAuthConfig::oauth_client_secret(*preset, client_secret.as_deref()) {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }

        let defaults = preset.and_then(OAuthPreset::defaults);
        let Some(auth_url) = authorize_url
            .as_deref()
            .or_else(|| defaults.map(|d| d.authorize_url))
        else {
            return json_error(StatusCode::BAD_REQUEST, "upstream missing authorize_url");
        };
        let Some(cid) = client_id.as_deref() else {
            return json_error(StatusCode::BAD_REQUEST, "upstream missing client_id");
        };
        let Some(redir) = redirect_uri
            .as_deref()
            .or_else(|| defaults.map(|d| d.redirect_uri))
        else {
            return json_error(StatusCode::BAD_REQUEST, "upstream missing redirect_uri");
        };
        let resolved_scopes: Vec<String> = if scopes.is_empty() {
            defaults
                .map(|d| d.scopes.iter().map(|s| (*s).to_string()).collect())
                .unwrap_or_default()
        } else {
            scopes.clone()
        };

        let pkce = PkceChallenge::generate();
        let state = generate_state();
        let url = match build_authorize_url(
            auth_url,
            cid,
            redir,
            &resolved_scopes,
            &state,
            &pkce,
            preset.map_or(&[][..], OAuthPreset::authorization_params),
        ) {
            Ok(u) => u,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
        };

        let mut sessions = self.pkce_sessions.lock().await;
        let now = now_epoch_secs();
        sessions.retain(|_, s| now.saturating_sub(s.created_at_secs) < 600);
        sessions.insert(
            state.clone(),
            PendingPkceSession {
                upstream: Some(upstream_name.to_string()),
                verifier: pkce.verifier,
                redirect_uri: redir.to_string(),
                client_id: cid.to_string(),
                created_at_secs: now,
            },
        );

        json_ok(&json!({
            "authorize_url": url,
            "state": state,
        }))
    }

    async fn oauth_callback(
        &self,
        upstream_name: &str,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let payload: OAuthCallbackPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

        let session = {
            let mut sessions = self.pkce_sessions.lock().await;
            sessions.remove(&payload.state)
        };
        let Some(session) = session else {
            return json_error(
                StatusCode::BAD_REQUEST,
                "unknown or expired OAuth state session",
            );
        };
        if let Some(bound_upstream) = &session.upstream
            && bound_upstream != upstream_name
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "OAuth state belongs to another upstream",
            );
        }

        let code = match parse_authorization_input(&payload.input, &payload.state) {
            Ok(c) => c,
            Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
        };

        let upstreams = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(up) = upstreams.iter().find(|u| u.name == upstream_name) else {
            return json_error(StatusCode::NOT_FOUND, "upstream not found");
        };
        let UpstreamAuthConfig::OAuth {
            preset,
            token_url,
            token_request_format,
            account_id,
            ..
        } = &up.auth
        else {
            return json_error(StatusCode::BAD_REQUEST, "upstream is not in OAuth mode");
        };

        let defaults = preset.and_then(OAuthPreset::defaults);
        let Some(t_url) = token_url
            .clone()
            .or_else(|| defaults.map(|d| d.token_url.to_string()))
        else {
            return json_error(StatusCode::BAD_REQUEST, "upstream missing OAuth token_url");
        };
        let (client_id, client_secret) = up.auth.oauth_credentials();
        let Some(cid) = client_id else {
            return json_error(StatusCode::BAD_REQUEST, "upstream missing OAuth client_id");
        };
        if cid != session.client_id {
            return json_error(StatusCode::BAD_REQUEST, "OAuth Client ID 已更改，请重新授权");
        }
        let client_secret =
            match UpstreamAuthConfig::oauth_client_secret(*preset, client_secret.as_deref()) {
                Ok(secret) => secret,
                Err(err) => return json_error(StatusCode::BAD_REQUEST, &err.to_string()),
            };
        let format = UpstreamAuthConfig::effective_token_format(*preset, *token_request_format);
        let acct_id = account_id
            .clone()
            .unwrap_or_else(|| upstream_name.to_string());

        let state_param = match preset {
            Some(OAuthPreset::ClaudeCode) => Some(payload.state.as_str()),
            _ => None,
        };

        let token = match self
            .oauth_http
            .exchange_code(
                &t_url,
                format,
                &code,
                &session.verifier,
                &session.redirect_uri,
                &cid,
                client_secret,
                state_param,
            )
            .await
        {
            Ok(t) => t,
            Err(err) => return json_error(StatusCode::BAD_GATEWAY, &err.to_string()),
        };

        let stored = match self.oauth_http.complete_login(up, token).await {
            Ok(stored) => stored,
            Err(err) => return json_error(StatusCode::BAD_GATEWAY, &err.to_string()),
        };
        let expires_at = stored.expires_at;

        let node = self
            .engine
            .router()
            .all_nodes()
            .into_iter()
            .find(|n| n.name == upstream_name);
        let result = if let Some(mgr) = node.as_ref().and_then(|n| n.auth.oauth_manager())
            && mgr.client_meta().account_id == acct_id
        {
            mgr.install_login(stored).await
        } else {
            TokenStore::put(self.db.as_ref(), &acct_id, stored)
        };
        if let Err(err) = result {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }

        json_ok(&json!({
            "status": "authenticated",
            "upstream": upstream_name,
            "account_id": acct_id,
            "expires_at": expires_at,
        }))
    }

    async fn oauth_refresh(&self, upstream_name: &str) -> Response<ProxyBody> {
        let Some(node) = self
            .engine
            .router()
            .all_nodes()
            .into_iter()
            .find(|n| n.name == upstream_name)
        else {
            return json_error(
                StatusCode::NOT_FOUND,
                &format!("upstream '{upstream_name}' not found"),
            );
        };

        let Some(mgr) = node.auth.oauth_manager() else {
            return json_error(StatusCode::BAD_REQUEST, "upstream is not in OAuth mode");
        };

        let (gen_before, _) = mgr.acquire();
        match mgr.refresh_via_http(gen_before).await {
            Ok(_) => {
                let st = mgr.current_state();
                json_ok(&json!({
                    "status": "refreshed",
                    "upstream": upstream_name,
                    "expires_at": st.expires_at,
                }))
            }
            Err(err) => json_error(StatusCode::BAD_GATEWAY, &err.to_string()),
        }
    }

    async fn fetch_models_adhoc(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let payload: FetchModelsPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if payload.base_url.trim().is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "base_url cannot be empty");
        }

        let mut headers = Vec::new();
        if let Some(key) = payload.api_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
            let formatted = match payload.prefix.as_deref() {
                Some(p) => format!("{p}{key}"),
                None => key.to_string(),
            };
            headers.push((payload.header_name.clone(), formatted));
        }
        for (k, v) in payload.extra_headers {
            headers.push((k, v));
        }

        match fetch_upstream_models_http(&payload.base_url, &payload.models_path, &headers).await {
            Ok((url, models)) => json_ok(&json!({ "url": url, "models": models })),
            Err(err) => json_error(StatusCode::BAD_GATEWAY, &err.to_string()),
        }
    }

    async fn fetch_models_for_upstream(
        &self,
        caller: &CallerIdentity,
        upstream_name: &str,
        models_path: &str,
    ) -> Response<ProxyBody> {
        let upstreams = match self.db.list_upstreams() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(up) = upstreams.iter().find(|u| u.name == upstream_name) else {
            return json_error(
                StatusCode::NOT_FOUND,
                &format!("upstream '{upstream_name}' not found"),
            );
        };
        if !caller.can_manage_upstream(up.owner_user_id) {
            return json_error(StatusCode::FORBIDDEN, "无权操作该渠道");
        }

        if matches!(
            up.auth,
            UpstreamAuthConfig::OAuth {
                preset: Some(OAuthPreset::Antigravity),
                ..
            }
        ) && matches!(
            models_path,
            "/models" | "/v1/models" | "/v1internal:fetchAvailableModels"
        ) {
            return match fetch_antigravity_models(&self.engine, up).await {
                Ok((url, models)) => json_ok(&json!({ "url": url, "models": models })),
                Err(err) => json_error(StatusCode::BAD_GATEWAY, &err),
            };
        }

        let base_url = if !up.base_url.trim().is_empty() {
            up.base_url.clone()
        } else {
            let endpoints = up.effective_endpoints();
            endpoints
                .get(&ProtocolFamily::OpenAi)
                .or_else(|| endpoints.get(&up.primary_protocol()))
                .or_else(|| endpoints.values().next())
                .cloned()
                .unwrap_or_default()
        };

        let mut headers = Vec::new();
        if let Some(node) = self
            .engine
            .router()
            .all_nodes()
            .into_iter()
            .find(|n| n.name == upstream_name)
        {
            let (_, cred) = node.auth.acquire();
            if let Ok(val) = cred.header_value.to_str()
                && !val.is_empty()
            {
                headers.push((cred.header_name.as_str().to_string(), val.to_string()));
            }
        }
        for (k, v) in &up.extra_headers {
            headers.push((k.clone(), v.clone()));
        }
        let fetch_proto = if up.protocol_endpoints.contains_key(&ProtocolFamily::OpenAi) {
            ProtocolFamily::OpenAi
        } else {
            up.primary_protocol()
        };
        if let Some(proto_hdrs) = up.protocol_headers.get(&fetch_proto) {
            for (k, v) in proto_hdrs {
                headers.push((k.clone(), v.clone()));
            }
        }

        match fetch_upstream_models_http(&base_url, models_path, &headers).await {
            Ok((url, models)) => json_ok(&json!({ "url": url, "models": models })),
            Err(err) => json_error(StatusCode::BAD_GATEWAY, &err.to_string()),
        }
    }

    async fn is_auth_initialized(&self) -> bool {
        if self.db.count_users().unwrap_or(0) > 0 {
            return true;
        }
        let admin_guard = self.admin_api_key.lock().await;
        admin_guard.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
    }

    async fn authenticate_request(&self, headers: &http::HeaderMap) -> Option<CallerIdentity> {
        // 1. Session token in X-Admin-Token or Authorization: Bearer
        if let Some(tok) = extract_admin_token(headers) {
            let now = now_epoch_secs();
            let mut guard = self.sessions.lock().await;
            if let Some(sess) = guard.get(&tok).cloned() {
                if sess.expires_at_secs > now {
                    // Verify user still exists & is enabled (if backed by `users` table)
                    if sess.user_id > 0 {
                        match self.db.get_user_by_id(sess.user_id).ok().flatten() {
                            Some(u) if u.enabled => {
                                return Some(CallerIdentity::from_user(u));
                            }
                            _ => {
                                guard.remove(&tok);
                                save_sessions_to_db(&self.db, &guard);
                                return None;
                            }
                        }
                    }
                    // Legacy session before user_id was added: resolve by username
                    if let Ok(Some(u)) = self.db.get_user_by_username(&sess.username)
                        && u.enabled
                    {
                        return Some(CallerIdentity::from_user(u));
                    }
                } else {
                    guard.remove(&tok);
                    save_sessions_to_db(&self.db, &guard);
                }
            }
        }

        // 2. Fallback: static admin_api_key (if configured)
        let admin_guard = self.admin_api_key.lock().await;
        if let Some(admin_key) = admin_guard.as_deref()
            && !admin_key.is_empty()
            && verify_admin_auth(admin_key, headers)
        {
            return Some(CallerIdentity {
                user_id: None,
                username: "admin".to_string(),
                role: "admin".to_string(),
                allow_private_upstreams: true,
                restrict_upstreams: false,
                allowed_upstreams: Vec::new(),
                restrict_models: false,
                allowed_models: Vec::new(),
            });
        }

        None
    }

    fn is_registration_allowed(&self) -> bool {
        self.db
            .get_setting("allow_registration")
            .ok()
            .flatten()
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true)
    }

    fn default_user_upstream_policy(&self) -> (bool, Vec<String>) {
        let restrict = self
            .db
            .get_setting("default_user_restrict_upstreams")
            .ok()
            .flatten()
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let allowed: Vec<String> = self
            .db
            .get_setting("default_user_allowed_upstreams")
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        (restrict, allowed)
    }

    async fn auth_status(&self, headers: &http::HeaderMap) -> Response<ProxyBody> {
        let initialized = self.is_auth_initialized().await;
        let caller = if initialized {
            self.authenticate_request(headers).await
        } else {
            None
        };
        let user_json = caller.as_ref().map(|c| {
            json!({
                "id": c.user_id.unwrap_or(0),
                "username": c.username,
                "role": c.role,
                "allow_private_upstreams": c.can_create_private_upstream(),
            })
        });
        json_ok(&json!({
            "initialized": initialized,
            "authenticated": caller.is_some(),
            "allow_registration": self.is_registration_allowed(),
            "user": user_json,
        }))
    }

    async fn auth_register(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        if !self.is_registration_allowed() {
            return json_error(StatusCode::FORBIDDEN, "当前未开放注册");
        }
        let payload: AdminSetupPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let username = payload.username.trim();
        let password = payload.password.trim();
        if username.len() < 2 || username.len() > 32 {
            return json_error(StatusCode::BAD_REQUEST, "用户名长度需为 2-32 个字符");
        }
        if password.len() < 6 {
            return json_error(StatusCode::BAD_REQUEST, "密码长度至少 6 位");
        }
        if self.db.get_user_by_username(username).ok().flatten().is_some() {
            return json_error(StatusCode::CONFLICT, "用户名已被占用");
        }

        let role = if self.db.count_users().unwrap_or(0) == 0 {
            "admin"
        } else {
            "user"
        };
        let (default_restrict, default_allowed) = if role == "admin" {
            (false, Vec::new())
        } else {
            self.default_user_upstream_policy()
        };
        let pw_hash = hash_password(password);
        let user = match self.db.create_user(
            username,
            &pw_hash,
            role,
            true,
            true,
            default_restrict,
            &default_allowed,
            false,
            &[],
        ) {
            Ok(u) => u,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };

        let token = self.issue_session(user.id, &user.username, &user.role).await;
        json_status(
            StatusCode::CREATED,
            &json!({
                "token": token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "role": user.role,
                    "allow_private_upstreams": user.allow_private_upstreams,
                },
            }),
        )
    }

    async fn auth_setup(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        if self.is_auth_initialized().await {
            return json_error(StatusCode::FORBIDDEN, "系统已初始化，请直接登录");
        }
        let payload: AdminSetupPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let username = payload.username.trim();
        let password = payload.password.trim();
        if username.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "用户名不能为空");
        }
        if password.len() < 6 {
            return json_error(StatusCode::BAD_REQUEST, "密码长度至少 6 位");
        }

        let pw_hash = hash_password(password);
        let user = match self.db.create_user(username, &pw_hash, "admin", true, true, false, &[], false, &[]) {
            Ok(u) => u,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };

        let token = self.issue_session(user.id, &user.username, &user.role).await;
        json_status(
            StatusCode::CREATED,
            &json!({
                "token": token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "role": user.role,
                    "allow_private_upstreams": user.allow_private_upstreams,
                },
            }),
        )
    }

    async fn auth_login(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        if !self.is_auth_initialized().await {
            return json_error(StatusCode::BAD_REQUEST, "尚未初始化管理员账号");
        }
        let payload: AdminLoginPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let username = payload.username.trim();
        let password = payload.password.trim();

        if let Ok(Some(user)) = self.db.get_user_by_username(username) {
            if !user.enabled {
                return json_error(StatusCode::FORBIDDEN, "该账号已被禁用");
            }
            if verify_password(password, &user.password_hash) {
                let token = self.issue_session(user.id, &user.username, &user.role).await;
                return json_ok(&json!({
                    "token": token,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "role": user.role,
                        "allow_private_upstreams": user.role == "admin" || user.allow_private_upstreams,
                    },
                }));
            }
            return json_error(StatusCode::UNAUTHORIZED, "用户名或密码错误");
        }

        // Fallback when only admin_api_key was configured via config.toml
        let admin_guard = self.admin_api_key.lock().await;
        if let Some(key) = admin_guard.as_deref()
            && !key.is_empty()
            && password == key
        {
            let token = self.issue_session(0, "admin", "admin").await;
            return json_ok(&json!({
                "token": token,
                "user": {
                    "id": 0,
                    "username": "admin",
                    "role": "admin",
                },
            }));
        }

        json_error(StatusCode::UNAUTHORIZED, "用户名或密码错误")
    }

    async fn auth_logout(&self, headers: &http::HeaderMap) -> Response<ProxyBody> {
        if let Some(tok) = extract_admin_token(headers) {
            let mut guard = self.sessions.lock().await;
            guard.remove(&tok);
            save_sessions_to_db(&self.db, &guard);
        }
        json_ok(&json!({ "status": "logged_out" }))
    }

    async fn auth_change_password(
        &self,
        caller: &CallerIdentity,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let payload: ChangePasswordPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let new_pw = payload.new_password.trim();
        if new_pw.len() < 6 {
            return json_error(StatusCode::BAD_REQUEST, "新密码长度至少 6 位");
        }

        let Some(uid) = caller.user_id else {
            return json_error(StatusCode::BAD_REQUEST, "当前会话不支持修改密码");
        };
        let Ok(Some(user)) = self.db.get_user_by_id(uid) else {
            return json_error(StatusCode::NOT_FOUND, "用户不存在");
        };
        if !verify_password(payload.current_password.trim(), &user.password_hash) {
            return json_error(StatusCode::UNAUTHORIZED, "当前密码不正确");
        }

        let new_hash = hash_password(new_pw);
        if let Err(err) = self.db.update_user_password(uid, &new_hash) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }

        // Revoke this user's old sessions and issue a fresh token.
        {
            let mut guard = self.sessions.lock().await;
            guard.retain(|_, s| s.user_id != uid);
            save_sessions_to_db(&self.db, &guard);
        }
        let token = self.issue_session(user.id, &user.username, &user.role).await;
        json_ok(&json!({
            "status": "updated",
            "token": token,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
            },
        }))
    }

    async fn issue_session(&self, user_id: i64, username: &str, role: &str) -> String {
        let token = generate_session_token();
        let expires_at_secs = now_epoch_secs().saturating_add(7 * 24 * 3600);
        let sess = AdminSession {
            token: token.clone(),
            user_id,
            username: username.to_string(),
            role: role.to_string(),
            expires_at_secs,
        };
        let mut guard = self.sessions.lock().await;
        let now = now_epoch_secs();
        guard.retain(|_, v| v.expires_at_secs > now);
        guard.insert(token.clone(), sess);
        save_sessions_to_db(&self.db, &guard);
        token
    }

    fn list_users(&self) -> Response<ProxyBody> {
        let users = match self.db.list_users() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let items: Vec<serde_json::Value> = users
            .into_iter()
            .map(|(u, key_count)| {
                json!({
                    "id": u.id,
                    "username": u.username,
                    "role": u.role,
                    "enabled": u.enabled,
                    "allow_private_upstreams": u.allow_private_upstreams,
                    "restrict_upstreams": u.restrict_upstreams,
                    "allowed_upstreams": u.allowed_upstreams,
                    "restrict_models": u.restrict_models,
                    "allowed_models": u.allowed_models,
                    "created_at": u.created_at,
                    "key_count": key_count,
                })
            })
            .collect();
        json_ok(&json!({ "users": items }))
    }

    async fn create_user(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let payload: CreateUserPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let username = payload.username.trim();
        let password = payload.password.trim();
        let role = if payload.role == "admin" { "admin" } else { "user" };

        if username.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "用户名不能为空");
        }
        if password.len() < 6 {
            return json_error(StatusCode::BAD_REQUEST, "密码长度至少 6 位");
        }
        if self.db.get_user_by_username(username).ok().flatten().is_some() {
            return json_error(StatusCode::CONFLICT, "用户名已存在");
        }

        let hash = hash_password(password);
        match self.db.create_user(
            username,
            &hash,
            role,
            payload.enabled,
            payload.allow_private_upstreams,
            payload.restrict_upstreams,
            &payload.allowed_upstreams,
            payload.restrict_models,
            &payload.allowed_models,
        ) {
            Ok(u) => json_status(
                StatusCode::CREATED,
                &json!({
                    "status": "created",
                    "user": {
                        "id": u.id,
                        "username": u.username,
                        "role": u.role,
                        "enabled": u.enabled,
                        "allow_private_upstreams": u.allow_private_upstreams,
                        "restrict_upstreams": u.restrict_upstreams,
                        "allowed_upstreams": u.allowed_upstreams,
                        "restrict_models": u.restrict_models,
                        "allowed_models": u.allowed_models,
                        "created_at": u.created_at,
                        "key_count": 0,
                    }
                }),
            ),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    }

    async fn update_user(
        &self,
        caller: &CallerIdentity,
        id_str: &str,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let Ok(id) = id_str.parse::<i64>() else {
            return json_error(StatusCode::BAD_REQUEST, "无效的用户 ID");
        };
        let payload: UpdateUserPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let Ok(Some(target)) = self.db.get_user_by_id(id) else {
            return json_error(StatusCode::NOT_FOUND, "用户不存在");
        };

        let next_role = if payload.role == "admin" { "admin" } else { "user" };
        let next_enabled = payload.enabled;

        // Prevent demoting or disabling the last enabled admin
        if target.role == "admin"
            && target.enabled
            && (next_role != "admin" || !next_enabled)
            && self.db.count_enabled_admins().unwrap_or(0) <= 1
        {
            return json_error(StatusCode::BAD_REQUEST, "系统至少需要保留一个启用的管理员");
        }

        // Prevent admin from disabling themselves
        if caller.user_id == Some(id) && !next_enabled {
            return json_error(StatusCode::BAD_REQUEST, "不能禁用当前登录账号");
        }

        let new_hash = match payload.password.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(pw) => {
                if pw.len() < 6 {
                    return json_error(StatusCode::BAD_REQUEST, "新密码长度至少 6 位");
                }
                Some(hash_password(pw))
            }
            None => None,
        };

        if let Err(err) = self.db.update_user(
            id,
            next_role,
            next_enabled,
            payload.allow_private_upstreams,
            payload.restrict_upstreams,
            &payload.allowed_upstreams,
            payload.restrict_models,
            &payload.allowed_models,
            new_hash.as_deref(),
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }

        // Immediately propagate updated user-level restrictions / enabled state to hot-path client keys.
        if let Ok(all) = self.db.list_client_keys() {
            self.engine.reload_client_keys(&all);
        }

        // Revoke sessions if user was disabled or password reset
        if !next_enabled || new_hash.is_some() {
            let mut guard = self.sessions.lock().await;
            guard.retain(|_, s| s.user_id != id);
            save_sessions_to_db(&self.db, &guard);
        }

        json_ok(&json!({ "status": "updated" }))
    }

    async fn delete_user(&self, caller: &CallerIdentity, id_str: &str) -> Response<ProxyBody> {
        let Ok(id) = id_str.parse::<i64>() else {
            return json_error(StatusCode::BAD_REQUEST, "无效的用户 ID");
        };
        if caller.user_id == Some(id) {
            return json_error(StatusCode::BAD_REQUEST, "不能删除当前登录账号");
        }
        let Ok(Some(target)) = self.db.get_user_by_id(id) else {
            return json_error(StatusCode::NOT_FOUND, "用户不存在");
        };
        if target.role == "admin"
            && target.enabled
            && self.db.count_enabled_admins().unwrap_or(0) <= 1
        {
            return json_error(StatusCode::BAD_REQUEST, "系统至少需要保留一个启用的管理员");
        }

        match self.db.delete_user(id) {
            Ok(true) => {
                {
                    let mut guard = self.sessions.lock().await;
                    guard.retain(|_, s| s.user_id != id);
                    save_sessions_to_db(&self.db, &guard);
                }
                if let Ok(all) = self.db.list_client_keys() {
                    self.engine.reload_client_keys(&all);
                }
                json_ok(&json!({ "status": "deleted" }))
            }
            Ok(false) => json_error(StatusCode::NOT_FOUND, "用户不存在"),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    }

    async fn get_settings(&self) -> Response<ProxyBody> {
        let admin = self.admin_api_key.lock().await;
        let (default_restrict, default_allowed) = self.default_user_upstream_policy();
        json_ok(&json!({
            "admin_auth_enabled": admin.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "allow_registration": self.is_registration_allowed(),
            "default_user_restrict_upstreams": default_restrict,
            "default_user_allowed_upstreams": default_allowed,
        }))
    }

    async fn update_settings(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let payload: SettingsPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Some(allow_reg) = payload.allow_registration {
            let val = if allow_reg { "true" } else { "false" };
            if let Err(err) = self.db.set_setting("allow_registration", Some(val)) {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
        }
        if let Some(restrict) = payload.default_user_restrict_upstreams {
            let val = if restrict { "true" } else { "false" };
            if let Err(err) = self
                .db
                .set_setting("default_user_restrict_upstreams", Some(val))
            {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
        }
        if let Some(allowed) = payload.default_user_allowed_upstreams {
            let raw = serde_json::to_string(&allowed).unwrap_or_else(|_| "[]".into());
            if let Err(err) = self
                .db
                .set_setting("default_user_allowed_upstreams", Some(&raw))
            {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
        }
        if payload.admin_api_key.is_some() {
            let next = payload
                .admin_api_key
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if let Err(err) = self.db.set_setting("admin_api_key", next.as_deref()) {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
            }
            *self.admin_api_key.lock().await = next;
        }
        let admin = self.admin_api_key.lock().await;
        let (default_restrict, default_allowed) = self.default_user_upstream_policy();
        json_ok(&json!({
            "status": "updated",
            "admin_auth_enabled": admin.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "allow_registration": self.is_registration_allowed(),
            "default_user_restrict_upstreams": default_restrict,
            "default_user_allowed_upstreams": default_allowed,
        }))
    }

    fn list_client_keys(&self, caller: &CallerIdentity) -> Response<ProxyBody> {
        let all_keys = match self.db.list_client_keys_with_owner() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let auth_enabled = !all_keys.is_empty();
        let items: Vec<serde_json::Value> = all_keys
            .into_iter()
            .filter(|(_, owner_id, _)| caller.is_admin() || *owner_id == caller.user_id)
            .map(|(k, _, owner_name)| {
                json!({
                    "key": k.key,
                    "masked": mask_secret(&k.key),
                    "name": k.name,
                    "enabled": k.enabled,
                    "restrict_upstreams": k.restrict_upstreams,
                    "allowed_upstreams": k.allowed_upstreams,
                    "restrict_models": k.restrict_models,
                    "allowed_models": k.allowed_models,
                    "owner_username": owner_name,
                })
            })
            .collect();
        json_ok(&json!({
            "auth_enabled": auth_enabled,
            "keys": items,
        }))
    }

    async fn upsert_client_key(
        &self,
        caller: &CallerIdentity,
        req: Request<Incoming>,
        is_create: bool,
    ) -> Response<ProxyBody> {
        let payload: UpsertKeyPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let key = payload.key.trim().to_string();
        if key.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "key cannot be empty");
        }

        let item = ClientKeyConfig {
            key: key.clone(),
            name: payload.name.trim().to_string(),
            enabled: payload.enabled,
            restrict_upstreams: false,
            allowed_upstreams: Vec::new(),
            restrict_models: false,
            allowed_models: Vec::new(),
            owner_user_id: caller.user_id,
        };

        let existing = match self.db.list_client_keys() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let exists = existing.iter().any(|k| k.key == key);
        if is_create && exists {
            return json_error(StatusCode::CONFLICT, "client API key already exists");
        }
        if !is_create && !exists {
            return json_error(StatusCode::NOT_FOUND, "client API key not found");
        }
        if !is_create && !caller.is_admin() {
            let owner = self.db.get_client_key_owner(&key).ok().flatten();
            if owner != caller.user_id {
                return json_error(StatusCode::FORBIDDEN, "无权修改他人令牌");
            }
        }

        let owner_for_insert = if is_create { caller.user_id } else { None };
        if let Err(err) = self.db.upsert_client_key_with_owner(&item, owner_for_insert) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string());
        }
        if let Ok(all) = self.db.list_client_keys() {
            self.engine.reload_client_keys(&all);
        }

        let status = if is_create {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        json_status(
            status,
            &json!({
                "status": if is_create { "created" } else { "updated" },
                "masked": mask_secret(&key),
            }),
        )
    }

    async fn delete_client_key(
        &self,
        caller: &CallerIdentity,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let payload: DeleteKeyPayload = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

        if !caller.is_admin() {
            let owner = self.db.get_client_key_owner(&payload.key).ok().flatten();
            if owner != caller.user_id {
                return json_error(StatusCode::FORBIDDEN, "无权删除他人令牌");
            }
        }

        match self.db.delete_client_key(&payload.key) {
            Ok(true) => {
                if let Ok(all) = self.db.list_client_keys() {
                    self.engine.reload_client_keys(&all);
                }
                json_ok(&json!({ "status": "deleted" }))
            }
            Ok(false) => json_error(StatusCode::NOT_FOUND, "client API key not found"),
            Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    }

    // =========================================================================
    // Outbound Proxies
    // =========================================================================

    fn list_proxies(&self) -> Response<ProxyBody> {
        let proxies = match self.db.list_proxies() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let mgr = self.engine.clash_manager();
        let items: Vec<serde_json::Value> = proxies
            .into_iter()
            .map(|p| {
                let active = mgr.is_active(&p.name);
                let has_password = p
                    .password
                    .as_deref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                json!({
                    "name": p.name,
                    "protocol": p.protocol,
                    "server": p.server,
                    "port": p.port,
                    "username": p.username,
                    "has_password": has_password,
                    "cipher": p.cipher,
                    "tls": p.tls,
                    "sni": p.sni,
                    "ws_path": p.ws_path,
                    "ws_host": p.ws_host,
                    "reality_public_key": p.reality_public_key,
                    "reality_short_id": p.reality_short_id,
                    "enabled": p.enabled,
                    "active": active,
                })
            })
            .collect();
        json_ok(&json!({ "proxies": items }))
    }

    async fn create_proxy(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let proxy: ProxyConfig = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Err(err) = proxy.validate() {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }
        let _guard = self.proxy_updates.lock().await;
        let list = match self.db.list_proxies() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        if list.iter().any(|p| p.name == proxy.name) {
            return json_error(
                StatusCode::CONFLICT,
                &format!("代理 '{}' 已存在", proxy.name),
            );
        }
        if let Err(err) = self
            .engine
            .clash_manager()
            .update(&proxy.name, Some(&proxy), || self.db.upsert_proxy(&proxy))
        {
            return proxy_update_error(err);
        }
        json_status(
            StatusCode::CREATED,
            &json!({ "status": "created", "name": proxy.name }),
        )
    }

    async fn import_proxies(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        let payload: ImportProxyPayload = match read_json_body(req).await {
            Ok(payload) => payload,
            Err(response) => return response,
        };
        let mut subscription = match fetch_subscription(&payload.url).await {
            Ok(subscription) => subscription,
            Err(err) => return json_error(err.status_code(), &err.to_string()),
        };

        let _guard = self.proxy_updates.lock().await;
        let mut names: HashSet<_> = match self.db.list_proxies() {
            Ok(proxies) => proxies.into_iter().map(|proxy| proxy.name).collect(),
            Err(err) => return proxy_update_error(err),
        };
        let found = subscription.nodes.len();
        subscription.nodes.retain(|proxy| names.insert(proxy.name.clone()));
        let duplicates = found - subscription.nodes.len();
        let imported = match self.engine.clash_manager().import(&subscription.nodes, |proxies| {
            self.db.insert_proxies(proxies)
        }) {
            Ok(imported) => imported,
            Err(err) => return proxy_update_error(err),
        };
        json_ok(&json!({
            "imported": imported,
            "duplicates": duplicates,
            "skipped": subscription.skipped + subscription.nodes.len() - imported,
        }))
    }

    async fn update_proxy(&self, name: &str, req: Request<Incoming>) -> Response<ProxyBody> {
        let mut updated: ProxyConfig = match read_json_body(req).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        updated.name = name.to_string();

        let _guard = self.proxy_updates.lock().await;
        let list = match self.db.list_proxies() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        let Some(previous) = list.iter().find(|p| p.name == name) else {
            return json_error(StatusCode::NOT_FOUND, &format!("代理 '{name}' 不存在"));
        };

        // Preserve existing password/UUID when left empty during edit.
        if updated
            .password
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            updated.password = previous.password.clone();
        }
        if updated.protocol == previous.protocol && updated.clash_options.is_none() {
            updated.clash_options = previous.clash_options.clone();
        }
        if let Err(err) = updated.validate() {
            return json_error(StatusCode::BAD_REQUEST, &err.to_string());
        }

        if let Err(err) = self
            .engine
            .clash_manager()
            .update(name, Some(&updated), || self.db.upsert_proxy(&updated))
        {
            return proxy_update_error(err);
        }
        json_ok(&json!({ "status": "updated", "name": name }))
    }

    async fn delete_proxy(&self, name: &str) -> Response<ProxyBody> {
        let _guard = self.proxy_updates.lock().await;
        let list = match self.db.list_proxies() {
            Ok(v) => v,
            Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        if !list.iter().any(|p| p.name == name) {
            return json_error(StatusCode::NOT_FOUND, &format!("代理 '{name}' 不存在"));
        }
        if let Err(err) = self.engine.clash_manager().update(name, None, || {
            self.db.delete_proxy(name).map(|_| ())
        }) {
            return proxy_update_error(err);
        }
        json_ok(&json!({ "status": "deleted", "name": name }))
    }

    async fn test_proxy(&self, name: &str, req: Request<Incoming>) -> Response<ProxyBody> {
        let payload: TestProxyPayload = read_json_body(req).await.unwrap_or(TestProxyPayload {
            target_url: None,
        });
        let target = payload
            .target_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("https://www.gstatic.com/generate_204");

        match self.engine.clash_manager().test_proxy(name, target).await {
            Ok((status, latency_ms)) => json_ok(&json!({
                "ok": (200..400).contains(&status),
                "status": status,
                "latency_ms": latency_ms,
            })),
            Err(err) => json_ok(&json!({
                "ok": false,
                "latency_ms": 0,
                "error": err.to_string(),
            })),
        }
    }
}

fn proxy_update_error(err: GatewayError) -> Response<ProxyBody> {
    let status = match err {
        GatewayError::Config(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, &err.to_string())
}

async fn fetch_upstream_models_http(
    base_url: &str,
    models_path: &str,
    headers: &[(String, String)],
) -> Result<(String, Vec<String>), GatewayError> {
    let target_str = UpstreamConfig::join_base_and_endpoint(
        base_url,
        if models_path.trim().is_empty() {
            "/v1/models"
        } else {
            models_path
        },
    );
    let target_uri: http::Uri = target_str
        .parse()
        .map_err(|e| GatewayError::InvalidRequest(format!("invalid fetch-models URL '{target_str}': {e}")))?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(Duration::from_secs(8)));

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http);

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(target_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "codex_cli_rs/0.1.0");
    for (k, v) in headers {
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            builder = builder.header(hn, hv);
        }
    }

    let req = builder
        .body(Empty::new())
        .map_err(|e| GatewayError::InvalidRequest(format!("failed to build fetch-models req: {e}")))?;

    let resp = tokio::time::timeout(Duration::from_secs(12), client.request(req))
        .await
        .map_err(|_| GatewayError::UpstreamTimeout)?
        .map_err(|e| GatewayError::UpstreamConnect(format!("failed to reach {target_str}: {e}")))?;

    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| GatewayError::UpstreamConnect(format!("failed to read response: {e}")))?
        .to_bytes();

    if !status.is_success() {
        let preview = String::from_utf8_lossy(&body);
        let short: String = preview.chars().take(240).collect();
        return Err(GatewayError::UpstreamConnect(format!(
            "{target_str} returned HTTP {status}: {short}"
        )));
    }

    let models = parse_models_response(&body)?;
    Ok((target_str, models))
}

/// Extract model IDs from OpenAI/Anthropic (`data[].id`), Gemini (`models[].name`),
/// or Ollama (`models[].name`) JSON responses.
fn parse_models_response(raw: &[u8]) -> Result<Vec<String>, GatewayError> {
    let val: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::InvalidRequest(format!("upstream returned invalid JSON: {e}")))?;

    let mut set = BTreeSet::new();

    if let Some(arr) = val.get("data").and_then(Value::as_array) {
        for item in arr {
            if let Some(id) = item
                .get("id")
                .or_else(|| item.get("slug"))
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
            {
                set.insert(id.strip_prefix("models/").unwrap_or(id).to_string());
            }
        }
    }

    if let Some(arr) = val.get("models").and_then(Value::as_array) {
        for item in arr {
            if let Some(id) = item
                .get("id")
                .or_else(|| item.get("slug"))
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
            {
                set.insert(id.strip_prefix("models/").unwrap_or(id).to_string());
            }
        }
    }

    if let Some(arr) = val.as_array() {
        for item in arr {
            if let Some(s) = item.as_str() {
                set.insert(s.to_string());
            } else if let Some(id) = item
                .get("id")
                .or_else(|| item.get("slug"))
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
            {
                set.insert(id.to_string());
            }
        }
    }

    Ok(set.into_iter().collect())
}

fn extract_query_param(query: Option<&str>, key: &str) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
            && !v.is_empty()
        {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = (bytes[i + 1] as char).to_digit(16);
            let h2 = (bytes[i + 2] as char).to_digit(16);
            if let (Some(a), Some(b)) = (h1, h2) {
                out.push(((a << 4) | b) as u8);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_json_body<T: for<'de> Deserialize<'de>>(
    req: Request<Incoming>,
) -> Result<T, Response<ProxyBody>> {
    let bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, &format!("failed to read body: {e}")))?
        .to_bytes();
    serde_json::from_slice(&bytes)
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON payload: {e}")))
}

fn extract_admin_token(headers: &http::HeaderMap) -> Option<String> {
    if let Some(val) = headers.get("x-admin-token").and_then(|v| v.to_str().ok()) {
        let t = val.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let t = val.strip_prefix("Bearer ").unwrap_or(val).trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

fn hash_password(password: &str) -> String {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let salt_hex = hex_encode(&salt);
    let digest = sha256_salted(&salt_hex, password);
    format!("{salt_hex}:{digest}")
}

fn verify_password(password: &str, stored: &str) -> bool {
    let Some((salt_hex, expected)) = stored.split_once(':') else {
        return false;
    };
    let actual = sha256_salted(salt_hex, password);
    constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

fn sha256_salted(salt_hex: &str, password: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt_hex.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    hex_encode(&h.finalize())
}

fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("ttt_adm_{}", hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn load_sessions_from_db(db: &GatewayDb) -> HashMap<String, AdminSession> {
    let Ok(Some(raw)) = db.get_setting("admin_sessions") else {
        return HashMap::new();
    };
    let Ok(list) = serde_json::from_str::<Vec<AdminSession>>(&raw) else {
        return HashMap::new();
    };
    let now = now_epoch_secs();
    list.into_iter()
        .filter(|s| s.expires_at_secs > now)
        .map(|s| (s.token.clone(), s))
        .collect()
}

fn save_sessions_to_db(db: &GatewayDb, sessions: &HashMap<String, AdminSession>) {
    let list: Vec<&AdminSession> = sessions.values().collect();
    if let Ok(raw) = serde_json::to_string(&list) {
        let _ = db.set_setting("admin_sessions", Some(&raw));
    }
}

fn verify_admin_auth(expected: &str, headers: &http::HeaderMap) -> bool {
    if let Some(val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let token = val.strip_prefix("Bearer ").unwrap_or(val).trim();
        if token == expected {
            return true;
        }
    }
    if let Some(val) = headers.get("x-admin-key").and_then(|v| v.to_str().ok())
        && val.trim() == expected
    {
        return true;
    }
    false
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        return "****".to_string();
    }
    format!("{}...{}", &s[..4], &s[s.len() - 4..])
}

fn cors_preflight() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .header(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "Content-Type, Authorization, X-Admin-Key, X-Admin-Token",
        )
        .body(ProxyBody::empty())
        .unwrap()
}

fn json_ok<T: Serialize>(data: &T) -> Response<ProxyBody> {
    json_status(StatusCode::OK, data)
}

fn json_status<T: Serialize>(status: StatusCode, data: &T) -> Response<ProxyBody> {
    let body = serde_json::to_vec(data)
        .map(Bytes::from)
        .unwrap_or_else(|e| GatewayError::Internal(e.to_string()).to_json_bytes());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(ProxyBody::full(body))
        .unwrap()
}

fn json_error(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = json!({
        "error": {
            "message": message,
            "code": status.as_u16(),
        }
    })
    .to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(ProxyBody::full(Bytes::from(body)))
        .unwrap()
}

#[inline]
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[inline]
fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
