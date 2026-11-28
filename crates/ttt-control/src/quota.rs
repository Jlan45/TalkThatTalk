use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, warn};
use ttt_core::config::antigravity_daily_fallback;
use ttt_core::{
    ANTIGRAVITY_USER_AGENT, PoolConfig, ProtocolFamily, QuotaDimension, QuotaMonitorConfig,
    QuotaProbeKind, QuotaSnapshot, QuotaStatus, UpstreamAuthConfig, UpstreamConfig,
};
use ttt_proxy::client::{build_proxied_client, build_upstream_client};
use ttt_proxy::{ProxyBody, ProxyEngine};

use crate::db::GatewayDb;

const CLAUDE_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
const CODEX_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
const ANTIGRAVITY_MODELS_PATH: &str = "/v1internal:fetchAvailableModels";
const ANTIGRAVITY_QUOTA_PATH: &str = "/v1internal:retrieveUserQuotaSummary";
const OPENCODE_GO_USAGE_URL: &str = "https://opencode.ai/inference/go/v1/usage";
const MIN_POLL_INTERVAL_SECS: u64 = 60;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Resolve the effective probe kind for an upstream, or `None` if quota monitoring is disabled/unconfigured.
pub fn resolve_probe_kind(cfg: &UpstreamConfig) -> Option<QuotaProbeKind> {
    if let Some(q) = &cfg.quota {
        if !q.enabled {
            return None;
        }
        match q.probe {
            QuotaProbeKind::Auto => auto_detect_probe(cfg),
            other => Some(other),
        }
    } else {
        auto_detect_probe(cfg)
    }
}

fn auto_detect_probe(cfg: &UpstreamConfig) -> Option<QuotaProbeKind> {
    match &cfg.auth {
        UpstreamAuthConfig::OAuth {
            preset: Some(ttt_core::OAuthPreset::ClaudeCode),
            ..
        } => Some(QuotaProbeKind::ClaudeCode),
        UpstreamAuthConfig::OAuth {
            preset: Some(ttt_core::OAuthPreset::Codex),
            ..
        } => Some(QuotaProbeKind::Codex),
        UpstreamAuthConfig::OAuth {
            preset: Some(ttt_core::OAuthPreset::Antigravity),
            ..
        } => Some(QuotaProbeKind::Antigravity),
        UpstreamAuthConfig::ApiKey { .. } if is_opencode_go(cfg) => Some(QuotaProbeKind::OpenCodeGo),
        _ => None,
    }
}

fn is_opencode_go(cfg: &UpstreamConfig) -> bool {
    fn is_go_url(url: &str) -> bool {
        let Ok(uri) = url.trim().parse::<http::Uri>() else {
            return false;
        };
        uri.scheme_str() == Some("https")
            && uri.host().is_some_and(|host| host.eq_ignore_ascii_case("opencode.ai"))
            && uri.port().is_none_or(|port| port.as_u16() == 443)
            && ["/inference/go", "/zen/go"].into_iter().any(|prefix| {
                uri.path()
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            })
    }

    is_go_url(&cfg.base_url) || cfg.effective_endpoints().values().any(|url| is_go_url(url))
}

fn effective_poll_interval(cfg: &UpstreamConfig) -> u64 {
    cfg.quota
        .as_ref()
        .map(|q| q.poll_interval_secs.max(MIN_POLL_INTERVAL_SECS))
        .unwrap_or(300)
}

/// Manages cached quota snapshots, on-demand refresh, and periodic background polling.
pub struct QuotaMonitor {
    db: Arc<GatewayDb>,
    engine: Arc<ProxyEngine>,
    snapshots: RwLock<HashMap<String, QuotaSnapshot>>,
    refresh_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl QuotaMonitor {
    pub fn new(db: Arc<GatewayDb>, engine: Arc<ProxyEngine>) -> Self {
        let initial = db.list_quota_snapshots().unwrap_or_default();
        let mut initial_filtered = HashMap::with_capacity(initial.len());
        for (name, snap) in initial {
            if snap.probe != QuotaProbeKind::Antigravity
                || snap.status == QuotaStatus::Error
                || !snap.available_models.is_empty()
            {
                engine
                    .router()
                    .set_quota_exhausted(&name, snap.status == QuotaStatus::Exhausted);
                initial_filtered.insert(name, snap);
            }
        }
        Self {
            db,
            engine,
            snapshots: RwLock::new(initial_filtered),
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    pub fn snapshot_map(&self) -> HashMap<String, QuotaSnapshot> {
        self.snapshots
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn remove_upstream(&self, name: &str) {
        if let Ok(mut g) = self.snapshots.write() {
            g.remove(name);
        }
        self.engine.router().set_quota_exhausted(name, false);
        let _ = self.db.delete_quota_snapshot(name);
    }

    /// Trigger an immediate quota probe for a single upstream (coalesced per upstream).
    pub async fn refresh_upstream(&self, cfg: &UpstreamConfig) -> QuotaSnapshot {
        let lock = {
            let mut map = self.refresh_locks.lock().await;
            Arc::clone(
                map.entry(cfg.id.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = lock.lock().await;

        let snap = probe_upstream(&self.engine, cfg).await;
        self.engine
            .router()
            .set_quota_exhausted(&cfg.id, snap.status == QuotaStatus::Exhausted);
        if let Ok(mut g) = self.snapshots.write() {
            g.insert(cfg.id.clone(), snap.clone());
        }
        if let Err(err) = self.db.upsert_quota_snapshot(&cfg.id, &snap) {
            warn!(upstream = %cfg.name, error = %err, "failed to persist quota snapshot");
        }
        snap
    }

    /// Spawn a low-overhead background loop that polls due upstreams every 30 seconds.
    pub fn spawn_background_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            // Brief startup delay so OAuth tokens and proxy configuration are fully initialized.
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                self.poll_due_upstreams().await;
            }
        });
    }

    async fn poll_due_upstreams(self: &Arc<Self>) {
        let Ok(upstreams) = self.db.list_upstreams() else {
            return;
        };
        let now = now_secs();
        let existing = self.snapshot_map();

        for cfg in upstreams {
            if resolve_probe_kind(&cfg).is_none() {
                continue;
            }
            let interval = effective_poll_interval(&cfg) as i64;
            let last_fetched = existing.get(&cfg.id).map(|s| s.fetched_at).unwrap_or(0);
            if now - last_fetched < interval {
                continue;
            }
            let monitor = Arc::clone(self);
            tokio::spawn(async move {
                debug!(upstream = %cfg.name, "background quota poll");
                monitor.refresh_upstream(&cfg).await;
            });
        }
    }
}

async fn probe_upstream(engine: &ProxyEngine, cfg: &UpstreamConfig) -> QuotaSnapshot {
    let fetched_at = now_secs();
    let Some(kind) = resolve_probe_kind(cfg) else {
        return error_snapshot(
            &cfg.name,
            QuotaProbeKind::Auto,
            "quota monitoring is disabled or unsupported for this upstream".to_string(),
            fetched_at,
        );
    };

    match kind {
        QuotaProbeKind::ClaudeCode => probe_claude_code(engine, cfg, fetched_at).await,
        QuotaProbeKind::Codex => probe_codex(engine, cfg, fetched_at).await,
        QuotaProbeKind::Antigravity => probe_antigravity(engine, cfg, fetched_at).await,
        QuotaProbeKind::OpenCodeGo => probe_opencode_go(engine, cfg, fetched_at).await,
        QuotaProbeKind::CustomHttp => probe_custom_http(engine, cfg, fetched_at).await,
        QuotaProbeKind::Auto => error_snapshot(
            &cfg.name,
            QuotaProbeKind::Auto,
            "unable to auto-detect quota probe".to_string(),
            fetched_at,
        ),
    }
}

async fn probe_claude_code(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
    fetched_at: i64,
) -> QuotaSnapshot {
    let token = match get_oauth_access_token(engine, &cfg.id).await {
        Ok(t) => t,
        Err(e) => return error_snapshot(&cfg.name, QuotaProbeKind::ClaudeCode, e, fetched_at),
    };

    let req = match Request::builder()
        .method(Method::GET)
        .uri(CLAUDE_USAGE_URL)
        .header("authorization", format!("Bearer {token}"))
        .header("anthropic-beta", "oauth-2025-04-20")
        .header(
            "user-agent",
            concat!("talkthattalk/", env!("CARGO_PKG_VERSION")),
        )
        .header("content-type", "application/json")
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(e) => {
            return error_snapshot(
                &cfg.name,
                QuotaProbeKind::ClaudeCode,
                e.to_string(),
                fetched_at,
            )
        }
    };

    match send_http_json(engine, cfg, req).await {
        Ok((status, body)) if status.is_success() => {
            parse_claude_usage(&cfg.name, &body, fetched_at)
        }
        Ok((status, body)) => error_snapshot(
            &cfg.name,
            QuotaProbeKind::ClaudeCode,
            format!("HTTP {}: {}", status.as_u16(), truncate_str(&body, 200)),
            fetched_at,
        ),
        Err(e) => error_snapshot(&cfg.name, QuotaProbeKind::ClaudeCode, e, fetched_at),
    }
}

async fn probe_codex(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
    fetched_at: i64,
) -> QuotaSnapshot {
    let token = match get_oauth_access_token(engine, &cfg.id).await {
        Ok(t) => t,
        Err(e) => return error_snapshot(&cfg.name, QuotaProbeKind::Codex, e, fetched_at),
    };

    let account_id = cfg
        .quota
        .as_ref()
        .and_then(|q| q.chatgpt_account_id.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| extract_chatgpt_account_id_from_jwt(&token));

    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(CODEX_USAGE_URL)
        .header("authorization", format!("Bearer {token}"))
        .header("user-agent", "codex-cli/0.171.0")
        .header("accept", "application/json");
    if let Some(acct) = account_id {
        builder = builder.header("chatgpt-account-id", acct);
    }
    let req = match builder.body(Full::new(Bytes::new())) {
        Ok(r) => r,
        Err(e) => return error_snapshot(&cfg.name, QuotaProbeKind::Codex, e.to_string(), fetched_at),
    };

    match send_http_json(engine, cfg, req).await {
        Ok((status, body)) if status.is_success() => parse_codex_usage(&cfg.name, &body, fetched_at),
        Ok((status, body)) => error_snapshot(
            &cfg.name,
            QuotaProbeKind::Codex,
            format!("HTTP {}: {}", status.as_u16(), truncate_str(&body, 200)),
            fetched_at,
        ),
        Err(e) => error_snapshot(&cfg.name, QuotaProbeKind::Codex, e, fetched_at),
    }
}

struct AntigravityQuotaSession {
    origin: String,
    access_token: String,
    project_id: Option<String>,
}

impl AntigravityQuotaSession {
    async fn load(engine: &ProxyEngine, cfg: &UpstreamConfig) -> Result<Self, String> {
        let node = engine
            .router()
            .all_nodes()
            .into_iter()
            .find(|node| node.id == cfg.id)
            .ok_or_else(|| "upstream not active in router".to_string())?;
        let endpoint = node
            .endpoints
            .get(&ProtocolFamily::Antigravity)
            .ok_or_else(|| "Antigravity 渠道缺少协议端点".to_string())?;
        let origin = format!("{}://{}", endpoint.base_scheme, endpoint.base_authority);
        let mgr = node
            .auth
            .oauth_manager()
            .ok_or_else(|| "Antigravity 渠道未配置 OAuth".to_string())?;
        if mgr.needs_proactive_refresh() && mgr.can_refresh() {
            mgr.refresh_via_http(mgr.current_state().generation)
                .await
                .map_err(|err| err.to_string())?;
        }
        let state = mgr
            .antigravity_session(&origin)
            .await
            .unwrap_or_else(|_| mgr.current_state());
        if state.access_token.is_empty() {
            return Err("请先授权 Antigravity 渠道".into());
        }
        Ok(Self {
            origin,
            access_token: state.access_token.clone(),
            project_id: state.antigravity_project_id.clone(),
        })
    }

    async fn catalog(
        &self,
        engine: &ProxyEngine,
        cfg: &UpstreamConfig,
    ) -> Result<(String, Value), String> {
        let (url, data) = self.post(engine, cfg, ANTIGRAVITY_MODELS_PATH).await?;
        if data.get("models").and_then(Value::as_object).is_none() {
            return Err("Antigravity 未返回模型目录".into());
        }
        Ok((url, data))
    }

    async fn post(
        &self,
        engine: &ProxyEngine,
        cfg: &UpstreamConfig,
        path: &str,
    ) -> Result<(String, Value), String> {
        let mut auth = http::HeaderValue::from_str(&format!("Bearer {}", self.access_token))
            .map_err(|err| err.to_string())?;
        auth.set_sensitive(true);
        let body = match &self.project_id {
            Some(project) => serde_json::json!({ "project": project }),
            None => serde_json::json!({}),
        };
        let body = Bytes::from(body.to_string());
        let mut last_error = String::new();
        for origin in
            std::iter::once(self.origin.as_str()).chain(antigravity_daily_fallback(&self.origin))
        {
            let url = format!("{origin}{path}");
            let req = Request::post(&url)
                .header("authorization", auth.clone())
                .header("user-agent", ANTIGRAVITY_USER_AGENT)
                .header("content-type", "application/json")
                .body(Full::new(body.clone()))
                .map_err(|err| err.to_string())?;
            match tokio::time::timeout(Duration::from_secs(12), send_http_json(engine, cfg, req))
                .await
            {
                Ok(Ok((status, response))) if status.is_success() => {
                    return serde_json::from_str(&response)
                        .map(|data| (url, data))
                        .map_err(|err| format!("Antigravity {path} JSON 无效: {err}"));
                }
                Ok(Ok((status, _))) => {
                    last_error = format!("Antigravity {path} HTTP {status}");
                    if !status.is_server_error()
                        && !matches!(status, StatusCode::NOT_FOUND | StatusCode::REQUEST_TIMEOUT)
                    {
                        break;
                    }
                }
                Ok(Err(err)) => last_error = err,
                Err(_) => last_error = format!("Antigravity {path} 请求超时"),
            }
        }
        Err(last_error)
    }
}

pub async fn fetch_antigravity_models(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
) -> Result<(String, Vec<String>), String> {
    let session = AntigravityQuotaSession::load(engine, cfg).await?;
    let (url, catalog) = session.catalog(engine, cfg).await?;
    let models = antigravity_models(&catalog)
        .into_iter()
        .map(|(id, _)| id.to_string())
        .collect();
    Ok((url, models))
}

async fn probe_antigravity(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
    fetched_at: i64,
) -> QuotaSnapshot {
    let error = |err| error_snapshot(&cfg.name, QuotaProbeKind::Antigravity, err, fetched_at);
    let session = match AntigravityQuotaSession::load(engine, cfg).await {
        Ok(session) => session,
        Err(err) => return error(err),
    };
    let (summary, catalog) = tokio::join!(
        session.post(engine, cfg, ANTIGRAVITY_QUOTA_PATH),
        session.catalog(engine, cfg),
    );
    let mut snapshot = antigravity_usage(
        &cfg.name,
        summary.as_ref().ok().map(|(_, data)| data),
        catalog.as_ref().ok().map(|(_, data)| data),
        fetched_at,
    );
    if snapshot.dimensions.is_empty() {
        snapshot.status = QuotaStatus::Error;
        snapshot.error = Some(match (summary.err(), catalog.err()) {
            (Some(summary), Some(catalog)) => format!("{summary}; {catalog}"),
            (Some(err), None) | (None, Some(err)) => err,
            (None, None) => "Antigravity 未返回额度数据".into(),
        });
    }
    snapshot
}

async fn probe_opencode_go(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
    fetched_at: i64,
) -> QuotaSnapshot {
    let kind = QuotaProbeKind::OpenCodeGo;
    let error = |message| error_snapshot(&cfg.name, kind, message, fetched_at);
    if !is_opencode_go(cfg) {
        return error("此探测模式需要使用 opencode.ai 的 Go 渠道".into());
    }
    let UpstreamAuthConfig::ApiKey { keys, .. } = &cfg.auth else {
        return error("OpenCode Go 额度探测需要 API Key".into());
    };
    let Some(api_key) = keys.iter().map(|key| key.trim()).find(|key| !key.is_empty()) else {
        return error("请先配置 OpenCode Go API Key".into());
    };
    let Ok(mut authorization) = http::HeaderValue::from_str(&format!("Bearer {api_key}")) else {
        return error("OpenCode Go API Key 格式无效".into());
    };
    authorization.set_sensitive(true);
    let request = Request::get(OPENCODE_GO_USAGE_URL)
        .header("authorization", authorization)
        .header("accept", "application/json")
        .body(Full::new(Bytes::new()))
        .expect("the OpenCode Go usage URL and request headers are valid");
    let body = match send_http_json(engine, cfg, request).await {
        Ok((status, body)) if status.is_success() => body,
        Ok((StatusCode::UNAUTHORIZED, _)) => return error("OpenCode Go API Key 无效（HTTP 401）".into()),
        Ok((StatusCode::FORBIDDEN, _)) => {
            return error("此 API Key 无权读取 Go 额度，请检查订阅与用量读取权限（HTTP 403）".into());
        }
        Ok((status, _)) => return error(format!("OpenCode Go 额度接口返回 HTTP {status}")),
        Err(err) => return error(err),
    };

    let data: Value = match serde_json::from_str(&body) {
        Ok(data) => data,
        Err(err) => return error(format!("OpenCode Go 额度响应格式无效: {err}")),
    };
    let dimensions: Vec<_> = [("rolling", "5 小时"), ("weekly", "每周"), ("monthly", "每月")]
        .into_iter()
        .filter_map(|(key, label)| {
            let window = data.get("usage")?.get(key)?;
            let used_percent = window["percent"].as_f64().filter(|percent| (0.0..=100.0).contains(percent))?;
            let resets_at = window["resetsAt"].as_str().and_then(parse_rfc3339_secs);
            Some(QuotaDimension::WindowUtilization {
                window: label.into(),
                used_percent,
                resets_at,
            })
        })
        .collect();
    if dimensions.is_empty() {
        return error("OpenCode Go 未返回有效的额度窗口".into());
    }
    QuotaSnapshot {
        upstream: cfg.name.clone(),
        probe: kind,
        status: status_from_dimensions(&dimensions),
        dimensions,
        available_models: Vec::new(),
        plan_type: None,
        error: None,
        fetched_at,
    }
}

async fn probe_custom_http(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
    fetched_at: i64,
) -> QuotaSnapshot {
    let Some(q) = cfg.quota.as_ref() else {
        return error_snapshot(
            &cfg.name,
            QuotaProbeKind::CustomHttp,
            "missing quota config".to_string(),
            fetched_at,
        );
    };
    let Some(url) = q.custom_url.as_deref().filter(|u| !u.trim().is_empty()) else {
        return error_snapshot(
            &cfg.name,
            QuotaProbeKind::CustomHttp,
            "missing custom_url".to_string(),
            fetched_at,
        );
    };

    let api_key = match &cfg.auth {
        UpstreamAuthConfig::ApiKey { keys, .. } => keys.first().cloned().unwrap_or_default(),
        UpstreamAuthConfig::OAuth { .. } => get_oauth_access_token(engine, &cfg.id)
            .await
            .unwrap_or_default(),
    };

    let resolved_url = url.replace("{{api_key}}", &api_key);
    let mut builder = Request::builder().method(Method::GET).uri(&resolved_url);
    for (k, v) in &q.custom_headers {
        builder = builder.header(k.as_str(), v.replace("{{api_key}}", &api_key));
    }
    let req = match builder.body(Full::new(Bytes::new())) {
        Ok(r) => r,
        Err(e) => {
            return error_snapshot(
                &cfg.name,
                QuotaProbeKind::CustomHttp,
                e.to_string(),
                fetched_at,
            )
        }
    };

    match send_http_json(engine, cfg, req).await {
        Ok((status, body)) if status.is_success() => {
            parse_custom_http_usage(&cfg.name, q, &body, fetched_at)
        }
        Ok((status, body)) => error_snapshot(
            &cfg.name,
            QuotaProbeKind::CustomHttp,
            format!("HTTP {}: {}", status.as_u16(), truncate_str(&body, 200)),
            fetched_at,
        ),
        Err(e) => error_snapshot(&cfg.name, QuotaProbeKind::CustomHttp, e, fetched_at),
    }
}

async fn get_oauth_access_token(engine: &ProxyEngine, upstream_id: &str) -> Result<String, String> {
    let nodes = engine.router().all_nodes();
    let node = nodes
        .iter()
        .find(|u| u.id == upstream_id)
        .ok_or_else(|| "upstream not active in router".to_string())?;
    let mgr = node
        .auth
        .oauth_manager()
        .ok_or_else(|| "upstream is not configured with OAuth".to_string())?;
    let state = mgr.current_state();
    if state.reauthorization_required {
        return Err("OAuth 授权已失效，请重新授权".into());
    }
    if mgr.needs_proactive_refresh() && mgr.can_refresh() {
        mgr.refresh_via_http(state.generation)
            .await
            .map_err(|err| err.to_string())?;
    }
    let token = mgr.current_state().access_token.clone();
    if token.is_empty() {
        return Err("OAuth access token is empty (please authorize first)".to_string());
    }
    Ok(token)
}

async fn send_http_json(
    engine: &ProxyEngine,
    cfg: &UpstreamConfig,
    req: Request<Full<Bytes>>,
) -> Result<(StatusCode, String), String> {
    let proxy = cfg
        .proxy
        .as_deref()
        .map(|name| {
            engine
                .clash_manager()
                .get(name)
                .ok_or_else(|| format!("configured proxy '{name}' is not active or disabled"))
        })
        .transpose()?;
    let timeout = Duration::from_secs(12);

    let req = req.map(|b| match b.into_inner() {
        Some(bytes) if !bytes.is_empty() => ProxyBody::full(bytes),
        _ => ProxyBody::empty(),
    }.into());
    let pool = PoolConfig::default();

    let resp = if let Some(resolved) = proxy {
        let client = build_proxied_client(&pool, resolved)
            .map_err(|e| format!("failed to build proxied HTTP client: {e}"))?;
        tokio::time::timeout(timeout, client.request(req))
            .await
            .map_err(|_| "quota probe timed out via proxy".to_string())?
            .map_err(|e| format!("proxy request failed: {e}"))?
    } else {
        let client = build_upstream_client(&pool)
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
        tokio::time::timeout(timeout, client.request(req))
            .await
            .map_err(|_| "quota probe timed out".to_string())?
            .map_err(|e| format!("HTTP request failed: {e}"))?
    };

    let status = resp.status();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed reading response body: {e}"))?
        .to_bytes();
    let text = String::from_utf8_lossy(&body_bytes).into_owned();
    Ok((status, text))
}

fn error_snapshot(
    upstream: &str,
    probe: QuotaProbeKind,
    error: String,
    fetched_at: i64,
) -> QuotaSnapshot {
    QuotaSnapshot {
        upstream: upstream.to_string(),
        probe,
        status: QuotaStatus::Error,
        dimensions: Vec::new(),
        available_models: Vec::new(),
        plan_type: None,
        error: Some(error),
        fetched_at,
    }
}

fn status_from_dimensions(dims: &[QuotaDimension]) -> QuotaStatus {
    let mut max_pct: f64 = 0.0;
    let mut exhausted = false;
    for d in dims {
        match d {
            QuotaDimension::WindowUtilization { used_percent, .. } => {
                if *used_percent >= 100.0 {
                    exhausted = true;
                }
                if *used_percent > max_pct {
                    max_pct = *used_percent;
                }
            }
            QuotaDimension::Monetary {
                remaining, total, ..
            } => {
                if let Some(rem) = remaining {
                    if *rem <= 0.0 {
                        exhausted = true;
                    } else if let Some(tot) = total {
                        if *tot > 0.0 {
                            let pct = ((tot - rem) / tot) * 100.0;
                            if pct > max_pct {
                                max_pct = pct;
                            }
                        }
                    }
                }
            }
        }
    }
    if exhausted {
        QuotaStatus::Exhausted
    } else if max_pct >= 80.0 {
        QuotaStatus::Low
    } else {
        QuotaStatus::Healthy
    }
}

pub fn parse_claude_usage(upstream: &str, body: &str, fetched_at: i64) -> QuotaSnapshot {
    let val: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return error_snapshot(
                upstream,
                QuotaProbeKind::ClaudeCode,
                format!("invalid JSON: {e}"),
                fetched_at,
            )
        }
    };

    let mut dimensions = Vec::new();
    for (field, label) in [
        ("five_hour", "5h"),
        ("seven_day", "7d"),
        ("seven_day_sonnet", "7d_sonnet"),
        ("seven_day_opus", "7d_opus"),
    ] {
        if let Some(obj) = val.get(field).and_then(|v| v.as_object()) {
            if let Some(util) = obj.get("utilization").and_then(|v| v.as_f64()) {
                let resets_at = obj
                    .get("resets_at")
                    .and_then(|v| v.as_str())
                    .and_then(parse_rfc3339_secs);
                dimensions.push(QuotaDimension::WindowUtilization {
                    window: label.to_string(),
                    used_percent: util,
                    resets_at,
                });
            }
        }
    }

    if let Some(extra) = val.get("extra_usage").and_then(|v| v.as_object()) {
        if extra.get("is_enabled").and_then(|v| v.as_bool()) == Some(true) {
            let total = extra.get("monthly_limit").and_then(|v| v.as_f64());
            let used = extra.get("used_credits").and_then(|v| v.as_f64());
            let remaining = match (total, used) {
                (Some(t), Some(u)) => Some((t - u).max(0.0)),
                _ => None,
            };
            dimensions.push(QuotaDimension::Monetary {
                currency: "USD".to_string(),
                remaining,
                used,
                total,
            });
        }
    }

    let status = status_from_dimensions(&dimensions);
    QuotaSnapshot {
        upstream: upstream.to_string(),
        probe: QuotaProbeKind::ClaudeCode,
        status,
        dimensions,
        available_models: Vec::new(),
        plan_type: None,
        error: None,
        fetched_at,
    }
}

pub fn parse_codex_usage(upstream: &str, body: &str, fetched_at: i64) -> QuotaSnapshot {
    let val: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return error_snapshot(
                upstream,
                QuotaProbeKind::Codex,
                format!("invalid JSON: {e}"),
                fetched_at,
            )
        }
    };

    let plan_type = val
        .get("plan_type")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let mut dimensions = Vec::new();

    if let Some(rl) = val.get("rate_limit").and_then(|v| v.as_object()) {
        for key in ["primary_window", "secondary_window"] {
            if let Some(w) = rl.get(key).and_then(|v| v.as_object()) {
                if let Some(used_percent) = w.get("used_percent").and_then(|v| v.as_f64()) {
                    let window_secs = w
                        .get("limit_window_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let window = format_window_label(window_secs, key);
                    let resets_at = w
                        .get("reset_at")
                        .and_then(|v| v.as_i64())
                        .or_else(|| {
                            w.get("reset_after_seconds")
                                .and_then(|v| v.as_i64())
                                .map(|after| fetched_at + after)
                        });
                    dimensions.push(QuotaDimension::WindowUtilization {
                        window,
                        used_percent,
                        resets_at,
                    });
                }
            }
        }
    }

    if let Some(credits) = val.get("credits").and_then(|v| v.as_object()) {
        if credits.get("has_credits").and_then(|v| v.as_bool()) == Some(true) {
            let remaining = credits.get("balance").and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
            });
            if remaining.is_some() {
                dimensions.push(QuotaDimension::Monetary {
                    currency: "USD".to_string(),
                    remaining,
                    used: None,
                    total: None,
                });
            }
        }
    }

    let status = status_from_dimensions(&dimensions);
    QuotaSnapshot {
        upstream: upstream.to_string(),
        probe: QuotaProbeKind::Codex,
        status,
        dimensions,
        available_models: Vec::new(),
        plan_type,
        error: None,
        fetched_at,
    }
}

fn antigravity_models(catalog: &Value) -> Vec<(&str, &Value)> {
    let Some(models) = catalog.get("models").and_then(Value::as_object) else {
        return Vec::new();
    };
    let advertised: HashSet<_> = catalog["agentModelSorts"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|sort| sort["groups"].as_array().into_iter().flatten())
        .map(|group| &group["modelIds"])
        .chain(
            catalog["tieredModelIds"]
                .as_object()
                .into_iter()
                .flat_map(|tiers| tiers.values()),
        )
        .flat_map(|ids| ids.as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .map(|id| id.trim().to_ascii_lowercase())
        .filter(|id| !id.is_empty())
        .collect();
    let mut models: Vec<_> = models
        .iter()
        .filter(|(id, info)| {
            let id = id.to_ascii_lowercase();
            (advertised.is_empty() || advertised.contains(&id))
                && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                && !id.starts_with("model_")
                && !id.starts_with("chat_")
                && !id.starts_with("tab_")
                && !id.ends_with("-disabled")
                && !id.ends_with("_disabled")
                && !id.contains("image")
                && info.is_object()
                && info["disabled"].as_bool() != Some(true)
                && info["isInternal"].as_bool() != Some(true)
                && info["apiProvider"].as_str() != Some("API_PROVIDER_INTERNAL")
        })
        .map(|(id, info)| (id.as_str(), info))
        .collect();
    models.sort_unstable_by_key(|(id, _)| *id);
    models
}

fn antigravity_window(label: String, info: &Value) -> Option<QuotaDimension> {
    let resets_at = info
        .get("resetTime")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_secs);
    // Protobuf JSON can omit a zero balance while still returning its reset time.
    let fraction = match info.get("remainingFraction") {
        Some(value) => value.as_f64().filter(|f| (0.0..=1.0).contains(f))?,
        None if resets_at.is_some() => 0.0,
        None => return None,
    };
    Some(QuotaDimension::WindowUtilization {
        window: label,
        used_percent: (1.0 - fraction) * 100.0,
        resets_at,
    })
}

fn antigravity_quota_windows(summary: &Value) -> Vec<QuotaDimension> {
    let Some(groups) = summary["groups"].as_array() else {
        return Vec::new();
    };
    let mut windows = Vec::new();
    for group in groups {
        let Some(buckets) = group["buckets"].as_array() else {
            continue;
        };
        let name = group["displayName"].as_str().unwrap_or("Antigravity");
        let lowercase_name = name.to_ascii_lowercase();
        for bucket in buckets {
            if bucket["disabled"].as_bool() == Some(true) {
                continue;
            }
            let id = bucket["bucketId"].as_str().unwrap_or_default();
            let (family_order, family) = if lowercase_name.starts_with("gemini 4") {
                (2, name)
            } else if id.starts_with("gemini-argon-") || lowercase_name.contains("argon") {
                (2, "Gemini 4 Argon")
            } else if id.starts_with("gemini-") || lowercase_name.starts_with("gemini") {
                (0, "Gemini")
            } else if id.starts_with("3p-")
                || (lowercase_name.contains("claude") && lowercase_name.contains("gpt"))
            {
                (1, "Claude/GPT")
            } else {
                (3, name)
            };
            let (period_order, period) = match bucket["window"].as_str() {
                Some("weekly" | "week" | "7d") => (0, "每周"),
                Some("5h") => (1, "5h"),
                other => (
                    2,
                    other
                        .or_else(|| bucket["displayName"].as_str())
                        .unwrap_or(id),
                ),
            };
            if let Some(window) = antigravity_window(format!("{family} · {period}"), bucket) {
                windows.push(((family_order, period_order), window));
            }
        }
    }
    windows.sort_by_key(|(order, _)| *order);
    windows.into_iter().map(|(_, window)| window).collect()
}

fn antigravity_usage(
    upstream: &str,
    summary: Option<&Value>,
    catalog: Option<&Value>,
    fetched_at: i64,
) -> QuotaSnapshot {
    let models = catalog.map(antigravity_models).unwrap_or_default();
    let mut dimensions = summary.map(antigravity_quota_windows).unwrap_or_default();
    if dimensions.is_empty() {
        dimensions.extend(
            models
                .iter()
                .filter_map(|(id, info)| antigravity_window(id.to_string(), info.get("quotaInfo")?)),
        );
    }

    QuotaSnapshot {
        upstream: upstream.to_string(),
        probe: QuotaProbeKind::Antigravity,
        status: status_from_dimensions(&dimensions),
        dimensions,
        available_models: models.into_iter().map(|(id, _)| id.to_string()).collect(),
        plan_type: None,
        error: None,
        fetched_at,
    }
}

pub fn parse_custom_http_usage(
    upstream: &str,
    q: &QuotaMonitorConfig,
    body: &str,
    fetched_at: i64,
) -> QuotaSnapshot {
    let val: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return error_snapshot(
                upstream,
                QuotaProbeKind::CustomHttp,
                format!("invalid JSON: {e}"),
                fetched_at,
            )
        }
    };
    let scale = q.scale.unwrap_or(1.0);
    let remaining = q
        .remaining_path
        .as_deref()
        .and_then(|p| extract_dot_number(&val, p))
        .map(|n| n * scale);
    let used = q
        .used_path
        .as_deref()
        .and_then(|p| extract_dot_number(&val, p))
        .map(|n| n * scale);
    let total = q
        .total_path
        .as_deref()
        .and_then(|p| extract_dot_number(&val, p))
        .map(|n| n * scale);

    let currency = q
        .currency
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("USD")
        .to_string();

    let dimensions = vec![QuotaDimension::Monetary {
        currency,
        remaining,
        used,
        total,
    }];
    let status = status_from_dimensions(&dimensions);
    QuotaSnapshot {
        upstream: upstream.to_string(),
        probe: QuotaProbeKind::CustomHttp,
        status,
        dimensions,
        available_models: Vec::new(),
        plan_type: None,
        error: None,
        fetched_at,
    }
}

fn extract_dot_number(val: &Value, path: &str) -> Option<f64> {
    let mut cur = val;
    for part in path.split('.').map(str::trim).filter(|s| !s.is_empty()) {
        cur = cur.get(part)?;
    }
    cur.as_f64()
        .or_else(|| cur.as_i64().map(|i| i as f64))
        .or_else(|| cur.as_str().and_then(|s| s.parse::<f64>().ok()))
}

fn format_window_label(secs: u64, fallback: &str) -> String {
    if secs == 0 {
        return fallback.to_string();
    }
    if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

pub fn extract_chatgpt_account_id_from_jwt(jwt: &str) -> Option<String> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let val: Value = serde_json::from_slice(&decoded).ok()?;
    val.get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(ToString::to_string)
}

/// Minimal RFC 3339 UTC/offset timestamp parser returning Unix seconds.
pub fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;

    // Howard Hinnant's days_from_civil
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let base = days * 86400 + hour * 3600 + min * 60 + sec;

    let rest = &s[19..];
    let tz_start = rest.find(['Z', 'z', '+', '-'])?;
    let tz = &rest[tz_start..];
    if tz.starts_with('Z') || tz.starts_with('z') {
        return Some(base);
    }
    let sign = if tz.starts_with('-') { -1 } else { 1 };
    let tz_digits = &tz[1..];
    let (oh, om): (i64, i64) = if tz_digits.len() >= 5 && tz_digits.as_bytes()[2] == b':' {
        (
            tz_digits[0..2].parse().ok()?,
            tz_digits[3..5].parse().ok()?,
        )
    } else if tz_digits.len() >= 4 {
        (
            tz_digits[0..2].parse().ok()?,
            tz_digits[2..4].parse().ok()?,
        )
    } else {
        return None;
    };
    Some(base - sign * (oh * 3600 + om * 60))
}

fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_claude_usage_extracts_windows() {
        let json = r#"{
            "five_hour": {"utilization": 33.0, "resets_at": "2026-04-11T07:00:00.528743+00:00"},
            "seven_day": {"utilization": 13.0, "resets_at": "2026-04-17T00:59:59.951713+00:00"},
            "seven_day_sonnet": {"utilization": 1.0, "resets_at": "2026-04-16T03:00:00.951719+00:00"},
            "extra_usage": {"is_enabled": true, "monthly_limit": 50.0, "used_credits": 12.5}
        }"#;
        let snap = parse_claude_usage("claude-main", json, 1700000000);
        assert_eq!(snap.status, QuotaStatus::Healthy);
        assert_eq!(snap.dimensions.len(), 4);
        match &snap.dimensions[0] {
            QuotaDimension::WindowUtilization {
                window,
                used_percent,
                resets_at,
            } => {
                assert_eq!(window, "5h");
                assert!((*used_percent - 33.0).abs() < 1e-6);
                assert!(resets_at.is_some());
            }
            _ => panic!("expected window utilization"),
        }
    }

    #[test]
    fn parse_codex_usage_extracts_windows_and_plan() {
        let json = r#"{
            "plan_type": "pro",
            "rate_limit": {
                "primary_window": {
                    "used_percent": 85,
                    "limit_window_seconds": 18000,
                    "reset_after_seconds": 3600
                },
                "secondary_window": {
                    "used_percent": 20,
                    "limit_window_seconds": 604800,
                    "reset_at": 1795500000
                }
            },
            "credits": {"has_credits": true, "balance": "14.5"}
        }"#;
        let snap = parse_codex_usage("codex-main", json, 1795000000);
        assert_eq!(snap.status, QuotaStatus::Low);
        assert_eq!(snap.plan_type.as_deref(), Some("pro"));
        assert_eq!(snap.dimensions.len(), 3);
        match &snap.dimensions[0] {
            QuotaDimension::WindowUtilization {
                window,
                used_percent,
                resets_at,
            } => {
                assert_eq!(window, "5h");
                assert!((*used_percent - 85.0).abs() < 1e-6);
                assert_eq!(*resets_at, Some(1795003600));
            }
            _ => panic!("expected window utilization"),
        }
    }

    #[test]
    fn parse_rfc3339_epoch_and_offset() {
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_secs("2026-04-11T07:00:00.528743+08:00"),
            parse_rfc3339_secs("2026-04-10T23:00:00Z")
        );
    }

    #[test]
    fn antigravity_usage_combines_quota_buckets_and_selectable_models() {
        let catalog: Value = serde_json::from_str(r#"{
            "models": {
                "gemini-2.5-pro": {"quotaInfo": {"remainingFraction": 0.65, "resetTime": "2026-04-11T07:00:00Z"}},
                "claude-sonnet-4-5": {},
                "chat_internal": {"quotaInfo": {"remainingFraction": 0}},
                "gemini-image": {},
                "disabled-model": {"disabled": true}
            }
        }"#).unwrap();
        let summary = serde_json::json!({"groups": [
            {"displayName": "Gemini 4 Argon", "buckets": [
                {"bucketId": "gemini-argon-wtu-weekly", "window": "weekly", "remainingFraction": 1}
            ]},
            {"displayName": "Claude and GPT models", "buckets": [
                {"bucketId": "3p-weekly", "window": "weekly", "remainingFraction": 1},
                {"bucketId": "3p-5h", "window": "5h", "remainingFraction": 1}
            ]},
            {"displayName": "Gemini Models", "buckets": [
                {"bucketId": "gemini-5h", "window": "5h", "remainingFraction": 0.585415},
                {"bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": 0.73530394, "resetTime": "2026-04-11T09:00:00Z"}
            ]}
        ]});
        let snap = antigravity_usage("ag-main", Some(&summary), Some(&catalog), 1700000000);
        assert_eq!(snap.status, QuotaStatus::Healthy);
        assert_eq!(snap.dimensions.len(), 5);
        assert_eq!(
            snap.available_models,
            ["claude-sonnet-4-5", "gemini-2.5-pro"]
        );
        let display: Vec<_> = snap.dimensions.iter().map(|dimension| match dimension {
            QuotaDimension::WindowUtilization { window, used_percent, .. } => {
                (window.as_str(), used_percent.round() as i64)
            }
            _ => panic!("expected window utilization"),
        }).collect();
        assert_eq!(display, [
            ("Gemini · 每周", 26),
            ("Gemini · 5h", 41),
            ("Claude/GPT · 每周", 0),
            ("Claude/GPT · 5h", 0),
            ("Gemini 4 Argon · 每周", 0),
        ]);
        assert!(matches!(snap.dimensions[0], QuotaDimension::WindowUtilization {
            resets_at: Some(_), ..
        }));
        let fallback = antigravity_usage("ag-main", None, Some(&catalog), 1700000000);
        assert!(matches!(&fallback.dimensions[..], [
            QuotaDimension::WindowUtilization { window, used_percent, .. }
        ] if window == "gemini-2.5-pro" && (*used_percent - 35.0).abs() < 1e-6));
    }

    #[test]
    fn antigravity_catalog_uses_advertised_text_models_and_reports_exhausted_balances() {
        let catalog = serde_json::json!({
            "agentModelSorts": [{"groups": [{"modelIds": ["gemini-4-neon", "gemini-image"]}]}],
            "tieredModelIds": {"flash": ["gemini-tiered"]},
            "models": {
                "gemini-4-neon": {"quotaInfo": {"resetTime": "2026-11-23T08:00:00Z"}},
                "gemini-tiered": {},
                "gemini-disabled-in-catalog": {},
                "gemini-image": {},
            }
        });
        let snapshot = antigravity_usage("antigravity", None, Some(&catalog), 0);
        assert_eq!(
            snapshot.available_models,
            ["gemini-4-neon", "gemini-tiered"]
        );
        assert!(
            matches!(&snapshot.dimensions[..], [QuotaDimension::WindowUtilization {
            window, used_percent: 100.0, resets_at: Some(_),
        }] if window == "gemini-4-neon")
        );

        let summary = serde_json::json!({"groups": [{"displayName": "Gemini 4 Neon", "buckets": [
            {"bucketId": "gemini-neon-weekly", "window": "7d", "remainingFraction": 0.5},
        ]}]});
        assert!(
            matches!(&antigravity_quota_windows(&summary)[..], [QuotaDimension::WindowUtilization {
            window, used_percent: 50.0, ..
        }] if window == "Gemini 4 Neon · 每周")
        );
    }
}
