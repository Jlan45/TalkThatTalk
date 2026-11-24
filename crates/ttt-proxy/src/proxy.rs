use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use ttt_auth::{CredentialHandle, TokenStore};
use ttt_core::{
    ClientKeyConfig, GatewayConfig, GatewayError, PromptCacheMode, ProtocolFamily, ProxyConfig,
    RequestId, TapEvent,
};
use ttt_protocol::openai_antigravity::openai_to_antigravity_project_request;
use ttt_protocol::{
    NativeSse, create_sse_translator, detect_ingress_protocol, json_response_to_sse,
    needs_translation, translate_request_with_session, translate_response_json,
};

use crate::affinity::{AffinityContext, AffinityExtractor};
use crate::body::{ProxyBody, SegmentedBody, UploadTiming, UpstreamBody, upstream_ttft_ms};
use crate::clash_manager::ClashProxyManager;
use crate::client::{build_upstream_client, UpstreamHttpClient};
use crate::model_extract::{find_model_span, ModelSpan};
pub use crate::router::AccessPolicy;
use crate::router::{ParsedEndpoint, Router, UpstreamNode};

static HEADER_X_TTT_MODEL: HeaderName = HeaderName::from_static("x-ttt-model");
static HEADER_X_TTT_SESSION_ID: HeaderName = HeaderName::from_static("x-ttt-session-id");
static HEADER_X_TTT_REQUEST_ID: HeaderName = HeaderName::from_static("x-ttt-request-id");
static HEADER_X_TTT_UPSTREAM: HeaderName = HeaderName::from_static("x-ttt-upstream");
static HEADER_X_TTT_AFFINITY_SOURCE: HeaderName = HeaderName::from_static("x-ttt-affinity-source");
static HEADER_X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
static HEADER_X_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

#[derive(Debug, Clone)]
struct CompiledClientKey {
    enabled: bool,
    policy: AccessPolicy,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct PlaygroundChat {
    model: String,
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    stream: bool,
}

struct RequestTelemetry {
    req_id: RequestId,
    started_at: Instant,
    lifetime: Option<Arc<Instant>>,
}

/// High-performance zero-copy AI gateway data-plane engine.
pub struct ProxyEngine {
    client: UpstreamHttpClient,
    clash_manager: ClashProxyManager,
    router: Router,
    affinity_extractor: AffinityExtractor,
    client_keys: ArcSwap<HashMap<String, CompiledClientKey>>,
    max_inspect_body_bytes: usize,
    tap_tx: Option<mpsc::Sender<TapEvent>>,
}

impl ProxyEngine {
    pub fn new(
        cfg: &GatewayConfig,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
        token_store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        let client = build_upstream_client(&cfg.pool)?;
        let router = Router::with_config(&cfg.upstreams, token_store, cfg.routing.clone())?;
        let affinity_extractor = AffinityExtractor::from_config(&cfg.routing);
        let compiled = compile_client_keys(&cfg.server.effective_client_keys());

        Ok(Self {
            client,
            clash_manager: ClashProxyManager::new(cfg.pool.clone())?,
            router,
            affinity_extractor,
            client_keys: ArcSwap::from_pointee(compiled),
            max_inspect_body_bytes: cfg.server.max_inspect_body_bytes,
            tap_tx,
        })
    }

    pub fn clash_manager(&self) -> &ClashProxyManager {
        &self.clash_manager
    }

    /// Restore saved outbound proxies and their client pools.
    pub fn reload_proxies(&self, proxies: &[ProxyConfig]) -> Result<(), GatewayError> {
        self.clash_manager.reload(proxies)
    }

    /// Send an upstream HTTP request directly or via its assigned proxy.
    async fn send_upstream_request(
        &self,
        node: &UpstreamNode,
        req: Request<ProxyBody>,
    ) -> Result<(Response<Incoming>, Option<UploadTiming>), GatewayError> {
        let upload_timing = self.tap_tx.as_ref().map(|_| UploadTiming::default());
        let req = req.map(|body| UpstreamBody::new(body, upload_timing.clone()));
        let response = if let Some(ref proxy_name) = node.proxy {
            let client = self.clash_manager.get_client(proxy_name).ok_or_else(|| {
                GatewayError::UpstreamConnect(format!(
                    "{}: configured proxy '{}' is not active or disabled",
                    node.name, proxy_name
                ))
            })?;
            client
                .request(req)
                .await
                .map_err(|e| GatewayError::UpstreamConnect(format!("{} (via {}): {e}", node.name, proxy_name)))?
        } else {
            self.client
                .request(req)
                .await
                .map_err(|e| GatewayError::UpstreamConnect(format!("{}: {e}", node.name)))?
        };
        Ok((response, upload_timing))
    }

    /// Atomically replace the active client API key policies without interrupting hot-path traffic.
    pub fn reload_client_keys(&self, keys: &[ClientKeyConfig]) {
        self.client_keys.store(Arc::new(compile_client_keys(keys)));
    }

    /// Spawn a background task that proactively refreshes expiring OAuth tokens
    /// before they hit 401 on the hot path.
    pub fn spawn_proactive_oauth_refresher(
        self: &Arc<Self>,
        poll_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                for node in engine.router.all_nodes() {
                    if let Some(mgr) = node.auth.oauth_manager()
                        && mgr.needs_proactive_refresh()
                    {
                        let (gen_before, _) = mgr.acquire();
                        match mgr.refresh_via_http(gen_before).await {
                            Ok(_) => {
                                info!(
                                    upstream = %node.name,
                                    account_id = %mgr.client_meta().account_id,
                                    "proactively refreshed OAuth token"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    upstream = %node.name,
                                    account_id = %mgr.client_meta().account_id,
                                    error = %err,
                                    "proactive OAuth refresh failed"
                                );
                            }
                        }
                    }
                }
            }
        })
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Main HTTP entrypoint invoked per incoming request.
    pub async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, std::convert::Infallible> {
        let path = req.uri().path();
        if req.method() == Method::GET && (path == "/healthz" || path == "/readyz") {
            return Ok(health_response());
        }

        Ok(self.dispatch(req, None).await)
    }

    /// Called by the control plane after authenticating the console session.
    pub async fn handle_playground(
        &self,
        mut req: Request<Incoming>,
        policy: AccessPolicy,
    ) -> Response<ProxyBody> {
        let target = if req.method() == Method::GET {
            "/v1/models"
        } else {
            "/v1/chat/completions"
        };
        *req.uri_mut() = Uri::from_static(target);
        req.headers_mut().clear();
        req.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self.dispatch(req, Some(policy)).await
    }

    async fn dispatch(
        &self,
        req: Request<Incoming>,
        policy: Option<AccessPolicy>,
    ) -> Response<ProxyBody> {
        let req_id = RequestId::next();
        let started_at = Instant::now();

        match self.forward(req, req_id, started_at, policy).await {
            Ok(resp) => resp,
            Err(err) => error_response(&err, req_id),
        }
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        req_id: RequestId,
        started_at: Instant,
        session_policy: Option<AccessPolicy>,
    ) -> Result<Response<ProxyBody>, GatewayError> {
        let is_playground = session_policy.is_some();
        let active_policy = if is_playground {
            session_policy
        } else {
            let keys = self.client_keys.load();
            if keys.is_empty() {
                None
            } else {
                Some(resolve_client_policy(&keys, req.headers()).ok_or_else(|| {
                    GatewayError::Unauthorized("missing, invalid, or disabled gateway API key".into())
                })?)
            }
        };

        // OpenAI-compatible model discovery endpoint filtered by the active token policy.
        if req.method() == Method::GET && req.uri().path() == "/v1/models" {
            let models: Vec<String> = self
                .router
                .list_models()
                .into_iter()
                .filter(|m| {
                    if let Some(pol) = &active_policy {
                        pol.allows_model(Some(m))
                            && self.router.has_accessible_node(m, Some(pol))
                    } else {
                        self.router.has_accessible_node(m, None)
                    }
                })
                .collect();
            return Ok(models_list_response(&models));
        }

        let (parts, incoming_body) = req.into_parts();
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let header_model = parts
            .headers
            .get(&HEADER_X_TTT_MODEL)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        // 2. Decide between pure streaming zero-copy fast path vs lightweight JSON model scan.
        let policy_requires_model = active_policy.as_ref().is_some_and(|p| p.allowed_models.is_some());
        let can_pure_stream = !is_playground && !policy_requires_model
            && should_use_pure_stream(
                &parts.method,
                &parts.headers,
                self.router.needs_body_inspection(),
                self.max_inspect_body_bytes,
            );

        let ingress_proto = detect_ingress_protocol(parts.uri.path());
        let telemetry = RequestTelemetry {
            req_id,
            started_at,
            lifetime: self.tap_tx.as_ref().map(|_| Arc::new(started_at)),
        };

        if can_pure_stream {
            return self
                .forward_pure_stream(
                    parts.method,
                    &parts.headers,
                    path_and_query,
                    ingress_proto,
                    header_model.as_deref(),
                    active_policy.as_ref(),
                    incoming_body,
                    telemetry,
                )
                .await;
        }

        // 3. Lightweight inspect path: buffer bounded body once, scan `"model"` with SIMD memmem
        //    (no full JSON DOM deserialization), enable zero-copy slice rewrite + pre-first-byte retry.
        let limited = Limited::new(incoming_body, self.max_inspect_body_bytes);
        let raw_body = limited
            .collect()
            .await
            .map_err(|e| {
                GatewayError::InvalidRequest(format!("failed to read request body: {e}"))
            })?
            .to_bytes();
        let raw_body = if is_playground {
            let chat: PlaygroundChat = serde_json::from_slice(&raw_body)
                .map_err(|err| GatewayError::InvalidRequest(format!("invalid Playground request: {err}")))?;
            let encoded = serde_json::to_vec(&chat)
                .map_err(|err| GatewayError::Internal(format!("failed to encode Playground request: {err}")))?;
            Bytes::from(encoded)
        } else {
            raw_body
        };

        let model_span = find_model_span(&raw_body);
        let extracted_model = model_span
            .as_ref()
            .and_then(|s| s.as_str(&raw_body))
            .map(ToOwned::to_owned)
            .or(header_model);

        if let Some(pol) = &active_policy
            && !pol.allows_model(extracted_model.as_deref())
        {
            return Err(GatewayError::Forbidden(format!(
                "API key is not permitted to access model '{}'",
                extracted_model.as_deref().unwrap_or("<unspecified>")
            )));
        }

        self.forward_buffered_with_retry(
            parts.method,
            &parts.headers,
            path_and_query,
            ingress_proto,
            extracted_model.as_deref(),
            active_policy.as_ref(),
            raw_body,
            model_span,
            telemetry,
        )
        .await
    }

    /// Pure zero-copy streaming path: forwards `hyper::body::Incoming` directly to upstream
    /// without buffering or parsing the request payload.
    #[allow(clippy::too_many_arguments)]
    async fn forward_pure_stream(
        &self,
        method: Method,
        incoming_headers: &HeaderMap,
        path_and_query: &str,
        ingress_proto: Option<ProtocolFamily>,
        model: Option<&str>,
        policy: Option<&AccessPolicy>,
        body: Incoming,
        telemetry: RequestTelemetry,
    ) -> Result<Response<ProxyBody>, GatewayError> {
        let req_id = telemetry.req_id;
        let affinity = if self.router.needs_affinity_extraction(model, policy) {
            self.affinity_extractor.extract_headers_only(
                incoming_headers,
                policy.and_then(|p| p.owner_user_id),
                model,
            )
        } else {
            None
        };
        let affinity_hash = affinity.as_ref().map(|a| a.hash);
        let affinity_source = affinity.as_ref().map(|a| a.source.as_str());

        let plan = self
            .router
            .plan_route(model, ingress_proto, policy, affinity_hash);
        if plan.blocked_by_policy {
            return Err(GatewayError::Forbidden(format!(
                "API key is not permitted to access any upstream for model '{}'",
                model.unwrap_or("<default>")
            )));
        }
        let node = plan.candidates.first().ok_or_else(|| {
            GatewayError::NoRoute(model.unwrap_or("<default>").to_string())
        })?;

        self.emit_start(
            &telemetry,
            policy.and_then(|p| p.owner_user_id),
            &node.name,
            model,
            path_and_query,
        );
        let (target_proto, endpoint) = node.resolve_endpoint(ingress_proto);

        let (cred_handle, upstream_req) = self.build_upstream_request(
            node,
            target_proto,
            endpoint,
            method,
            incoming_headers,
            path_and_query,
            ProxyBody::incoming(body),
            None,
            affinity.as_ref(),
            req_id,
        )?;

        let (upstream_resp, upload_timing) = match self.send_upstream_request(node, upstream_req).await {
            Ok(result) => result,
            Err(err) => {
                node.record_transient_failure(self.router.routing_config().failure_cooldown_base_secs);
                return Err(err);
            }
        };

        let status = upstream_resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let cooldown = parse_retry_after(upstream_resp.headers())
                .unwrap_or(node.default_cooldown_secs);
            node.auth.on_rate_limited(cred_handle, cooldown);
            node.mark_cooldown(cooldown);
        } else if is_retryable_status(status) {
            node.record_transient_failure(self.router.routing_config().failure_cooldown_base_secs);
        } else {
            node.record_success();
        }

        Ok(self.wrap_upstream_response(
            upstream_resp,
            &node.name,
            affinity_source,
            path_and_query,
            telemetry,
            upload_timing,
            target_proto,
        ))
    }

    /// Buffered lightweight-inspect path with zero-copy model rewriting, cross-protocol
    /// translation when `ingress_proto != node.protocol`, and pre-first-byte retry.
    #[allow(clippy::too_many_arguments)]
    async fn forward_buffered_with_retry(
        &self,
        method: Method,
        incoming_headers: &HeaderMap,
        path_and_query: &str,
        ingress_proto: Option<ProtocolFamily>,
        model: Option<&str>,
        policy: Option<&AccessPolicy>,
        raw_body: Bytes,
        model_span: Option<ModelSpan>,
        telemetry: RequestTelemetry,
    ) -> Result<Response<ProxyBody>, GatewayError> {
        let req_id = telemetry.req_id;
        let affinity: Option<AffinityContext> = if self.router.needs_affinity_extraction(model, policy) {
            self.affinity_extractor.extract(
                incoming_headers,
                &raw_body,
                ingress_proto,
                policy.and_then(|p| p.owner_user_id),
                model,
            )
        } else {
            None
        };
        let affinity_hash = affinity.as_ref().map(|a| a.hash);
        let affinity_source = affinity.as_ref().map(|a| a.source.as_str());

        let plan = self
            .router
            .plan_route(model, ingress_proto, policy, affinity_hash);
        if plan.blocked_by_policy {
            return Err(GatewayError::Forbidden(format!(
                "API key is not permitted to access any upstream for model '{}'",
                model.unwrap_or("<default>")
            )));
        }
        if plan.candidates.is_empty() {
            return Err(GatewayError::NoRoute(
                model.unwrap_or("<default>").to_string(),
            ));
        }

        let candidates = &plan.candidates;
        let max_attempts = candidates
            .iter()
            .map(|n| n.max_retries.saturating_add(1))
            .max()
            .unwrap_or(1)
            .min(candidates.len());

        let mut last_err: Option<GatewayError> = None;

        for (attempt, node) in candidates.iter().take(max_attempts).enumerate() {
            let has_more_attempts = attempt + 1 < max_attempts;
            self.emit_start(
                &telemetry,
                policy.and_then(|p| p.owner_user_id),
                &node.name,
                model,
                path_and_query,
            );

            // Resolve best endpoint on this node: zero-copy native protocol if supported,
            // otherwise fall back to node's primary protocol with translation.
            let (target_proto, endpoint) = node.resolve_endpoint(ingress_proto);
            let cross_proto = ingress_proto
                .filter(|&in_p| needs_translation(in_p, target_proto));

            let mut oauth_refreshed_on_node = false;

            loop {
                let antigravity_session = if cross_proto == Some(ProtocolFamily::OpenAi)
                    && target_proto == ProtocolFamily::Antigravity
                    && let Some(mgr) = node.auth.oauth_manager()
                {
                    let origin = format!("{}://{}", endpoint.base_scheme, endpoint.base_authority);
                    match mgr.antigravity_session(&origin).await {
                        Ok(session) => Some(session),
                        Err(err) => {
                            last_err = Some(err);
                            break;
                        }
                    }
                } else {
                    None
                };

                // Fast Path (same protocol): zero-copy slice rewrite or O(1) Bytes::clone.
                // Cross-Protocol Path (L1 framework): translate request + path + headers.
                let claude_code_compat =
                    node.is_claude_code_oauth && target_proto == ProtocolFamily::Anthropic;

                let (
                    mut target_path,
                    body,
                    content_length_override,
                    proto_headers,
                    effective_model,
                    translated_is_stream,
                ) = if let Some(in_p) = cross_proto {
                    let mapped = model.and_then(|m| node.mapped_model(m));
                    let project = antigravity_session
                        .as_ref()
                        .and_then(|session| session.antigravity_project_id.as_deref());
                    let tr = if let Some(project) = project {
                        openai_to_antigravity_project_request(&raw_body, mapped, project)?
                    } else {
                        translate_request_with_session(
                            in_p,
                            target_proto,
                            &raw_body,
                            mapped,
                            affinity.as_ref().map(|a| a.session_id.as_str()),
                        )?
                    };
                    let final_bytes = if claude_code_compat {
                        ensure_claude_code_system_prompt(&tr.body).unwrap_or(tr.body)
                    } else {
                        tr.body
                    };
                    let len = final_bytes.len() as u64;
                    (
                        tr.target_path_and_query,
                        ProxyBody::full(final_bytes),
                        Some(len),
                        tr.extra_headers,
                        tr.model,
                        tr.is_stream,
                    )
                } else if claude_code_compat {
                    // For real Claude Code clients, `"You are Claude Code"` is already present
                    // and we stay on the zero-copy path; for non-Claude-Code clients we inject
                    // the required identity system block so Anthropic OAuth accepts the request.
                    let rewritten_bytes = if let (Some(span), Some(orig_model)) =
                        (model_span.as_ref(), model)
                        && let Some(mapped) = node.mapped_model(orig_model)
                        && mapped != orig_model
                    {
                        let mut v = Vec::with_capacity(
                            raw_body.len() + mapped.len().saturating_sub(orig_model.len()),
                        );
                        v.extend_from_slice(&raw_body[..span.value_range.start]);
                        v.extend_from_slice(mapped.as_bytes());
                        v.extend_from_slice(&raw_body[span.value_range.end..]);
                        Bytes::from(v)
                    } else {
                        raw_body.clone()
                    };
                    if let Some(patched) = ensure_claude_code_system_prompt(&rewritten_bytes) {
                        let len = patched.len() as u64;
                        (
                            path_and_query.to_string(),
                            ProxyBody::full(patched),
                            Some(len),
                            Vec::new(),
                            model.unwrap_or("").to_string(),
                            false,
                        )
                    } else {
                        let (body, cl) = build_rewritten_or_cloned_body(
                            &raw_body,
                            model_span.as_ref(),
                            model,
                            node,
                        );
                        (
                            path_and_query.to_string(),
                            body,
                            cl,
                            Vec::new(),
                            model.unwrap_or("").to_string(),
                            false,
                        )
                    }
                } else {
                    let mapped_model = model.and_then(|m| node.mapped_model(m));
                    if node.strip_openai_cache_fields
                        && let Some(cleaned) =
                            strip_openai_cache_fields_if_present(&raw_body, mapped_model)
                    {
                        let len = cleaned.len() as u64;
                        (
                            path_and_query.to_string(),
                            ProxyBody::full(cleaned),
                            Some(len),
                            Vec::new(),
                            model.unwrap_or("").to_string(),
                            false,
                        )
                    } else {
                        let (body, cl) = build_rewritten_or_cloned_body(
                            &raw_body,
                            model_span.as_ref(),
                            model,
                            node,
                        );
                        (
                            path_and_query.to_string(),
                            body,
                            cl,
                            Vec::new(),
                            model.unwrap_or("").to_string(),
                            false,
                        )
                    }
                };

                if claude_code_compat {
                    target_path = ensure_beta_query_param(&target_path);
                }

                let (cred_handle, mut upstream_req) = self.build_upstream_request(
                    node,
                    target_proto,
                    endpoint,
                    method.clone(),
                    incoming_headers,
                    &target_path,
                    body,
                    content_length_override,
                    affinity.as_ref(),
                    req_id,
                )?;
                if let Some(session) = antigravity_session
                    && !matches!(cred_handle, CredentialHandle::OAuthGeneration(generation) if generation == session.generation)
                {
                    continue;
                }

                if cross_proto.is_some() {
                    // Request uncompressed payload so we can parse/translate JSON or SSE cleanly.
                    upstream_req
                        .headers_mut()
                        .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
                    if translated_is_stream {
                        upstream_req
                            .headers_mut()
                            .insert(header::ACCEPT, HeaderValue::from_static("text/event-stream"));
                    }
                }

                for (k, v) in proto_headers {
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_bytes()),
                        HeaderValue::from_str(&v),
                    ) {
                        upstream_req.headers_mut().entry(hn).or_insert(hv);
                    }
                }

                match self.send_upstream_request(node, upstream_req).await {
                    Ok((resp, upload_timing)) => {
                        let status = resp.status();

                        // Native OAuth 401 Singleflight refresh + transparent in-place retry.
                        if status == StatusCode::UNAUTHORIZED
                            && !oauth_refreshed_on_node
                            && let CredentialHandle::OAuthGeneration(failed_gen) = cred_handle
                            && let Some(mgr) = node.auth.oauth_manager()
                            && mgr.can_refresh()
                        {
                            oauth_refreshed_on_node = true;
                            match mgr.refresh_via_http(failed_gen).await {
                                Ok(_) => {
                                    info!(
                                        %req_id,
                                        upstream = %node.name,
                                        "OAuth token refreshed after 401, retrying request transparently"
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    warn!(
                                        %req_id,
                                        upstream = %node.name,
                                        error = %err,
                                        "OAuth Singleflight refresh after 401 failed"
                                    );
                                }
                            }
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let cooldown = parse_retry_after(resp.headers())
                                .unwrap_or(node.default_cooldown_secs);
                            node.auth.on_rate_limited(cred_handle, cooldown);
                            node.mark_cooldown(cooldown);
                            if has_more_attempts {
                                warn!(
                                    %req_id,
                                    upstream = %node.name,
                                    cooldown_secs = cooldown,
                                    "upstream rate-limited (429), retrying next candidate"
                                );
                                break;
                            }
                        } else if is_retryable_status(status) {
                            node.record_transient_failure(
                                self.router.routing_config().failure_cooldown_base_secs,
                            );
                            if has_more_attempts {
                                warn!(
                                    %req_id,
                                    upstream = %node.name,
                                    %status,
                                    "transient upstream status before first byte, retrying next candidate"
                                );
                                break;
                            }
                        } else if status != StatusCode::UNAUTHORIZED {
                            node.record_success();
                        }

                        if status.is_success()
                            && let Some(aff) = affinity.as_ref()
                            && (plan.primary_hrw_node.as_deref() != Some(node.name.as_str())
                                || plan.sticky_hit)
                        {
                            self.router.record_failover_success(aff.hash, &node.name);
                        }

                        if let Some(in_p) = cross_proto
                            && status.is_success()
                        {
                            return self
                                .wrap_translated_response(
                                    resp,
                                    in_p,
                                    target_proto,
                                    &effective_model,
                                    &node.name,
                                    affinity_source,
                                    translated_is_stream,
                                    telemetry,
                                    upload_timing,
                                )
                                .await;
                        }

                        return Ok(self.wrap_upstream_response(
                            resp,
                            &node.name,
                            affinity_source,
                            path_and_query,
                            telemetry,
                            upload_timing,
                            target_proto,
                        ));
                    }
                    Err(err) => {
                        node.record_transient_failure(
                            self.router.routing_config().failure_cooldown_base_secs,
                        );
                        warn!(
                            %req_id,
                            upstream = %node.name,
                            attempt = attempt + 1,
                            error = %err,
                            "upstream request failed before first byte"
                        );
                        last_err = Some(err);
                        break;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| GatewayError::Internal("exhausted upstream candidates".into())))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_upstream_request(
        &self,
        node: &UpstreamNode,
        target_proto: ProtocolFamily,
        endpoint: &ParsedEndpoint,
        method: Method,
        incoming_headers: &HeaderMap,
        path_and_query: &str,
        body: ProxyBody,
        content_length_override: Option<u64>,
        affinity: Option<&AffinityContext>,
        req_id: RequestId,
    ) -> Result<(ttt_auth::CredentialHandle, Request<ProxyBody>), GatewayError> {
        let target_uri = endpoint.build_target_uri(path_and_query)?;
        let mut builder = Request::builder().method(method).uri(target_uri);

        let headers = builder
            .headers_mut()
            .ok_or_else(|| GatewayError::Internal("failed to access request headers".into()))?;

        copy_filtered_request_headers(incoming_headers, headers);

        // Outbound session header mapping & optional cleanup of heterogeneous agent headers.
        let out_session_header = node.resolve_outbound_session_header(target_proto);
        if node.strip_other_session_headers {
            let to_remove: Vec<HeaderName> = headers
                .keys()
                .filter(|k| {
                    self.affinity_extractor.is_session_header(k)
                        && Some(*k) != out_session_header.as_ref()
                })
                .cloned()
                .collect();
            for k in to_remove {
                headers.remove(&k);
            }
        }
        if let Some(target_hdr) = out_session_header
            && !headers.contains_key(&target_hdr)
        {
            if let Some(aff) = affinity
                && let Ok(hv) = HeaderValue::from_str(&aff.session_id)
            {
                headers.insert(target_hdr, hv);
            } else if node.effective_cache_mode == PromptCacheMode::OpenCode
                && let Ok(hv) = HeaderValue::from_str(&format!("ses_ttt-{req_id}"))
            {
                headers.insert(target_hdr, hv);
            }
        }

        // Update Content-Length if zero-copy model rewrite changed payload length.
        if let Some(len) = content_length_override {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        }

        // Inject global extra headers, then protocol-scoped headers, then upstream auth credential.
        for (k, v) in &node.extra_headers {
            if k.as_str() == "anthropic-beta"
                && let Ok(s) = v.to_str()
            {
                merge_comma_header(headers, k, s);
            } else {
                headers.insert(k.clone(), v.clone());
            }
        }
        if let Some(scoped) = node.protocol_headers.get(&target_proto) {
            for (k, v) in scoped {
                if k.as_str() == "anthropic-beta"
                    && let Ok(s) = v.to_str()
                {
                    merge_comma_header(headers, k, s);
                } else {
                    headers.insert(k.clone(), v.clone());
                }
            }
        }

        // Claude Code OAuth compatibility headers: merge required beta flags without clobbering
        // client flags, and mimic Claude CLI headers only when the caller is not already Claude CLI.
        if node.is_claude_code_oauth && target_proto == ProtocolFamily::Anthropic {
            let beta_name = HeaderName::from_static("anthropic-beta");
            merge_comma_header(headers, &beta_name, "claude-code-20250219,oauth-2025-04-20");

            headers
                .entry(HeaderName::from_static("anthropic-version"))
                .or_insert_with(|| HeaderValue::from_static("2023-06-01"));

            let is_real_claude_cli = incoming_headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|ua| ua.starts_with("claude-cli/"))
                .unwrap_or(false);
            if !is_real_claude_cli {
                headers.insert(
                    header::USER_AGENT,
                    HeaderValue::from_static("claude-cli/2.1.251 (external, cli)"),
                );
                headers.insert(
                    HeaderName::from_static("x-app"),
                    HeaderValue::from_static("cli"),
                );
                headers.insert(
                    HeaderName::from_static("anthropic-dangerous-direct-browser-access"),
                    HeaderValue::from_static("true"),
                );
            }
        }

        let (cred_handle, cred) = node.auth.acquire_with_affinity(affinity.map(|a| a.hash));
        headers.insert(cred.header_name, cred.header_value);

        debug!(
            upstream = %node.name,
            auth_mode = node.auth.mode_name(),
            "forwarding request to upstream"
        );

        let req = builder
            .body(body)
            .map_err(|e| GatewayError::Internal(format!("failed to build upstream request: {e}")))?;
        Ok((cred_handle, req))
    }

    #[allow(clippy::too_many_arguments)]
    fn wrap_upstream_response(
        &self,
        upstream_resp: Response<Incoming>,
        upstream_name: &str,
        affinity_source: Option<&str>,
        path_and_query: &str,
        telemetry: RequestTelemetry,
        upload_timing: Option<UploadTiming>,
        target_proto: ProtocolFamily,
    ) -> Response<ProxyBody> {
        let RequestTelemetry { req_id, started_at, lifetime } = telemetry;
        let (parts, body) = upstream_resp.into_parts();
        let status = parts.status;
        let is_sse = is_event_stream(&parts.headers);
        let path = path_and_query.split('?').next().unwrap_or_default();
        let is_stream = is_sse || (status.is_success() && path.ends_with(":streamGenerateContent"));
        let native_sse = if is_sse
            && status.is_success()
            && detect_ingress_protocol(path) == Some(target_proto)
            && parts
                .headers
                .get(header::CONTENT_ENCODING)
                .is_none_or(|encoding| encoding.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            NativeSse::new(target_proto)
        } else {
            None
        };

        let mut builder = Response::builder().status(status);
        if let Some(headers) = builder.headers_mut() {
            copy_filtered_response_headers(&parts.headers, headers);
            if native_sse.is_some() {
                // An incomplete response may need one extra SSE error event.
                headers.remove(header::CONTENT_LENGTH);
            }

            if let Ok(hv) = HeaderValue::from_str(&req_id.to_string()) {
                headers.insert(HEADER_X_TTT_REQUEST_ID.clone(), hv);
            }
            if let Ok(hv) = HeaderValue::from_str(&encode_header_value(upstream_name)) {
                headers.insert(HEADER_X_TTT_UPSTREAM.clone(), hv);
            }
            if let Ok(hv) = HeaderValue::from_str(affinity_source.unwrap_or("none")) {
                headers.insert(HEADER_X_TTT_AFFINITY_SOURCE.clone(), hv);
            }

            // Ensure reverse proxies in front of TalkThatTalk do not buffer SSE chunks.
            if is_sse {
                headers.insert(
                    HEADER_X_ACCEL_BUFFERING.clone(),
                    HeaderValue::from_static("no"),
                );
                headers
                    .entry(header::CACHE_CONTROL)
                    .or_insert_with(|| HeaderValue::from_static("no-cache"));
            }
        }

        let tapped = ProxyBody::tap(
            body,
            req_id,
            lifetime,
            status,
            is_stream,
            started_at,
            upload_timing,
            self.tap_tx.clone(),
            native_sse,
        );
        builder
            .body(tapped)
            .unwrap_or_else(|_| Response::new(ProxyBody::empty()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn wrap_translated_response(
        &self,
        upstream_resp: Response<Incoming>,
        ingress_proto: ProtocolFamily,
        upstream_proto: ProtocolFamily,
        model: &str,
        upstream_name: &str,
        affinity_source: Option<&str>,
        client_wants_stream: bool,
        telemetry: RequestTelemetry,
        upload_timing: Option<UploadTiming>,
    ) -> Result<Response<ProxyBody>, GatewayError> {
        let RequestTelemetry { req_id, started_at, lifetime } = telemetry;
        let (parts, body) = upstream_resp.into_parts();
        let status = parts.status;
        let explicit_json = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
        let is_sse = is_event_stream(&parts.headers) || (client_wants_stream && !explicit_json);

        let mut builder = Response::builder().status(status);
        if let Some(headers) = builder.headers_mut() {
            copy_filtered_response_headers(&parts.headers, headers);
            // Translated body length & encoding differ from upstream.
            headers.remove(header::CONTENT_LENGTH);
            headers.remove(header::CONTENT_ENCODING);

            if let Ok(hv) = HeaderValue::from_str(&req_id.to_string()) {
                headers.insert(HEADER_X_TTT_REQUEST_ID.clone(), hv);
            }
            if let Ok(hv) = HeaderValue::from_str(&encode_header_value(upstream_name)) {
                headers.insert(HEADER_X_TTT_UPSTREAM.clone(), hv);
            }
            if let Ok(hv) = HeaderValue::from_str(affinity_source.unwrap_or("none")) {
                headers.insert(HEADER_X_TTT_AFFINITY_SOURCE.clone(), hv);
            }

            if is_sse || client_wants_stream {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/event-stream; charset=utf-8"),
                );
                headers.insert(
                    HEADER_X_ACCEL_BUFFERING.clone(),
                    HeaderValue::from_static("no"),
                );
                headers
                    .entry(header::CACHE_CONTROL)
                    .or_insert_with(|| HeaderValue::from_static("no-cache"));
            } else {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
            }
        }

        if is_sse {
            let translator =
                create_sse_translator(ingress_proto, upstream_proto, model.to_string())?;
            let stream_body = ProxyBody::translated(
                body,
                translator,
                req_id,
                lifetime,
                status,
                started_at,
                upload_timing,
                self.tap_tx.clone(),
            );
            return Ok(builder
                .body(stream_body)
                .unwrap_or_else(|_| Response::new(ProxyBody::empty())));
        }

        // Translate a complete upstream JSON response before constructing the downstream body.
        let mut upload_timing = upload_timing;
        let mut ttft_ms = None;
        let upstream_bytes = body
            .map_frame(|frame| {
                if upload_timing.is_some() && frame.data_ref().is_some_and(|data| !data.is_empty()) {
                    ttft_ms = upstream_ttft_ms(upload_timing.take().as_ref());
                }
                frame
            })
            .collect()
            .await
            .map_err(|e| GatewayError::UpstreamConnect(format!("{upstream_name}: {e}")))?
            .to_bytes();

        if client_wants_stream {
            let payload: serde_json::Value = serde_json::from_slice(&upstream_bytes)
                .map_err(|err| {
                    GatewayError::UpstreamConnect(format!("{upstream_name}: invalid JSON response: {err}"))
                })?;
            if let Some(error) = payload.get("error").filter(|error| error.is_object() || error.is_string()) {
                let message = error
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| error.as_str())
                    .unwrap_or("upstream returned an error response");
                return Err(GatewayError::UpstreamConnect(format!("{upstream_name}: {message}")));
            }
        }

        if let Some(tx) = &self.tap_tx {
            let elapsed = started_at.elapsed().as_millis() as u64;
            let _ = tx.try_send(TapEvent::ResponseChunk {
                req_id,
                data: upstream_bytes.clone(),
            });
            let _ = tx.try_send(TapEvent::ResponseEnd {
                req_id,
                lifetime,
                status,
                is_stream: client_wants_stream,
                stream_failure: None,
                total_bytes: upstream_bytes.len() as u64,
                ttft_ms,
                duration_ms: elapsed,
            });
        }

        let translated =
            translate_response_json(ingress_proto, upstream_proto, &upstream_bytes, model)?;
        let translated = if client_wants_stream {
            json_response_to_sse(ingress_proto, &translated)?
        } else {
            translated
        };
        if let Some(headers) = builder.headers_mut() {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(translated.len() as u64));
        }

        Ok(builder
            .body(ProxyBody::full(translated))
            .unwrap_or_else(|_| Response::new(ProxyBody::empty())))
    }

    fn emit_start(
        &self,
        telemetry: &RequestTelemetry,
        user_id: Option<i64>,
        upstream: &str,
        model: Option<&str>,
        path: &str,
    ) {
        if let Some(tx) = &self.tap_tx
            && let Some(lifetime) = &telemetry.lifetime
        {
            let _ = tx.try_send(TapEvent::RequestStart {
                req_id: telemetry.req_id,
                lifetime: Arc::downgrade(lifetime),
                user_id,
                upstream: upstream.to_string(),
                model: model.map(ToOwned::to_owned),
                path: path.to_string(),
            });
        }
    }
}

fn compile_client_keys(keys: &[ClientKeyConfig]) -> HashMap<String, CompiledClientKey> {
    keys.iter()
        .map(|key| {
            (key.key.clone(), CompiledClientKey {
                enabled: key.enabled,
                policy: AccessPolicy::new(
                    key.owner_user_id,
                    key.restrict_upstreams.then(|| key.allowed_upstreams.clone()),
                    key.restrict_models.then(|| key.allowed_models.clone()),
                ),
            })
        })
        .collect()
}

fn resolve_client_policy(
    allowed_keys: &HashMap<String, CompiledClientKey>,
    headers: &HeaderMap,
) -> Option<AccessPolicy> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
        if let Some(pol) = allowed_keys.get(token)
            && pol.enabled
        {
            return Some(pol.policy.clone());
        }
    }
    if let Some(key) = headers
        .get(&HEADER_X_API_KEY)
        .and_then(|v| v.to_str().ok())
        && let Some(pol) = allowed_keys.get(key.trim())
        && pol.enabled
    {
        return Some(pol.policy.clone());
    }
    None
}

fn models_list_response(models: &[String]) -> Response<ProxyBody> {
    let data: Vec<serde_json::Value> = models
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": "talkthattalk",
            })
        })
        .collect();
    let payload = serde_json::json!({
        "object": "list",
        "data": data,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(ProxyBody::full(Bytes::from(payload.to_string())))
        .unwrap()
}

fn strip_openai_cache_fields_if_present(
    raw: &[u8],
    mapped_model: Option<&str>,
) -> Option<Bytes> {
    if memchr::memmem::find(raw, b"\"prompt_cache_key\"").is_none()
        && memchr::memmem::find(raw, b"\"prompt_cache_retention\"").is_none()
    {
        return None;
    }
    let mut val: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let obj = val.as_object_mut()?;
    let removed_key = obj.remove("prompt_cache_key").is_some();
    let removed_ret = obj.remove("prompt_cache_retention").is_some();
    if !removed_key && !removed_ret {
        return None;
    }
    if let Some(m) = mapped_model {
        obj.insert("model".to_string(), serde_json::Value::String(m.to_string()));
    }
    serde_json::to_vec(&val).ok().map(Bytes::from)
}

fn build_rewritten_or_cloned_body(
    raw_body: &Bytes,
    model_span: Option<&ModelSpan>,
    model: Option<&str>,
    node: &UpstreamNode,
) -> (ProxyBody, Option<u64>) {
    if let (Some(span), Some(m)) = (model_span, model)
        && let Some(mapped) = node.mapped_model(m)
    {
        let seg = SegmentedBody::from_replacement(
            raw_body,
            span.value_range.start,
            span.value_range.end,
            Bytes::copy_from_slice(mapped.as_bytes()),
        );
        let len = seg.exact_len();
        return (ProxyBody::segmented(seg), Some(len));
    }
    // O(1) zero-copy Bytes::clone()
    (ProxyBody::full(raw_body.clone()), None)
}

fn should_use_pure_stream(
    method: &Method,
    headers: &HeaderMap,
    needs_body_inspection: bool,
    max_inspect_body_bytes: usize,
) -> bool {
    if matches!(
        *method,
        Method::GET | Method::HEAD | Method::DELETE | Method::OPTIONS
    ) {
        return true;
    }

    if !needs_body_inspection {
        return true;
    }

    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false);
    if !is_json {
        return true;
    }

    if let Some(len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && len > max_inspect_body_bytes
    {
        return true;
    }

    false
}

fn copy_filtered_request_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    let conn_tokens = collect_connection_headers(src);
    for (name, value) in src {
        if is_hop_by_hop(name)
            || *name == header::HOST
            || *name == header::AUTHORIZATION
            || *name == HEADER_X_API_KEY
            || *name == HEADER_X_TTT_MODEL
            || *name == HEADER_X_TTT_SESSION_ID
            || conn_tokens.contains(name.as_str())
        {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn copy_filtered_response_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    let conn_tokens = collect_connection_headers(src);
    for (name, value) in src {
        if is_hop_by_hop(name) || conn_tokens.contains(name.as_str()) {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn collect_connection_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut set = HashSet::new();
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    set.insert(t);
                }
            }
        }
    }
    set
}

#[inline]
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        *name,
        header::CONNECTION
            | header::PROXY_AUTHENTICATE
            | header::PROXY_AUTHORIZATION
            | header::TE
            | header::TRAILER
            | header::TRANSFER_ENCODING
            | header::UPGRADE
    ) || name.as_str().eq_ignore_ascii_case("keep-alive")
}

#[inline]
fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
        .unwrap_or(false)
}

#[inline]
fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

fn parse_retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

const CLAUDE_CODE_IDENTITY_PROMPT: &str =
    "You are Claude Code, Anthropic's official CLI for Claude.";

fn ensure_beta_query_param(path_and_query: &str) -> String {
    let path_only = path_and_query.split('?').next().unwrap_or(path_and_query);
    if !path_only.ends_with("/messages") {
        return path_and_query.to_string();
    }
    if let Some((_, q)) = path_and_query.split_once('?') {
        if q.split('&').any(|pair| pair == "beta=true" || pair.starts_with("beta=")) {
            return path_and_query.to_string();
        }
        format!("{path_and_query}&beta=true")
    } else {
        format!("{path_and_query}?beta=true")
    }
}

fn ensure_claude_code_system_prompt(raw: &[u8]) -> Option<Bytes> {
    if memchr::memmem::find(raw, b"You are Claude Code").is_some() {
        return None;
    }
    let mut val: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let obj = val.as_object_mut()?;
    let identity_block = serde_json::json!({
        "type": "text",
        "text": CLAUDE_CODE_IDENTITY_PROMPT,
    });

    match obj.get_mut("system") {
        Some(serde_json::Value::Array(arr)) => {
            arr.insert(0, identity_block);
        }
        Some(serde_json::Value::String(s)) => {
            let existing = std::mem::take(s);
            let mut blocks = vec![identity_block];
            if !existing.is_empty() {
                blocks.push(serde_json::json!({ "type": "text", "text": existing }));
            }
            obj.insert("system".to_string(), serde_json::Value::Array(blocks));
        }
        _ => {
            obj.insert("system".to_string(), serde_json::Value::Array(vec![identity_block]));
        }
    }

    serde_json::to_vec(&val).ok().map(Bytes::from)
}

fn merge_comma_header(headers: &mut HeaderMap, name: &HeaderName, extra_csv: &str) {
    let mut tokens: Vec<String> = Vec::new();
    for val in headers.get_all(name) {
        if let Ok(s) = val.to_str() {
            for part in s.split(',') {
                let t = part.trim();
                if !t.is_empty() && !tokens.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                    tokens.push(t.to_string());
                }
            }
        }
    }
    for part in extra_csv.split(',') {
        let t = part.trim();
        if !t.is_empty() && !tokens.iter().any(|x| x.eq_ignore_ascii_case(t)) {
            tokens.push(t.to_string());
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&tokens.join(",")) {
        headers.insert(name.clone(), hv);
    }
}

fn encode_header_value(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b' ') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn health_response() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(ProxyBody::full(Bytes::from_static(
            br#"{"status":"ok","service":"TalkThatTalk"}"#,
        )))
        .unwrap()
}

fn error_response(err: &GatewayError, req_id: RequestId) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(err.status_code())
        .header(header::CONTENT_TYPE, "application/json");
    if let Ok(hv) = HeaderValue::from_str(&req_id.to_string()) {
        builder = builder.header(HEADER_X_TTT_REQUEST_ID.clone(), hv);
    }
    builder
        .body(ProxyBody::full(err.to_json_bytes()))
        .unwrap()
}
