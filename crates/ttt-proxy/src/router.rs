use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use http::header::{HeaderName, HeaderValue};
use http::uri::{Authority, Scheme, Uri};
use ttt_auth::{AuthProvider, TokenStore};
use ttt_core::{GatewayError, OAuthPreset, ProtocolFamily, UpstreamAuthConfig, UpstreamConfig};

/// Pre-parsed upstream endpoint ready for zero-overhead target URI construction.
#[derive(Debug, Clone)]
pub struct ParsedEndpoint {
    pub base_scheme: Scheme,
    pub base_authority: Authority,
    /// Normalized base path without trailing slash (e.g. "", "/v1", "/api/plan/v3").
    pub base_path_prefix: String,
}

impl ParsedEndpoint {
    pub fn parse(base_url: &str) -> Result<Self, GatewayError> {
        let uri: Uri = base_url.parse().map_err(|e| {
            GatewayError::Config(format!("invalid base_url '{base_url}': {e}"))
        })?;
        let base_scheme = uri
            .scheme()
            .cloned()
            .ok_or_else(|| GatewayError::Config(format!("base_url missing scheme: {base_url}")))?;
        let base_authority = uri.authority().cloned().ok_or_else(|| {
            GatewayError::Config(format!("base_url missing authority: {base_url}"))
        })?;

        let raw_path = uri.path().trim_end_matches('/');
        let base_path_prefix = if raw_path == "/" {
            String::new()
        } else {
            raw_path.to_string()
        };

        Ok(Self {
            base_scheme,
            base_authority,
            base_path_prefix,
        })
    }

    /// Join this endpoint's resolved URL (`base_url + endpoint`) with `incoming_path_and_query`.
    ///
    /// - If this endpoint already points to a concrete protocol action path (e.g.
    ///   `/v1/chat/completions`, `/v3/chat/completions`, `/v1/messages`, `/v1/responses`),
    ///   it is used directly as the final path (preserving any incoming `?query`).
    /// - Otherwise it acts as a base prefix and joins `incoming_path_and_query` with
    ///   version-segment deduplication.
    pub fn build_target_uri(&self, incoming_path_and_query: &str) -> Result<Uri, GatewayError> {
        let joined = if is_concrete_action_path(&self.base_path_prefix) {
            if let Some((_, query)) = incoming_path_and_query.split_once('?') {
                if self.base_path_prefix.contains('?') {
                    format!("{}&{}", self.base_path_prefix, query)
                } else {
                    format!("{}?{}", self.base_path_prefix, query)
                }
            } else {
                self.base_path_prefix.clone()
            }
        } else if self.base_path_prefix.is_empty() {
            incoming_path_and_query.to_string()
        } else {
            let suffix = if ends_with_version_segment(&self.base_path_prefix) {
                strip_leading_version(incoming_path_and_query)
            } else if incoming_path_and_query.starts_with(&self.base_path_prefix) {
                return Uri::builder()
                    .scheme(self.base_scheme.clone())
                    .authority(self.base_authority.clone())
                    .path_and_query(incoming_path_and_query)
                    .build()
                    .map_err(|e| {
                        GatewayError::InvalidRequest(format!("failed to build upstream URI: {e}"))
                    });
            } else {
                incoming_path_and_query
            };

            if suffix.is_empty() || suffix.starts_with('/') || suffix.starts_with('?') {
                format!("{}{}", self.base_path_prefix, suffix)
            } else {
                format!("{}/{}", self.base_path_prefix, suffix)
            }
        };

        Uri::builder()
            .scheme(self.base_scheme.clone())
            .authority(self.base_authority.clone())
            .path_and_query(joined)
            .build()
            .map_err(|e| GatewayError::InvalidRequest(format!("failed to build upstream URI: {e}")))
    }
}

pub struct UpstreamNode {
    pub name: String,
    pub default_protocol: ProtocolFamily,
    pub is_claude_code_oauth: bool,
    pub owner_user_id: Option<i64>,
    pub proxy: Option<String>,
    pub endpoints: HashMap<ProtocolFamily, ParsedEndpoint>,
    pub auth: AuthProvider,
    pub extra_headers: Vec<(HeaderName, HeaderValue)>,
    pub protocol_headers: HashMap<ProtocolFamily, Vec<(HeaderName, HeaderValue)>>,
    pub model_mapping: HashMap<String, String>,
    pub default_cooldown_secs: u64,
    pub max_retries: usize,
    cooldown_until_ms: AtomicU64,
}

impl UpstreamNode {
    pub fn from_config(
        cfg: &UpstreamConfig,
        token_store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        let raw_endpoints = cfg.effective_endpoints();
        if raw_endpoints.is_empty() {
            return Err(GatewayError::Config(format!(
                "upstream '{}' has no protocol endpoints",
                cfg.name
            )));
        }

        let mut endpoints = HashMap::with_capacity(raw_endpoints.len());
        for (proto, url) in raw_endpoints {
            endpoints.insert(proto, ParsedEndpoint::parse(&url)?);
        }
        let default_protocol = cfg.primary_protocol();

        let auth = AuthProvider::from_config(&cfg.name, &cfg.auth, token_store)?;

        let mut extra_headers = Vec::with_capacity(cfg.extra_headers.len());
        for (k, v) in &cfg.extra_headers {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                GatewayError::Config(format!(
                    "upstream '{}' invalid extra header name '{k}': {e}",
                    cfg.name
                ))
            })?;
            let val = HeaderValue::from_str(v).map_err(|e| {
                GatewayError::Config(format!(
                    "upstream '{}' invalid extra header value for '{k}': {e}",
                    cfg.name
                ))
            })?;
            extra_headers.push((name, val));
        }

        let mut protocol_headers: HashMap<ProtocolFamily, Vec<(HeaderName, HeaderValue)>> =
            HashMap::with_capacity(cfg.protocol_headers.len());
        for (proto, map) in &cfg.protocol_headers {
            let mut list = Vec::with_capacity(map.len());
            for (k, v) in map {
                let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                    GatewayError::Config(format!(
                        "upstream '{}' invalid protocol header name '{k}': {e}",
                        cfg.name
                    ))
                })?;
                let val = HeaderValue::from_str(v).map_err(|e| {
                    GatewayError::Config(format!(
                        "upstream '{}' invalid protocol header value for '{k}': {e}",
                        cfg.name
                    ))
                })?;
                list.push((name, val));
            }
            if !list.is_empty() {
                protocol_headers.insert(*proto, list);
            }
        }

        let is_claude_code_oauth = matches!(
            cfg.auth,
            UpstreamAuthConfig::OAuth {
                preset: Some(OAuthPreset::ClaudeCode),
                ..
            }
        );

        Ok(Self {
            name: cfg.name.clone(),
            default_protocol,
            is_claude_code_oauth,
            owner_user_id: cfg.owner_user_id,
            proxy: cfg
                .proxy
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned),
            endpoints,
            auth,
            extra_headers,
            protocol_headers,
            model_mapping: cfg.model_mapping.clone(),
            default_cooldown_secs: cfg.default_cooldown_secs,
            max_retries: cfg.max_retries,
            cooldown_until_ms: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn supports_protocol(&self, proto: ProtocolFamily) -> bool {
        self.endpoints.contains_key(&proto)
    }

    /// Resolve the best endpoint for an incoming protocol:
    /// prefers native zero-copy pass-through when `ingress_proto` is present in `endpoints`,
    /// otherwise falls back to `default_protocol` (triggering cross-protocol translation).
    #[inline]
    pub fn resolve_endpoint(
        &self,
        ingress_proto: Option<ProtocolFamily>,
    ) -> (ProtocolFamily, &ParsedEndpoint) {
        if let Some(p) = ingress_proto
            && let Some(ep) = self.endpoints.get(&p)
        {
            return (p, ep);
        }
        let ep = self
            .endpoints
            .get(&self.default_protocol)
            .or_else(|| self.endpoints.values().next())
            .expect("validated upstream always has at least one endpoint");
        (self.default_protocol, ep)
    }

    #[inline]
    pub fn is_cooling_down(&self, now_ms: u64) -> bool {
        let until = self.cooldown_until_ms.load(Ordering::Relaxed);
        until != 0 && now_ms < until
    }

    pub fn mark_cooldown(&self, secs: u64) {
        let until = now_epoch_ms().saturating_add(secs.saturating_mul(1000));
        self.cooldown_until_ms.store(until, Ordering::Relaxed);
    }

    #[inline]
    pub fn mapped_model(&self, model: &str) -> Option<&str> {
        self.model_mapping.get(model).map(String::as_str)
    }
}

struct WeightedPool {
    weighted_ring: Vec<usize>,
    unique_nodes: Vec<Arc<UpstreamNode>>,
    cursor: AtomicUsize,
}

impl WeightedPool {
    fn new() -> Self {
        Self {
            weighted_ring: Vec::new(),
            unique_nodes: Vec::new(),
            cursor: AtomicUsize::new(0),
        }
    }

    fn push(&mut self, node: Arc<UpstreamNode>, weight: u32) {
        let idx = self.unique_nodes.len();
        self.unique_nodes.push(node);
        for _ in 0..weight.max(1) {
            self.weighted_ring.push(idx);
        }
    }

    /// Return ordered unique candidate nodes starting from weighted round-robin position.
    ///
    /// Protocol-affinity priority tiers (preserving weighted RR within each tier):
    /// 1. Healthy + natively supports `ingress_proto` (zero-copy, no translation)
    /// 2. Healthy + requires protocol translation (fallback)
    /// 3. Cooling down + natively supports `ingress_proto`
    /// 4. Cooling down + requires protocol translation
    fn select_candidates(&self, ingress_proto: Option<ProtocolFamily>) -> Vec<Arc<UpstreamNode>> {
        if self.unique_nodes.is_empty() {
            return Vec::new();
        }
        let ring_idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.weighted_ring.len();
        let primary_node_idx = self.weighted_ring[ring_idx];
        let total = self.unique_nodes.len();
        let now = now_epoch_ms();

        let mut healthy_native = Vec::with_capacity(total);
        let mut healthy_translate = Vec::new();
        let mut cooling_native = Vec::new();
        let mut cooling_translate = Vec::new();

        for offset in 0..total {
            let idx = (primary_node_idx + offset) % total;
            let node = Arc::clone(&self.unique_nodes[idx]);
            let native = ingress_proto
                .map(|p| node.supports_protocol(p))
                .unwrap_or(true);
            let cooling = node.is_cooling_down(now);

            match (cooling, native) {
                (false, true) => healthy_native.push(node),
                (false, false) => healthy_translate.push(node),
                (true, true) => cooling_native.push(node),
                (true, false) => cooling_translate.push(node),
            }
        }

        healthy_native.extend(healthy_translate);
        healthy_native.extend(cooling_native);
        healthy_native.extend(cooling_translate);
        healthy_native
    }
}

struct RoutingTable {
    exact: HashMap<String, WeightedPool>,
    wildcard: WeightedPool,
    all_nodes: Vec<Arc<UpstreamNode>>,
    has_model_rules: bool,
    has_model_mapping: bool,
    has_mixed_protocols: bool,
}

impl RoutingTable {
    fn build(
        configs: &[UpstreamConfig],
        token_store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        let mut exact: HashMap<String, WeightedPool> = HashMap::new();
        let mut wildcard = WeightedPool::new();
        let mut all_nodes = Vec::with_capacity(configs.len());
        let mut has_model_mapping = false;
        let mut has_mixed_protocols = false;

        for cfg in configs {
            let node = Arc::new(UpstreamNode::from_config(cfg, token_store.clone())?);
            if node.default_protocol != ProtocolFamily::OpenAi || node.endpoints.len() > 1 {
                has_mixed_protocols = true;
            }
            all_nodes.push(Arc::clone(&node));
            if !node.model_mapping.is_empty() {
                has_model_mapping = true;
            }
            for model in &cfg.models {
                if model == "*" {
                    wildcard.push(Arc::clone(&node), cfg.weight);
                } else {
                    exact
                        .entry(model.clone())
                        .or_insert_with(WeightedPool::new)
                        .push(Arc::clone(&node), cfg.weight);
                }
            }
        }

        let has_model_rules = !exact.is_empty();
        Ok(Self {
            exact,
            wildcard,
            all_nodes,
            has_model_rules,
            has_model_mapping,
            has_mixed_protocols,
        })
    }
}

/// Lock-free router supporting atomic hot-reload via `ArcSwap`.
pub struct Router {
    table: ArcSwap<RoutingTable>,
    token_store: Option<Arc<dyn TokenStore>>,
}

impl Router {
    pub fn new(
        configs: &[UpstreamConfig],
        token_store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        let table = RoutingTable::build(configs, token_store.clone())?;
        Ok(Self {
            table: ArcSwap::from_pointee(table),
            token_store,
        })
    }

    pub fn reload(&self, configs: &[UpstreamConfig]) -> Result<(), GatewayError> {
        let next = RoutingTable::build(configs, self.token_store.clone())?;
        self.table.store(Arc::new(next));
        Ok(())
    }

    pub fn all_nodes(&self) -> Vec<Arc<UpstreamNode>> {
        self.table.load().all_nodes.clone()
    }

    pub fn list_models(&self) -> Vec<String> {
        let table = self.table.load();
        let mut models: Vec<String> = table.exact.keys().cloned().collect();
        models.sort();
        models
    }

    #[inline]
    pub fn needs_body_inspection(&self) -> bool {
        let table = self.table.load();
        table.has_model_rules || table.has_model_mapping || table.has_mixed_protocols
    }

    /// Select ordered candidate upstreams for the requested model with protocol affinity.
    pub fn select_candidates(
        &self,
        model: Option<&str>,
        ingress_proto: Option<ProtocolFamily>,
    ) -> Vec<Arc<UpstreamNode>> {
        let table = self.table.load();
        if let Some(m) = model
            && let Some(pool) = table.exact.get(m)
        {
            let candidates = pool.select_candidates(ingress_proto);
            if !candidates.is_empty() {
                return candidates;
            }
        }
        table.wildcard.select_candidates(ingress_proto)
    }
}

fn is_concrete_action_path(path: &str) -> bool {
    path.ends_with("/chat/completions")
        || path.ends_with("/messages")
        || path.ends_with("/responses")
        || path.contains(":generateContent")
        || path.contains(":streamGenerateContent")
}

fn ends_with_version_segment(path: &str) -> bool {
    let seg = path.rsplit('/').next().unwrap_or("");
    if seg == "v1beta" {
        return true;
    }
    let Some(rest) = seg.strip_prefix('v') else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

fn strip_leading_version(path: &str) -> &str {
    for prefix in ["/v1beta", "/v1"] {
        if let Some(rest) = path.strip_prefix(prefix)
            && (rest.is_empty() || rest.starts_with('/') || rest.starts_with('?'))
        {
            return rest;
        }
    }
    path
}

#[inline]
fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ttt_core::{UpstreamAuthConfig, UpstreamConfig};

    fn make_node(name: &str, endpoints: Vec<(ProtocolFamily, &str)>) -> UpstreamConfig {
        let mut map = HashMap::new();
        let first_proto = endpoints[0].0;
        let first_url = endpoints[0].1.to_string();
        for (p, u) in endpoints {
            map.insert(p, u.to_string());
        }
        UpstreamConfig {
            name: name.into(),
            base_url: first_url,
            protocol: first_proto,
            protocol_endpoints: map,
            auth: UpstreamAuthConfig::ApiKey {
                keys: vec!["sk-1".into()],
                header_name: "authorization".into(),
                prefix: Some("Bearer ".into()),
            },
            models: vec!["ark-code-latest".into()],
            model_mapping: HashMap::new(),
            extra_headers: HashMap::new(),
            protocol_headers: HashMap::new(),
            weight: 1,
            default_cooldown_secs: 30,
            max_retries: 0,
            owner_user_id: None,
            proxy: None,
        }
    }

    #[test]
    fn deduplicates_version_segments_for_v1_v3_and_v1beta() {
        let ep_v1 = ParsedEndpoint::parse("https://openrouter.ai/api/v1").unwrap();
        assert_eq!(
            ep_v1.build_target_uri("/v1/chat/completions").unwrap().to_string(),
            "https://openrouter.ai/api/v1/chat/completions"
        );

        let ep_v3 = ParsedEndpoint::parse("https://ark.cn-beijing.volces.com/api/v3").unwrap();
        assert_eq!(
            ep_v3.build_target_uri("/v1/chat/completions").unwrap().to_string(),
            "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
        );

        let ep_plan_v1 = ParsedEndpoint::parse("https://ark.cn-beijing.volces.com/api/plan/v1").unwrap();
        assert_eq!(
            ep_plan_v1.build_target_uri("/v1/messages").unwrap().to_string(),
            "https://ark.cn-beijing.volces.com/api/plan/v1/messages"
        );

        // Concrete `base_url + endpoint` paths are used directly without double-appending.
        let exact = ParsedEndpoint::parse(&UpstreamConfig::join_base_and_endpoint(
            "https://ark.cn-beijing.volces.com/api/plan",
            "/v3/chat/completions",
        ))
        .unwrap();
        assert_eq!(
            exact.build_target_uri("/v1/chat/completions").unwrap().to_string(),
            "https://ark.cn-beijing.volces.com/api/plan/v3/chat/completions"
        );
    }

    #[test]
    fn protocol_affinity_prefers_zero_copy_native_provider() {
        let openai_only = make_node(
            "openai-only",
            vec![(ProtocolFamily::OpenAi, "https://a.example.com/v1")],
        );
        let multi = make_node(
            "agent-plan-multi",
            vec![
                (ProtocolFamily::Anthropic, "https://ark.cn-beijing.volces.com/api/plan/v1"),
                (ProtocolFamily::OpenAi, "https://ark.cn-beijing.volces.com/api/plan/v3"),
            ],
        );

        let router = Router::new(&[openai_only, multi], None).unwrap();

        // Anthropic ingress must always prioritize `agent-plan-multi` (native zero-copy) ahead of `openai-only`.
        for _ in 0..4 {
            let cands = router.select_candidates(Some("ark-code-latest"), Some(ProtocolFamily::Anthropic));
            assert_eq!(cands[0].name, "agent-plan-multi");
            let (proto, ep) = cands[0].resolve_endpoint(Some(ProtocolFamily::Anthropic));
            assert_eq!(proto, ProtocolFamily::Anthropic);
            assert_eq!(
                ep.build_target_uri("/v1/messages").unwrap().to_string(),
                "https://ark.cn-beijing.volces.com/api/plan/v1/messages"
            );
        }
    }
}
