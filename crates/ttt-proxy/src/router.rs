use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use http::header::{HeaderName, HeaderValue};
use http::uri::{Authority, Scheme, Uri};
use ttt_auth::{AuthProvider, TokenStore};
use ttt_core::{
    GatewayError, OAuthPreset, PromptCacheMode, ProtocolFamily, RoutingConfig, UpstreamAuthConfig,
    UpstreamConfig,
};
use ttt_protocol::supports_translation;

use crate::affinity::{hash_str_64, mix64};

/// Client key access control policy evaluated before upstream candidate selection.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub owner_user_id: Option<i64>,
    pub allowed_upstreams: Option<HashSet<String>>,
    pub allowed_models: Option<HashSet<String>>,
}

impl AccessPolicy {
    pub fn new(
        owner_user_id: Option<i64>,
        allowed_upstreams: Option<Vec<String>>,
        allowed_models: Option<Vec<String>>,
    ) -> Self {
        Self {
            owner_user_id,
            allowed_upstreams: allowed_upstreams.map(|names| names.into_iter().collect()),
            allowed_models: allowed_models.map(|names| names.into_iter().collect()),
        }
    }

    #[inline]
    pub fn allows_model(&self, model: Option<&str>) -> bool {
        self.allowed_models
            .as_ref()
            .is_none_or(|allowed| model.is_some_and(|m| allowed.contains(m)))
    }

    #[inline]
    pub fn allows_upstream(&self, upstream_name: &str) -> bool {
        self.allowed_upstreams
            .as_ref()
            .is_none_or(|allowed| allowed.contains(upstream_name))
    }

    /// Enforce owner isolation + user-level global upstream allowlist.
    /// - Private upstreams (`owner_user_id = Some(uid)`) are ONLY routable by keys owned by `uid`.
    /// - Global upstreams (`owner_user_id = None`) are subject to `restrict_upstreams` / `allowed_upstreams`.
    #[inline]
    pub fn can_access_node(&self, node: &UpstreamNode) -> bool {
        if let Some(node_owner) = node.owner_user_id {
            return self.owner_user_id == Some(node_owner);
        }
        self.allows_upstream(&node.name)
    }
}

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
    pub name_hash: u64,
    pub weight: u32,
    pub default_protocol: ProtocolFamily,
    pub is_claude_code_oauth: bool,
    pub is_codex_oauth: bool,
    pub effective_cache_mode: PromptCacheMode,
    pub strip_openai_cache_fields: bool,
    pub session_header_out: Option<HeaderName>,
    pub strip_other_session_headers: bool,
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
    consecutive_failures: AtomicU32,
    quota_exhausted: AtomicBool,
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
        let is_codex_oauth = matches!(
            cfg.auth,
            UpstreamAuthConfig::OAuth {
                preset: Some(OAuthPreset::Codex),
                ..
            }
        );
        let session_header_out = match cfg
            .session_header_out
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(raw) => Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                GatewayError::Config(format!(
                    "upstream '{}' invalid session_header_out '{raw}': {e}",
                    cfg.name
                ))
            })?),
            None => None,
        };
        let effective_cache_mode =
            resolve_effective_cache_mode(cfg, &endpoints, is_codex_oauth);
        let strip_openai_cache_fields =
            effective_cache_mode == PromptCacheMode::StripOpenAiCacheFields;

        Ok(Self {
            name: cfg.name.clone(),
            name_hash: hash_str_64(&cfg.name),
            weight: cfg.weight.max(1),
            default_protocol,
            is_claude_code_oauth,
            is_codex_oauth,
            effective_cache_mode,
            strip_openai_cache_fields,
            session_header_out,
            strip_other_session_headers: cfg.strip_other_session_headers,
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
            consecutive_failures: AtomicU32::new(0),
            quota_exhausted: AtomicBool::new(false),
        })
    }

    #[inline]
    pub fn supports_protocol(&self, proto: ProtocolFamily) -> bool {
        self.endpoints.contains_key(&proto)
    }

    #[inline]
    pub fn can_handle_protocol(&self, ingress_proto: Option<ProtocolFamily>) -> bool {
        match ingress_proto {
            None => true,
            Some(in_p) => {
                self.supports_protocol(in_p) || supports_translation(in_p, self.default_protocol)
            }
        }
    }

    #[inline]
    pub fn key_count(&self) -> usize {
        self.auth.key_count()
    }

    /// Resolve the outbound session header name for `target_proto`, using explicit
    /// `session_header_out` first, then the resolved built-in provider `PromptCacheMode`.
    #[inline]
    pub fn resolve_outbound_session_header(&self, target_proto: ProtocolFamily) -> Option<HeaderName> {
        if let Some(ref hn) = self.session_header_out {
            return Some(hn.clone());
        }
        match self.effective_cache_mode {
            PromptCacheMode::XaiGrok => Some(HeaderName::from_static("x-grok-conv-id")),
            PromptCacheMode::OpenRouter => Some(HeaderName::from_static("x-session-id")),
            PromptCacheMode::OpenCode => Some(HeaderName::from_static("x-opencode-session")),
            PromptCacheMode::OpenAi
                if self.is_codex_oauth || target_proto == ProtocolFamily::OpenAiResponses =>
            {
                Some(HeaderName::from_static("session_id"))
            }
            _ => None,
        }
    }

    #[inline]
    pub fn needs_outbound_session_mapping(&self) -> bool {
        self.session_header_out.is_some()
            || self.strip_other_session_headers
            || self.strip_openai_cache_fields
            || matches!(
                self.effective_cache_mode,
                PromptCacheMode::XaiGrok | PromptCacheMode::OpenRouter | PromptCacheMode::OpenCode
            )
            || self.is_codex_oauth
            || (self.effective_cache_mode == PromptCacheMode::OpenAi
                && (self.default_protocol == ProtocolFamily::OpenAiResponses
                    || self.endpoints.contains_key(&ProtocolFamily::OpenAiResponses)))
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

    #[inline]
    pub fn is_degraded(&self, now_ms: u64, quota_aware: bool) -> bool {
        self.is_cooling_down(now_ms)
            || (quota_aware && self.quota_exhausted.load(Ordering::Relaxed))
    }

    pub fn mark_cooldown(&self, secs: u64) {
        let until = now_epoch_ms().saturating_add(secs.saturating_mul(1000));
        self.cooldown_until_ms.store(until, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        if self.consecutive_failures.load(Ordering::Relaxed) != 0 {
            self.consecutive_failures.store(0, Ordering::Relaxed);
        }
    }

    /// Record a transient 5xx/connect failure and apply exponential backoff cooldown up to 60s.
    pub fn record_transient_failure(&self, base_secs: u64) {
        let prev = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if base_secs == 0 {
            return;
        }
        let shift = prev.min(5);
        let secs = base_secs.saturating_mul(1u64 << shift).min(60);
        self.mark_cooldown(secs);
    }

    pub fn set_quota_exhausted(&self, exhausted: bool) {
        self.quota_exhausted.store(exhausted, Ordering::Relaxed);
    }

    #[inline]
    pub fn mapped_model(&self, model: &str) -> Option<&str> {
        self.model_mapping.get(model).map(String::as_str)
    }
}

const STICKY_SHARDS: usize = 16;
const STICKY_SHARD_CAP: usize = 256;

struct StickyEntry {
    upstream_name: String,
    expires_at_ms: u64,
}

/// Sharded, bounded soft-sticky failover cache with a zero-lock atomic fast path.
struct StickyFailoverCache {
    active_entries: AtomicUsize,
    shards: [RwLock<HashMap<u64, StickyEntry>>; STICKY_SHARDS],
}

impl StickyFailoverCache {
    fn new() -> Self {
        Self {
            active_entries: AtomicUsize::new(0),
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
        }
    }

    #[inline]
    fn shard_idx(hash: u64) -> usize {
        ((hash ^ (hash >> 32)) as usize) & (STICKY_SHARDS - 1)
    }

    fn get(&self, hash: u64, now_ms: u64) -> Option<String> {
        if self.active_entries.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let shard = &self.shards[Self::shard_idx(hash)];
        let name = {
            let guard = shard.read().ok()?;
            let entry = guard.get(&hash)?;
            if now_ms < entry.expires_at_ms {
                return Some(entry.upstream_name.clone());
            }
            entry.upstream_name.clone()
        };
        let _ = name;
        // Expired entry: clean up lazily.
        if let Ok(mut guard) = shard.write()
            && let Some(entry) = guard.get(&hash)
            && now_ms >= entry.expires_at_ms
        {
            guard.remove(&hash);
            self.active_entries.fetch_sub(1, Ordering::Relaxed);
        }
        None
    }

    fn record(&self, hash: u64, upstream_name: &str, ttl_secs: u64, now_ms: u64) {
        if ttl_secs == 0 {
            return;
        }
        let expires_at_ms = now_ms.saturating_add(ttl_secs.saturating_mul(1000));
        let shard = &self.shards[Self::shard_idx(hash)];
        if let Ok(mut guard) = shard.write() {
            if guard.len() >= STICKY_SHARD_CAP && !guard.contains_key(&hash) {
                let before = guard.len();
                guard.retain(|_, v| now_ms < v.expires_at_ms);
                let removed = before.saturating_sub(guard.len());
                if removed > 0 {
                    self.active_entries.fetch_sub(removed, Ordering::Relaxed);
                }
                if guard.len() >= STICKY_SHARD_CAP
                    && let Some(&evict_key) = guard.keys().next()
                {
                    guard.remove(&evict_key);
                    self.active_entries.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let existed = guard
                .insert(
                    hash,
                    StickyEntry {
                        upstream_name: upstream_name.to_string(),
                        expires_at_ms,
                    },
                )
                .is_some();
            if !existed {
                self.active_entries.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn invalidate(&self, hash: u64) {
        if self.active_entries.load(Ordering::Relaxed) == 0 {
            return;
        }
        let shard = &self.shards[Self::shard_idx(hash)];
        if let Ok(mut guard) = shard.write()
            && guard.remove(&hash).is_some()
        {
            self.active_entries.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct ModelPool {
    nodes: Vec<Arc<UpstreamNode>>,
    cursor: AtomicUsize,
}

impl ModelPool {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cursor: AtomicUsize::new(0),
        }
    }

    fn push(&mut self, node: Arc<UpstreamNode>) {
        if !self.nodes.iter().any(|n| n.name == node.name) {
            self.nodes.push(node);
        }
    }

    #[inline]
    fn next_ticket(&self) -> usize {
        self.cursor.fetch_add(1, Ordering::Relaxed)
    }
}

struct RoutingTable {
    exact: HashMap<String, ModelPool>,
    wildcard: ModelPool,
    all_nodes: Vec<Arc<UpstreamNode>>,
    has_model_rules: bool,
    has_model_mapping: bool,
    has_mixed_protocols: bool,
    has_outbound_session_mapping: bool,
}

impl RoutingTable {
    fn build(
        configs: &[UpstreamConfig],
        token_store: Option<Arc<dyn TokenStore>>,
        exhausted_upstreams: &HashSet<String>,
    ) -> Result<Self, GatewayError> {
        let mut exact: HashMap<String, ModelPool> = HashMap::new();
        let mut wildcard = ModelPool::new();
        let mut all_nodes = Vec::with_capacity(configs.len());
        let mut has_model_mapping = false;
        let mut has_mixed_protocols = false;
        let mut has_outbound_session_mapping = false;

        for cfg in configs {
            let node = Arc::new(UpstreamNode::from_config(cfg, token_store.clone())?);
            if exhausted_upstreams.contains(&node.name) {
                node.set_quota_exhausted(true);
            }
            if node.default_protocol != ProtocolFamily::OpenAi || node.endpoints.len() > 1 {
                has_mixed_protocols = true;
            }
            if node.needs_outbound_session_mapping() {
                has_outbound_session_mapping = true;
            }
            all_nodes.push(Arc::clone(&node));
            if !node.model_mapping.is_empty() {
                has_model_mapping = true;
            }
            for model in &cfg.models {
                if model == "*" {
                    wildcard.push(Arc::clone(&node));
                } else {
                    exact
                        .entry(model.clone())
                        .or_insert_with(ModelPool::new)
                        .push(Arc::clone(&node));
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
            has_outbound_session_mapping,
        })
    }
}

pub struct RoutePlan {
    pub candidates: Vec<Arc<UpstreamNode>>,
    pub blocked_by_policy: bool,
    pub primary_hrw_node: Option<String>,
    pub sticky_hit: bool,
}

impl std::fmt::Debug for RoutePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.candidates.iter().map(|n| n.name.as_str()).collect();
        f.debug_struct("RoutePlan")
            .field("candidates", &names)
            .field("blocked_by_policy", &self.blocked_by_policy)
            .field("primary_hrw_node", &self.primary_hrw_node)
            .field("sticky_hit", &self.sticky_hit)
            .finish()
    }
}

/// Lock-free router supporting atomic hot-reload via `ArcSwap`,
/// Filter-Before-Select candidate planning, Weighted HRW / Smooth WRR,
/// and soft-sticky failover caching.
pub struct Router {
    table: ArcSwap<RoutingTable>,
    token_store: Option<Arc<dyn TokenStore>>,
    routing_config: RoutingConfig,
    sticky_cache: StickyFailoverCache,
    exhausted_upstreams: RwLock<HashSet<String>>,
    fallback_cursor: AtomicUsize,
}

impl Router {
    pub fn new(
        configs: &[UpstreamConfig],
        token_store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, GatewayError> {
        Self::with_config(configs, token_store, RoutingConfig::default())
    }

    pub fn with_config(
        configs: &[UpstreamConfig],
        token_store: Option<Arc<dyn TokenStore>>,
        routing_config: RoutingConfig,
    ) -> Result<Self, GatewayError> {
        let exhausted = HashSet::new();
        let table = RoutingTable::build(configs, token_store.clone(), &exhausted)?;
        Ok(Self {
            table: ArcSwap::from_pointee(table),
            token_store,
            routing_config,
            sticky_cache: StickyFailoverCache::new(),
            exhausted_upstreams: RwLock::new(exhausted),
            fallback_cursor: AtomicUsize::new(0),
        })
    }

    pub fn reload(&self, configs: &[UpstreamConfig]) -> Result<(), GatewayError> {
        let exhausted = self
            .exhausted_upstreams
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        let next = RoutingTable::build(configs, self.token_store.clone(), &exhausted)?;
        self.table.store(Arc::new(next));
        Ok(())
    }

    pub fn routing_config(&self) -> &RoutingConfig {
        &self.routing_config
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
        table.has_model_rules
            || table.has_model_mapping
            || table.has_mixed_protocols
            || table.has_outbound_session_mapping
    }

    /// Read-only visibility check for `/v1/models` (never advances any round-robin cursor).
    pub fn has_accessible_node(&self, model: &str, policy: Option<&AccessPolicy>) -> bool {
        let table = self.table.load();
        let exact_ok = table.exact.get(model).is_some_and(|pool| {
            pool.nodes
                .iter()
                .any(|n| node_allowed_by_policy(n, policy))
        });
        if exact_ok {
            return true;
        }
        table
            .wildcard
            .nodes
            .iter()
            .any(|n| node_allowed_by_policy(n, policy))
    }

    /// Zero-overhead shortcut: skip affinity extraction when at most 1 accessible candidate exists,
    /// it has at most 1 credential slot, and no accessible candidate needs outbound session header mapping.
    pub fn needs_affinity_extraction(
        &self,
        model: Option<&str>,
        policy: Option<&AccessPolicy>,
    ) -> bool {
        if !self.routing_config.affinity_enabled {
            return false;
        }
        let table = self.table.load();
        let mut seen: Vec<&str> = Vec::new();
        let mut count = 0usize;
        let mut max_keys = 0usize;

        if let Some(m) = model
            && let Some(pool) = table.exact.get(m)
        {
            for n in &pool.nodes {
                if node_allowed_by_policy(n, policy) {
                    if n.needs_outbound_session_mapping() {
                        return true;
                    }
                    seen.push(&n.name);
                    count += 1;
                    max_keys = max_keys.max(n.key_count());
                    if count > 1 || max_keys > 1 {
                        return true;
                    }
                }
            }
        }
        for n in &table.wildcard.nodes {
            if !seen.contains(&n.name.as_str()) && node_allowed_by_policy(n, policy) {
                if n.needs_outbound_session_mapping() {
                    return true;
                }
                count += 1;
                max_keys = max_keys.max(n.key_count());
                if count > 1 || max_keys > 1 {
                    return true;
                }
            }
        }
        false
    }

    pub fn set_quota_exhausted(&self, upstream_name: &str, exhausted: bool) {
        if let Ok(mut guard) = self.exhausted_upstreams.write() {
            if exhausted {
                guard.insert(upstream_name.to_string());
            } else {
                guard.remove(upstream_name);
            }
        }
        let table = self.table.load();
        for node in &table.all_nodes {
            if node.name == upstream_name {
                node.set_quota_exhausted(exhausted);
            }
        }
    }

    pub fn record_failover_success(&self, affinity_hash: u64, upstream_name: &str) {
        self.sticky_cache.record(
            affinity_hash,
            upstream_name,
            self.routing_config.sticky_failover_ttl_secs,
            now_epoch_ms(),
        );
    }

    /// Plan ordered upstream candidates using Filter-Before-Select:
    /// 1. Merge exact pool + deduplicated wildcard fallback pool.
    /// 2. Apply `AccessPolicy` before selection (exact-denied falls back to wildcard).
    /// 3. Filter out nodes whose protocol cannot handle `ingress_proto`.
    /// 4. Bucket into 8 priority tiers (Healthy/Degraded × Exact/Wildcard × Native/Translate).
    /// 5. Order within each bucket via Weighted HRW (with affinity) or Smooth WRR (without affinity).
    /// 6. Apply Soft-Sticky failover override if pinned backup is still healthy.
    pub fn plan_route(
        &self,
        model: Option<&str>,
        ingress_proto: Option<ProtocolFamily>,
        policy: Option<&AccessPolicy>,
        affinity_hash: Option<u64>,
    ) -> RoutePlan {
        let table = self.table.load();
        let exact_pool = model.and_then(|m| table.exact.get(m));

        let exact_raw = exact_pool.map(|p| p.nodes.as_slice()).unwrap_or(&[]);
        let wildcard_raw = table.wildcard.nodes.as_slice();

        let mut exact_names: HashSet<&str> = HashSet::with_capacity(exact_raw.len());
        for n in exact_raw {
            exact_names.insert(n.name.as_str());
        }

        let had_any = !exact_raw.is_empty() || !wildcard_raw.is_empty();
        if !had_any {
            return RoutePlan {
                candidates: Vec::new(),
                blocked_by_policy: false,
                primary_hrw_node: None,
                sticky_hit: false,
            };
        }

        let mut exact_allowed: Vec<Arc<UpstreamNode>> = Vec::with_capacity(exact_raw.len());
        for n in exact_raw {
            if node_allowed_by_policy(n, policy) {
                exact_allowed.push(Arc::clone(n));
            }
        }

        let mut wildcard_allowed: Vec<Arc<UpstreamNode>> = Vec::with_capacity(wildcard_raw.len());
        for n in wildcard_raw {
            if !exact_names.contains(n.name.as_str()) && node_allowed_by_policy(n, policy) {
                wildcard_allowed.push(Arc::clone(n));
            }
        }

        if exact_allowed.is_empty() && wildcard_allowed.is_empty() {
            return RoutePlan {
                candidates: Vec::new(),
                blocked_by_policy: true,
                primary_hrw_node: None,
                sticky_hit: false,
            };
        }

        exact_allowed.retain(|n| n.can_handle_protocol(ingress_proto));
        wildcard_allowed.retain(|n| n.can_handle_protocol(ingress_proto));

        let now = now_epoch_ms();
        let quota_aware = self.routing_config.quota_aware;

        let mut h_exact_native = Vec::new();
        let mut h_exact_trans = Vec::new();
        let mut d_exact_native = Vec::new();
        let mut d_exact_trans = Vec::new();

        for n in exact_allowed {
            let native = ingress_proto.is_none_or(|p| n.supports_protocol(p));
            let degraded = n.is_degraded(now, quota_aware);
            match (degraded, native) {
                (false, true) => h_exact_native.push(n),
                (false, false) => h_exact_trans.push(n),
                (true, true) => d_exact_native.push(n),
                (true, false) => d_exact_trans.push(n),
            }
        }

        let mut h_wild_native = Vec::new();
        let mut h_wild_trans = Vec::new();
        let mut d_wild_native = Vec::new();
        let mut d_wild_trans = Vec::new();

        for n in wildcard_allowed {
            let native = ingress_proto.is_none_or(|p| n.supports_protocol(p));
            let degraded = n.is_degraded(now, quota_aware);
            match (degraded, native) {
                (false, true) => h_wild_native.push(n),
                (false, false) => h_wild_trans.push(n),
                (true, true) => d_wild_native.push(n),
                (true, false) => d_wild_trans.push(n),
            }
        }

        let ticket = if affinity_hash.is_none() {
            Some(
                exact_pool
                    .map(ModelPool::next_ticket)
                    .unwrap_or_else(|| self.fallback_cursor.fetch_add(1, Ordering::Relaxed)),
            )
        } else {
            None
        };

        let mut buckets = [
            h_exact_native,
            h_exact_trans,
            h_wild_native,
            h_wild_trans,
            d_exact_native,
            d_exact_trans,
            d_wild_native,
            d_wild_trans,
        ];

        let mut candidates = Vec::new();
        for bucket in &mut buckets {
            if bucket.len() > 1 {
                if let Some(h) = affinity_hash {
                    sort_weighted_hrw(bucket, h);
                } else if let Some(t) = ticket {
                    order_smooth_weighted(bucket, t);
                }
            }
            candidates.append(bucket);
        }

        let primary_hrw_node = affinity_hash.and_then(|_| candidates.first().map(|n| n.name.clone()));
        let mut sticky_hit = false;

        if let Some(h) = affinity_hash
            && let Some(sticky_name) = self.sticky_cache.get(h, now)
        {
            if let Some(idx) = candidates.iter().position(|n| n.name == sticky_name) {
                if !candidates[idx].is_degraded(now, quota_aware) {
                    if idx > 0 {
                        let node = candidates.remove(idx);
                        candidates.insert(0, node);
                    }
                    sticky_hit = true;
                } else {
                    self.sticky_cache.invalidate(h);
                }
            } else {
                self.sticky_cache.invalidate(h);
            }
        }

        RoutePlan {
            candidates,
            blocked_by_policy: false,
            primary_hrw_node,
            sticky_hit,
        }
    }

    /// Backward-compatible wrapper selecting ordered candidates without policy or affinity.
    pub fn select_candidates(
        &self,
        model: Option<&str>,
        ingress_proto: Option<ProtocolFamily>,
    ) -> Vec<Arc<UpstreamNode>> {
        self.plan_route(model, ingress_proto, None, None).candidates
    }
}

#[inline]
fn node_allowed_by_policy(node: &UpstreamNode, policy: Option<&AccessPolicy>) -> bool {
    match policy {
        Some(pol) => pol.can_access_node(node),
        None => node.owner_user_id.is_none(),
    }
}

/// Weighted Rendezvous Hashing (HRW):
/// `score_i = -ln(u_i) / weight_i`, sorted ascending.
fn sort_weighted_hrw(bucket: &mut [Arc<UpstreamNode>], affinity_hash: u64) {
    bucket.sort_by(|a, b| {
        let sa = hrw_score(affinity_hash, a.name_hash, a.weight);
        let sb = hrw_score(affinity_hash, b.name_hash, b.weight);
        sa.total_cmp(&sb).then_with(|| a.name.cmp(&b.name))
    });
}

#[inline]
fn hrw_score(affinity_hash: u64, node_name_hash: u64, weight: u32) -> f64 {
    let mixed = mix64(affinity_hash ^ node_name_hash);
    // Map to open interval (0, 1) using 53-bit mantissa precision.
    let u = ((mixed >> 11) as f64 + 0.5) / ((1u64 << 53) as f64);
    -u.ln() / (weight.max(1) as f64)
}

/// Low-discrepancy Golden-Ratio (Weyl) weighted selection over an arbitrary filtered bucket:
/// produces smooth interleaving with exact weight proportionality regardless of filtering.
fn order_smooth_weighted(bucket: &mut [Arc<UpstreamNode>], ticket: usize) {
    let total_weight: u64 = bucket.iter().map(|n| n.weight.max(1) as u64).sum();
    if total_weight == 0 || bucket.len() <= 1 {
        return;
    }
    const PHI_FRAC: f64 = 0.618_033_988_749_894_9;
    let frac = ((ticket as f64) * PHI_FRAC).fract();
    let target = ((frac * (total_weight as f64)) as u64).min(total_weight - 1);

    let mut acc = 0u64;
    let mut primary_idx = 0usize;
    for (idx, n) in bucket.iter().enumerate() {
        acc += n.weight.max(1) as u64;
        if target < acc {
            primary_idx = idx;
            break;
        }
    }
    if primary_idx > 0 {
        bucket.rotate_left(primary_idx);
    }
}

fn resolve_effective_cache_mode(
    cfg: &UpstreamConfig,
    endpoints: &HashMap<ProtocolFamily, ParsedEndpoint>,
    is_codex_oauth: bool,
) -> PromptCacheMode {
    if cfg.prompt_cache_mode != PromptCacheMode::Auto {
        return cfg.prompt_cache_mode;
    }

    for ep in endpoints.values() {
        let host = ep.base_authority.host().to_ascii_lowercase();
        if host == "api.x.ai" || host.ends_with(".x.ai") {
            return PromptCacheMode::XaiGrok;
        }
        if host == "openrouter.ai" || host.ends_with(".openrouter.ai") {
            return PromptCacheMode::OpenRouter;
        }
        if host == "opencode.ai" || host.ends_with(".opencode.ai") {
            return PromptCacheMode::OpenCode;
        }
        if host == "api.deepseek.com"
            || host.ends_with(".deepseek.com")
            || host.ends_with(".volces.com")
            || host.ends_with(".volcengine.com")
        {
            return PromptCacheMode::StripOpenAiCacheFields;
        }
        if host == "api.openai.com"
            || host.ends_with(".openai.azure.com")
            || host == "chatgpt.com"
        {
            return PromptCacheMode::OpenAi;
        }
    }

    if is_codex_oauth
        || cfg.primary_protocol() == ProtocolFamily::OpenAiResponses
        || endpoints.contains_key(&ProtocolFamily::OpenAiResponses)
    {
        return PromptCacheMode::OpenAi;
    }

    PromptCacheMode::Passthrough
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
        make_node_with(name, endpoints, vec!["ark-code-latest"], 1, None)
    }

    fn make_node_with(
        name: &str,
        endpoints: Vec<(ProtocolFamily, &str)>,
        models: Vec<&str>,
        weight: u32,
        owner_user_id: Option<i64>,
    ) -> UpstreamConfig {
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
            models: models.into_iter().map(String::from).collect(),
            model_mapping: HashMap::new(),
            extra_headers: HashMap::new(),
            protocol_headers: HashMap::new(),
            weight,
            default_cooldown_secs: 30,
            max_retries: 0,
            owner_user_id,
            proxy: None,
            quota: None,
            session_header_out: None,
            strip_other_session_headers: false,
            prompt_cache_mode: PromptCacheMode::Auto,
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

    #[test]
    fn weighted_hrw_and_smooth_wrr_eliminate_protocol_tier_skew() {
        // Node A (OpenAI only, weight=10), Node B (Anthropic, weight=1), Node C (Anthropic, weight=1).
        // Previously, Anthropic requests skewed ~91.7% to B because A fell into Tier 2.
        let a = make_node_with(
            "node-a",
            vec![(ProtocolFamily::OpenAi, "https://a.example.com/v1")],
            vec!["claude-sonnet-4"],
            10,
            None,
        );
        let b = make_node_with(
            "node-b",
            vec![(ProtocolFamily::Anthropic, "https://b.example.com/v1")],
            vec!["claude-sonnet-4"],
            1,
            None,
        );
        let c = make_node_with(
            "node-c",
            vec![(ProtocolFamily::Anthropic, "https://c.example.com/v1")],
            vec!["claude-sonnet-4"],
            1,
            None,
        );

        let router = Router::new(&[a, b, c], None).unwrap();

        // 1. Weighted HRW across 1000 distinct sessions -> roughly 50/50 between B and C
        let mut b_hrw = 0usize;
        let mut c_hrw = 0usize;
        for i in 0..1000u64 {
            let h = mix64(0xdead_beef_u64.wrapping_add(i));
            let plan = router.plan_route(
                Some("claude-sonnet-4"),
                Some(ProtocolFamily::Anthropic),
                None,
                Some(h),
            );
            match plan.candidates[0].name.as_str() {
                "node-b" => b_hrw += 1,
                "node-c" => c_hrw += 1,
                other => panic!("unexpected primary node: {other}"),
            }
        }
        assert!(b_hrw > 400 && c_hrw > 400, "HRW skewed: b={b_hrw}, c={c_hrw}");

        // 2. Smooth WRR without affinity -> exact 50/50 split and zero burst
        let mut b_rr = 0usize;
        let mut c_rr = 0usize;
        for _ in 0..100 {
            let plan = router.plan_route(
                Some("claude-sonnet-4"),
                Some(ProtocolFamily::Anthropic),
                None,
                None,
            );
            match plan.candidates[0].name.as_str() {
                "node-b" => b_rr += 1,
                "node-c" => c_rr += 1,
                other => panic!("unexpected primary node: {other}"),
            }
        }
        assert!(b_rr >= 48 && c_rr >= 48, "Smooth WRR skewed: b={b_rr}, c={c_rr}");
    }

    #[test]
    fn exact_denied_by_policy_falls_back_to_global_wildcard() {
        let priv_user1 = make_node_with(
            "priv-u1",
            vec![(ProtocolFamily::OpenAi, "https://u1.example.com/v1")],
            vec!["gpt-4o"],
            1,
            Some(1),
        );
        let global_wild = make_node_with(
            "global-wild",
            vec![(ProtocolFamily::OpenAi, "https://wild.example.com/v1")],
            vec!["*"],
            1,
            None,
        );
        let router = Router::new(&[priv_user1, global_wild], None).unwrap();

        let user2_pol = AccessPolicy::new(Some(2), None, None);
        let plan = router.plan_route(
            Some("gpt-4o"),
            Some(ProtocolFamily::OpenAi),
            Some(&user2_pol),
            None,
        );
        assert!(!plan.blocked_by_policy);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].name, "global-wild");
        assert!(router.has_accessible_node("gpt-4o", Some(&user2_pol)));

        // When user2 is also disallowed from global-wild, blocked_by_policy = true
        let restricted = AccessPolicy::new(Some(2), Some(vec!["other".into()]), None);
        let denied = router.plan_route(
            Some("gpt-4o"),
            Some(ProtocolFamily::OpenAi),
            Some(&restricted),
            None,
        );
        assert!(denied.blocked_by_policy);
        assert!(denied.candidates.is_empty());
    }

    #[test]
    fn filters_unsupported_cross_protocol_candidates() {
        // Anthropic -> Gemini is unsupported; Anthropic -> OpenAI is supported.
        let gemini_up = make_node_with(
            "gemini-only",
            vec![(ProtocolFamily::Gemini, "https://g.example.com/v1beta")],
            vec!["shared-model"],
            1,
            None,
        );
        let openai_up = make_node_with(
            "openai-ok",
            vec![(ProtocolFamily::OpenAi, "https://o.example.com/v1")],
            vec!["shared-model"],
            1,
            None,
        );
        let router = Router::new(&[gemini_up, openai_up], None).unwrap();
        let plan = router.plan_route(
            Some("shared-model"),
            Some(ProtocolFamily::Anthropic),
            None,
            None,
        );
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].name, "openai-ok");
    }

    #[test]
    fn soft_sticky_failover_prevents_flapping_after_primary_recovers() {
        let up1 = make_node_with(
            "up-1",
            vec![(ProtocolFamily::OpenAi, "https://1.example.com/v1")],
            vec!["gpt-4o"],
            1,
            None,
        );
        let up2 = make_node_with(
            "up-2",
            vec![(ProtocolFamily::OpenAi, "https://2.example.com/v1")],
            vec!["gpt-4o"],
            1,
            None,
        );
        let router = Router::new(&[up1, up2], None).unwrap();

        let aff_hash = 0x55aa_1122_3344_5566_u64;
        let initial = router.plan_route(Some("gpt-4o"), Some(ProtocolFamily::OpenAi), None, Some(aff_hash));
        let primary = initial.candidates[0].clone();
        let backup = initial.candidates[1].clone();

        // Simulate primary cooldown -> failover to backup -> record sticky
        primary.mark_cooldown(30);
        let during_cd = router.plan_route(Some("gpt-4o"), Some(ProtocolFamily::OpenAi), None, Some(aff_hash));
        assert_eq!(during_cd.candidates[0].name, backup.name);
        router.record_failover_success(aff_hash, &backup.name);

        // Recover primary -> sticky cache keeps session on healthy backup!
        primary.cooldown_until_ms.store(0, Ordering::Relaxed);
        let after_recover = router.plan_route(Some("gpt-4o"), Some(ProtocolFamily::OpenAi), None, Some(aff_hash));
        assert_eq!(after_recover.candidates[0].name, backup.name);
        assert!(after_recover.sticky_hit);
    }

    #[test]
    fn has_accessible_node_does_not_advance_cursor_and_quota_persists_across_reload() {
        let up1 = make_node_with(
            "up-1",
            vec![(ProtocolFamily::OpenAi, "https://1.example.com/v1")],
            vec!["gpt-4o"],
            1,
            None,
        );
        let up2 = make_node_with(
            "up-2",
            vec![(ProtocolFamily::OpenAi, "https://2.example.com/v1")],
            vec!["gpt-4o"],
            1,
            None,
        );
        let router = Router::new(&[up1.clone(), up2.clone()], None).unwrap();

        let first = router.plan_route(Some("gpt-4o"), Some(ProtocolFamily::OpenAi), None, None).candidates[0].name.clone();
        for _ in 0..10 {
            assert!(router.has_accessible_node("gpt-4o", None));
        }
        let second = router.plan_route(Some("gpt-4o"), Some(ProtocolFamily::OpenAi), None, None).candidates[0].name.clone();
        assert_ne!(first, second);

        // Quota exhaustion demotes up-1 and survives reload
        router.set_quota_exhausted("up-1", true);
        router.reload(&[up1, up2]).unwrap();
        for _ in 0..5 {
            let picked = router.plan_route(Some("gpt-4o"), Some(ProtocolFamily::OpenAi), None, None).candidates[0].name.clone();
            assert_eq!(picked, "up-2");
        }

        // Transient failure exponential backoff and success reset
        let node = router.all_nodes().into_iter().find(|n| n.name == "up-2").unwrap();
        node.record_transient_failure(3);
        assert!(node.is_cooling_down(now_epoch_ms()));
        node.record_success();
        assert_eq!(node.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn auto_detects_provider_prompt_cache_mode_and_respects_overrides() {
        let grok = make_node("grok", vec![(ProtocolFamily::OpenAi, "https://api.x.ai/v1")]);
        let grok_node = UpstreamNode::from_config(&grok, None).unwrap();
        assert_eq!(grok_node.effective_cache_mode, PromptCacheMode::XaiGrok);
        assert_eq!(
            grok_node.resolve_outbound_session_header(ProtocolFamily::OpenAi),
            Some(HeaderName::from_static("x-grok-conv-id"))
        );

        let openrouter = make_node(
            "or",
            vec![(ProtocolFamily::OpenAi, "https://openrouter.ai/api/v1")],
        );
        let or_node = UpstreamNode::from_config(&openrouter, None).unwrap();
        assert_eq!(or_node.effective_cache_mode, PromptCacheMode::OpenRouter);
        assert_eq!(
            or_node.resolve_outbound_session_header(ProtocolFamily::OpenAi),
            Some(HeaderName::from_static("x-session-id"))
        );

        let deepseek = make_node(
            "ds",
            vec![(ProtocolFamily::OpenAi, "https://api.deepseek.com/v1")],
        );
        let ds_node = UpstreamNode::from_config(&deepseek, None).unwrap();
        assert_eq!(
            ds_node.effective_cache_mode,
            PromptCacheMode::StripOpenAiCacheFields
        );
        assert!(ds_node.strip_openai_cache_fields);

        let ark = make_node(
            "ark",
            vec![(
                ProtocolFamily::OpenAi,
                "https://ark.cn-beijing.volces.com/api/v3",
            )],
        );
        let ark_node = UpstreamNode::from_config(&ark, None).unwrap();
        assert_eq!(
            ark_node.effective_cache_mode,
            PromptCacheMode::StripOpenAiCacheFields
        );

        // Explicit Passthrough disables auto OpenAiResponses `session_id` injection
        let mut custom_resp = make_node(
            "resp-pass",
            vec![(ProtocolFamily::OpenAiResponses, "https://custom.example.com/v1")],
        );
        custom_resp.prompt_cache_mode = PromptCacheMode::Passthrough;
        let pass_node = UpstreamNode::from_config(&custom_resp, None).unwrap();
        assert_eq!(
            pass_node.resolve_outbound_session_header(ProtocolFamily::OpenAiResponses),
            None
        );

        // Explicit `session_header_out` overrides any built-in cache mode
        let mut custom_hdr = make_node("grok-custom", vec![(ProtocolFamily::OpenAi, "https://api.x.ai/v1")]);
        custom_hdr.session_header_out = Some("x-custom-conv".into());
        let custom_node = UpstreamNode::from_config(&custom_hdr, None).unwrap();
        assert_eq!(
            custom_node.resolve_outbound_session_header(ProtocolFamily::OpenAi),
            Some(HeaderName::from_static("x-custom-conv"))
        );

        let opencode = make_node(
            "opencode-go",
            vec![
                (ProtocolFamily::OpenAi, "https://opencode.ai/zen/go/v1/chat/completions"),
                (ProtocolFamily::OpenAiResponses, "https://opencode.ai/zen/go/v1/responses"),
                (ProtocolFamily::Anthropic, "https://opencode.ai/zen/go/v1/messages"),
            ],
        );
        let oc_node = UpstreamNode::from_config(&opencode, None).unwrap();
        assert_eq!(oc_node.effective_cache_mode, PromptCacheMode::OpenCode);
        for proto in [
            ProtocolFamily::OpenAi,
            ProtocolFamily::OpenAiResponses,
            ProtocolFamily::Anthropic,
        ] {
            assert_eq!(
                oc_node.resolve_outbound_session_header(proto),
                Some(HeaderName::from_static("x-opencode-session"))
            );
        }
    }
}
