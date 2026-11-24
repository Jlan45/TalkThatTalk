use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use ttt_core::{GatewayError, RequestId, StreamFailure};
use ttt_proxy::TokenUsage;

const MAX_RECENT_LOGS: usize = 100;
const MAX_ACTIVE_REQUESTS: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct RequestLogEntry {
    pub req_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub timestamp_secs: u64,
    pub upstream: String,
    pub model: Option<String>,
    pub path: String,
    pub status: u16,
    pub is_stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_failure: Option<StreamFailure>,
    pub ttft_ms: u64,
    pub ttft_measured: bool,
    pub duration_ms: u64,
    pub total_bytes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpstreamStats {
    pub requests: u64,
    pub errors: u64,
    pub input_tokens: u64,
    pub total_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cache_hit_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatsSnapshot {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub success_requests: u64,
    pub error_requests: u64,
    pub avg_ttft_ms: u64,
    pub ttft_sample_count: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_write_tokens: u64,
    pub cache_hit_rate: f64,
    pub cache_hit_requests: u64,
    pub cache_request_hit_rate: f64,
    pub by_upstream: HashMap<String, UpstreamStats>,
    pub by_model: HashMap<String, u64>,
    pub recent_requests: Vec<RequestLogEntry>,
}

#[derive(Default, Serialize)]
pub struct ActiveRequestsSnapshot {
    total: usize,
    requests: Vec<ActiveRequest>,
}

#[derive(Serialize)]
struct ActiveRequest {
    req_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    upstream: String,
    model: Option<String>,
    path: String,
    elapsed_ms: u64,
    is_stream: Option<bool>,
}

struct PendingMeta {
    lifetime: Weak<Instant>,
    user_id: Option<i64>,
    username: Option<String>,
    upstream: String,
    model: Option<String>,
    path: String,
    is_stream: Option<bool>,
}

#[derive(Default)]
struct RequestTotals {
    total_requests: u64,
    success_requests: u64,
    error_requests: u64,
    ttft_sum_ms: u64,
    ttft_count: u64,
    total_input_tokens: u64,
    total_output_tokens: u64,
    total_tokens: u64,
    total_cache_read_tokens: u64,
    total_cache_write_tokens: u64,
    cache_hit_requests: u64,
    usage_requests: u64,
    by_upstream: HashMap<String, UpstreamStats>,
    by_model: HashMap<String, u64>,
}

impl RequestTotals {
    fn record(&mut self, entry: &RequestLogEntry) {
        self.total_requests += 1;
        if (200..400).contains(&entry.status) && entry.stream_failure.is_none() {
            self.success_requests += 1;
        } else {
            self.error_requests += 1;
        }
        if entry.ttft_measured {
            self.ttft_sum_ms += entry.ttft_ms;
            self.ttft_count += 1;
        }
        self.total_input_tokens += entry.input_tokens;
        self.total_output_tokens += entry.output_tokens;
        self.total_tokens += entry.total_tokens;
        self.total_cache_read_tokens += entry.cache_read_tokens;
        self.total_cache_write_tokens += entry.cache_write_tokens;
        self.usage_requests += u64::from(entry.input_tokens > 0);
        self.cache_hit_requests += u64::from(entry.cache_read_tokens > 0);

        let upstream = self.by_upstream.entry(entry.upstream.clone()).or_default();
        upstream.requests += 1;
        upstream.errors += u64::from(entry.status >= 400 || entry.stream_failure.is_some());
        upstream.input_tokens += entry.input_tokens;
        upstream.total_tokens += entry.total_tokens;
        upstream.cache_read_tokens += entry.cache_read_tokens;
        upstream.cache_write_tokens += entry.cache_write_tokens;

        if let Some(model) = &entry.model {
            *self.by_model.entry(model.clone()).or_insert(0) += 1;
        }
    }

    fn snapshot(
        &self,
        uptime_secs: u64,
        recent_requests: Vec<RequestLogEntry>,
    ) -> GatewayStatsSnapshot {
        let mut by_upstream = self.by_upstream.clone();
        for upstream in by_upstream.values_mut() {
            upstream.cache_hit_rate = pct_rate(upstream.cache_read_tokens, upstream.input_tokens);
        }
        GatewayStatsSnapshot {
            uptime_secs,
            total_requests: self.total_requests,
            success_requests: self.success_requests,
            error_requests: self.error_requests,
            avg_ttft_ms: self.ttft_sum_ms.checked_div(self.ttft_count).unwrap_or(0),
            ttft_sample_count: self.ttft_count,
            total_input_tokens: self.total_input_tokens,
            total_output_tokens: self.total_output_tokens,
            total_tokens: self.total_tokens,
            total_cache_read_tokens: self.total_cache_read_tokens,
            total_cache_write_tokens: self.total_cache_write_tokens,
            cache_hit_rate: pct_rate(self.total_cache_read_tokens, self.total_input_tokens),
            cache_hit_requests: self.cache_hit_requests,
            cache_request_hit_rate: pct_rate(self.cache_hit_requests, self.usage_requests),
            by_upstream,
            by_model: self.by_model.clone(),
            recent_requests,
        }
    }
}

struct InnerMetrics {
    started_at_secs: u64,
    totals: RequestTotals,
    pending: HashMap<RequestId, PendingMeta>,
    recent: VecDeque<RequestLogEntry>,
}

/// Off-hot-path metrics & recent request log store fed exclusively by the async Tap worker.
pub struct MetricsStore {
    inner: Mutex<InnerMetrics>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InnerMetrics {
                started_at_secs: now_secs(),
                totals: RequestTotals::default(),
                pending: HashMap::new(),
                recent: VecDeque::with_capacity(MAX_RECENT_LOGS),
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_start(
        &self,
        req_id: RequestId,
        lifetime: Weak<Instant>,
        user_id: Option<i64>,
        username: Option<String>,
        upstream: String,
        model: Option<String>,
        path: String,
    ) {
        if let Ok(mut g) = self.inner.lock() {
            g.pending.insert(
                req_id,
                PendingMeta {
                    lifetime,
                    user_id,
                    username,
                    upstream,
                    model,
                    path,
                    is_stream: None,
                },
            );
        }
    }

    pub fn record_first_byte(&self, req_id: RequestId, is_stream: bool) {
        if let Ok(mut g) = self.inner.lock()
            && let Some(meta) = g.pending.get_mut(&req_id)
        {
            meta.is_stream = Some(is_stream);
        }
    }

    pub fn prune_inactive_requests(&self) -> Vec<RequestId> {
        let mut inactive = Vec::new();
        if let Ok(mut g) = self.inner.lock() {
            g.pending.retain(|req_id, meta| {
                let active = meta.lifetime.strong_count() > 0;
                if !active {
                    inactive.push(*req_id);
                }
                active
            });
        }
        inactive
    }

    pub fn active_requests(&self, owner: Option<i64>) -> ActiveRequestsSnapshot {
        let g = self.inner.lock().expect("metrics mutex poisoned");
        let mut active: Vec<_> = g
            .pending
            .iter()
            .filter(|(_, meta)| owner.is_none() || owner == meta.user_id)
            .filter_map(|(id, meta)| Some((id, meta, *meta.lifetime.upgrade()?)))
            .collect();
        let total = active.len();
        if total > MAX_ACTIVE_REQUESTS {
            active.select_nth_unstable_by_key(MAX_ACTIVE_REQUESTS, |(id, _, _)| Reverse(id.0));
            active.truncate(MAX_ACTIVE_REQUESTS);
        }
        active.sort_unstable_by_key(|(id, _, _)| Reverse(id.0));
        let now = Instant::now();
        let requests = active
            .into_iter()
            .map(|(id, meta, started_at)| ActiveRequest {
                req_id: id.to_string(),
                user_id: meta.user_id,
                username: meta.username.clone(),
                upstream: meta.upstream.clone(),
                model: meta.model.clone(),
                path: meta.path.split('?').next().unwrap_or_default().to_string(),
                elapsed_ms: now.saturating_duration_since(started_at).as_millis() as u64,
                is_stream: meta.is_stream,
            })
            .collect();
        ActiveRequestsSnapshot { total, requests }
    }

    /// Rebuild totals from persisted logs in newest-first order, keeping only recent rows in memory.
    pub(crate) fn restore_logs(
        &self,
        entries: impl Iterator<Item = Result<RequestLogEntry, GatewayError>>,
    ) -> Result<u64, GatewayError> {
        let mut totals = RequestTotals::default();
        let mut recent = VecDeque::with_capacity(MAX_RECENT_LOGS);
        let mut last_request_id = 0;
        for entry in entries {
            let entry = entry?;
            if let Some(id) = entry
                .req_id
                .strip_prefix("req-")
                .and_then(|id| id.parse::<u64>().ok())
            {
                last_request_id = last_request_id.max(id);
            }
            totals.record(&entry);
            if recent.len() < MAX_RECENT_LOGS {
                recent.push_back(entry);
            }
        }

        let mut inner = self.inner.lock().expect("metrics mutex poisoned");
        inner.totals = totals;
        inner.recent = recent;
        Ok(last_request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_end(
        &self,
        req_id: RequestId,
        status: u16,
        is_stream: bool,
        stream_failure: Option<StreamFailure>,
        total_bytes: u64,
        ttft_ms: Option<u64>,
        duration_ms: u64,
        usage: TokenUsage,
    ) -> Option<RequestLogEntry> {
        if let Ok(mut g) = self.inner.lock() {
            let meta = g.pending.remove(&req_id).unwrap_or_else(|| PendingMeta {
                lifetime: Weak::new(),
                user_id: None,
                username: None,
                upstream: "unknown".into(),
                model: None,
                path: "-".into(),
                is_stream: None,
            });

            let entry = RequestLogEntry {
                req_id: req_id.to_string(),
                user_id: meta.user_id,
                username: meta.username,
                timestamp_secs: now_secs(),
                upstream: meta.upstream,
                model: meta.model,
                path: meta.path,
                status,
                is_stream: Some(is_stream),
                stream_failure,
                ttft_ms: ttft_ms.unwrap_or(0),
                ttft_measured: ttft_ms.is_some(),
                duration_ms,
                total_bytes,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                total_tokens: usage.total_tokens,
                cache_read_tokens: usage.cache_read_tokens,
                cache_write_tokens: usage.cache_write_tokens,
            };

            g.totals.record(&entry);
            if g.recent.len() >= MAX_RECENT_LOGS {
                g.recent.pop_back();
            }
            g.recent.push_front(entry.clone());
            return Some(entry);
        }
        None
    }

    pub fn uptime_secs(&self) -> u64 {
        let g = self.inner.lock().expect("metrics mutex poisoned");
        now_secs().saturating_sub(g.started_at_secs)
    }

    /// Build an isolated stats snapshot strictly from a single user's request logs.
    pub fn snapshot_from_entries(&self, entries: Vec<RequestLogEntry>) -> GatewayStatsSnapshot {
        let mut totals = RequestTotals::default();
        for entry in &entries {
            totals.record(entry);
        }
        totals.snapshot(
            self.uptime_secs(),
            entries.into_iter().take(MAX_RECENT_LOGS).collect(),
        )
    }

    pub fn snapshot(&self) -> GatewayStatsSnapshot {
        let g = self.inner.lock().expect("metrics mutex poisoned");
        g.totals.snapshot(
            now_secs().saturating_sub(g.started_at_secs),
            g.recent.iter().cloned().collect(),
        )
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn pct_rate(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        (num as f64 / den as f64 * 100.0).min(100.0)
    }
}

#[inline]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn tracks_incomplete_streams_as_failures_with_the_original_http_status() {
        let store = MetricsStore::new();
        let entry = store
            .record_end(
                RequestId::next(),
                200,
                true,
                Some(StreamFailure::Incomplete),
                210,
                Some(30),
                300,
                TokenUsage::default(),
            )
            .unwrap();
        assert_eq!(entry.status, 200);
        let reloaded = MetricsStore::new();
        reloaded
            .restore_logs(std::iter::once(Ok(entry.clone())))
            .unwrap();
        for snapshot in [
            store.snapshot(),
            store.snapshot_from_entries(vec![entry]),
            reloaded.snapshot(),
        ] {
            assert_eq!(snapshot.total_requests, 1);
            assert_eq!(snapshot.success_requests, 0);
            assert_eq!(snapshot.error_requests, 1);
            assert_eq!(snapshot.by_upstream["unknown"].errors, 1);
        }
    }

    #[test]
    fn ttft_average_uses_only_measured_samples_including_zero() {
        let store = MetricsStore::new();
        let entries: Vec<_> = [Some(0), Some(40), None]
            .into_iter()
            .map(|ttft| {
                store
                    .record_end(
                        RequestId::next(),
                        200,
                        true,
                        None,
                        10,
                        ttft,
                        50,
                        TokenUsage::default(),
                    )
                    .unwrap()
            })
            .collect();
        let reloaded = MetricsStore::new();
        reloaded
            .restore_logs(entries.iter().rev().cloned().map(Ok))
            .unwrap();
        for snapshot in [
            store.snapshot(),
            store.snapshot_from_entries(entries),
            reloaded.snapshot(),
        ] {
            assert_eq!(snapshot.total_requests, 3);
            assert_eq!(snapshot.ttft_sample_count, 2);
            assert_eq!(snapshot.avg_ttft_ms, 20);
        }
    }

    #[test]
    fn active_requests_follow_lifetime_and_owner() {
        let store = MetricsStore::new();
        let lifetime = Arc::new(Instant::now());
        let id = RequestId::next();
        store.record_start(
            id,
            Arc::downgrade(&lifetime),
            Some(1),
            Some("alice".into()),
            "primary".into(),
            Some("model".into()),
            "/v1/messages?private=value".into(),
        );
        assert_eq!(store.active_requests(None).total, 1);
        assert_eq!(store.active_requests(Some(2)).total, 0);
        assert_eq!(store.active_requests(Some(1)).requests[0].is_stream, None);

        store.record_start(
            id,
            Arc::downgrade(&lifetime),
            Some(1),
            Some("alice".into()),
            "backup".into(),
            Some("model".into()),
            "/v1/messages?private=value".into(),
        );
        store.record_first_byte(id, true);
        let active = store.active_requests(Some(1));
        assert_eq!(active.total, 1);
        assert_eq!(active.requests[0].upstream, "backup");
        assert_eq!(active.requests[0].path, "/v1/messages");
        assert_eq!(active.requests[0].is_stream, Some(true));

        drop(lifetime);
        assert_eq!(store.active_requests(None).total, 0);
        assert_eq!(store.prune_inactive_requests(), vec![id]);
        assert!(store.prune_inactive_requests().is_empty());
    }

    #[test]
    fn computes_weighted_and_per_upstream_cache_hit_rates() {
        let store = MetricsStore::new();

        // Request 1 on up-a: 1000 input, 800 cache_read
        let id1 = RequestId::next();
        store.record_start(
            id1,
            Weak::new(),
            Some(1),
            Some("alice".into()),
            "up-a".into(),
            Some("gpt-4o".into()),
            "/v1/chat/completions".into(),
        );
        store.record_end(
            id1,
            200,
            true,
            None,
            128,
            Some(120),
            200,
            TokenUsage {
                input_tokens: 1000,
                output_tokens: 50,
                total_tokens: 1050,
                cache_read_tokens: 800,
                cache_write_tokens: 0,
            },
        );

        // Request 2 on up-b: 3000 input, 0 cache_read, 3000 cache_write
        let id2 = RequestId::next();
        store.record_start(
            id2,
            Weak::new(),
            Some(1),
            Some("alice".into()),
            "up-b".into(),
            Some("claude-sonnet-4".into()),
            "/v1/messages".into(),
        );
        let e2 = store
            .record_end(
                id2,
                200,
                false,
                None,
                128,
                Some(250),
                400,
                TokenUsage {
                    input_tokens: 3000,
                    output_tokens: 100,
                    total_tokens: 3100,
                    cache_read_tokens: 0,
                    cache_write_tokens: 3000,
                },
            )
            .unwrap();

        let snap = store.snapshot();
        assert_eq!(snap.recent_requests[1].user_id, Some(1));
        assert_eq!(snap.recent_requests[1].username.as_deref(), Some("alice"));
        assert_eq!(snap.recent_requests[1].is_stream, Some(true));
        assert_eq!(e2.is_stream, Some(false));
        // Weighted global token hit rate: 800 / 4000 = 20.0%
        assert_eq!(snap.total_input_tokens, 4000);
        assert_eq!(snap.total_cache_read_tokens, 800);
        assert_eq!(snap.total_cache_write_tokens, 3000);
        assert_eq!(snap.cache_hit_rate, 20.0);
        // Request-level hit rate: 1 / 2 = 50.0%
        assert_eq!(snap.cache_hit_requests, 1);
        assert_eq!(snap.cache_request_hit_rate, 50.0);
        assert_eq!(snap.by_upstream["up-a"].cache_hit_rate, 80.0);
        assert_eq!(snap.by_upstream["up-b"].cache_hit_rate, 0.0);

        // User-isolated snapshot matches the same calculation
        let iso = store.snapshot_from_entries(vec![snap.recent_requests[1].clone(), e2]);
        assert_eq!(iso.cache_hit_rate, 20.0);
        assert_eq!(iso.cache_request_hit_rate, 50.0);
    }
}
