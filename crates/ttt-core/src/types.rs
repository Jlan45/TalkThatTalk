use bytes::Bytes;
use http::StatusCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(1);

/// Monotonic lightweight request identifier (avoids UUID allocation on hot path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

impl RequestId {
    #[inline]
    pub fn next() -> Self {
        Self(NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn resume_after(latest: u64) {
        NEXT_REQ_ID.fetch_max(latest.saturating_add(1), Ordering::Relaxed);
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "req-{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamFailure {
    Incomplete,
    UpstreamError,
    ClientDisconnected,
}

impl StreamFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::UpstreamError => "upstream_error",
            Self::ClientDisconnected => "client_disconnected",
        }
    }

    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "incomplete" => Some(Self::Incomplete),
            "upstream_error" => Some(Self::UpstreamError),
            "client_disconnected" => Some(Self::ClientDisconnected),
            _ => None,
        }
    }
}

/// Zero-copy side-channel events emitted from the hot data plane to async workers.
///
/// `ResponseChunk` carries an O(1) `Bytes::clone()` reference-counted slice so
/// billing/telemetry never copies payload bytes or blocks the streaming path.
#[derive(Debug, Clone)]
pub enum TapEvent {
    RequestStart {
        req_id: RequestId,
        lifetime: Weak<Instant>,
        user_id: Option<i64>,
        upstream: String,
        model: Option<String>,
        path: String,
    },
    ResponseFirstByte {
        req_id: RequestId,
        status: StatusCode,
        is_stream: bool,
        ttft_ms: Option<u64>,
    },
    ResponseChunk {
        req_id: RequestId,
        data: Bytes,
    },
    ResponseEnd {
        req_id: RequestId,
        // Keep pending metadata alive while this event is queued.
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        is_stream: bool,
        stream_failure: Option<StreamFailure>,
        total_bytes: u64,
        ttft_ms: Option<u64>,
        duration_ms: u64,
    },
}
