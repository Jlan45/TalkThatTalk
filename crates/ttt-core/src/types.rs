use bytes::Bytes;
use http::StatusCode;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(1);

/// Monotonic lightweight request identifier (avoids UUID allocation on hot path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

impl RequestId {
    #[inline]
    pub fn next() -> Self {
        Self(NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "req-{}", self.0)
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
        user_id: Option<i64>,
        upstream: String,
        model: Option<String>,
        path: String,
    },
    ResponseFirstByte {
        req_id: RequestId,
        status: StatusCode,
        ttft_ms: u64,
    },
    ResponseChunk {
        req_id: RequestId,
        data: Bytes,
    },
    ResponseEnd {
        req_id: RequestId,
        status: StatusCode,
        total_bytes: u64,
        ttft_ms: Option<u64>,
        duration_ms: u64,
    },
}
