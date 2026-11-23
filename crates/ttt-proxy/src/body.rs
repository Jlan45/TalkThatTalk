use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::StatusCode;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use pin_project_lite::pin_project;
use tokio::sync::mpsc;
use ttt_core::{RequestId, TapEvent};
use ttt_protocol::{SseTranslator, TranslatedStreamBody};

pin_project! {
    /// Zero-copy streaming body wrapper that tees O(1) `Bytes::clone()` slices
    /// into a bounded side-channel without blocking the hot forwarding path.
    pub struct TapBody<B> {
        #[pin]
        inner: B,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        is_stream: bool,
        started_at: Instant,
        ttft_ms: Option<u64>,
        total_bytes: u64,
        finished: bool,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
    }

    impl<B> PinnedDrop for TapBody<B> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if !*this.finished {
                *this.finished = true;
                if let Some(tx) = this.tap_tx.take() {
                    let _ = tx.try_send(TapEvent::ResponseEnd {
                        req_id: *this.req_id,
                        lifetime: this.lifetime.take(),
                        status: *this.status,
                        is_stream: *this.is_stream,
                        total_bytes: *this.total_bytes,
                        ttft_ms: *this.ttft_ms,
                        duration_ms: this.started_at.elapsed().as_millis() as u64,
                    });
                }
            }
        }
    }
}

impl<B> TapBody<B> {
    pub fn new(
        inner: B,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        is_stream: bool,
        started_at: Instant,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
    ) -> Self {
        Self {
            inner,
            req_id,
            lifetime,
            status,
            is_stream,
            started_at,
            ttft_ms: None,
            total_bytes: 0,
            finished: false,
            tap_tx,
        }
    }
}

impl<B> Body for TapBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && !data.is_empty()
                {
                    *this.total_bytes += data.len() as u64;
                    if this.ttft_ms.is_none() {
                        let ttft = this.started_at.elapsed().as_millis() as u64;
                        *this.ttft_ms = Some(ttft);
                        if let Some(tx) = this.tap_tx.as_ref() {
                            let _ = tx.try_send(TapEvent::ResponseFirstByte {
                                req_id: *this.req_id,
                                status: *this.status,
                                is_stream: *this.is_stream,
                                ttft_ms: ttft,
                            });
                        }
                    }
                    if let Some(tx) = this.tap_tx.as_ref() {
                        // O(1) atomic ref-count increment, zero payload copy.
                        let _ = tx.try_send(TapEvent::ResponseChunk {
                            req_id: *this.req_id,
                            data: data.clone(),
                        });
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                if !*this.finished {
                    *this.finished = true;
                    if let Some(tx) = this.tap_tx.take() {
                        let _ = tx.try_send(TapEvent::ResponseEnd {
                            req_id: *this.req_id,
                            lifetime: this.lifetime.take(),
                            status: *this.status,
                            is_stream: *this.is_stream,
                            total_bytes: *this.total_bytes,
                            ttft_ms: *this.ttft_ms,
                            duration_ms: this.started_at.elapsed().as_millis() as u64,
                        });
                    }
                }
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if !*this.finished {
                    *this.finished = true;
                    if let Some(tx) = this.tap_tx.take() {
                        let _ = tx.try_send(TapEvent::ResponseEnd {
                            req_id: *this.req_id,
                            lifetime: this.lifetime.take(),
                            status: *this.status,
                            is_stream: *this.is_stream,
                            total_bytes: *this.total_bytes,
                            ttft_ms: *this.ttft_ms,
                            duration_ms: this.started_at.elapsed().as_millis() as u64,
                        });
                    }
                }
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Zero-copy 3-segment body used when rewriting a single field (e.g., `"model"`)
/// inside a JSON payload without re-serializing or copying the rest of the body.
#[derive(Debug, Clone)]
pub struct SegmentedBody {
    segments: [Bytes; 3],
    idx: usize,
    total_len: u64,
}

impl SegmentedBody {
    pub fn from_replacement(original: &Bytes, start: usize, end: usize, replacement: Bytes) -> Self {
        let prefix = original.slice(..start);
        let suffix = original.slice(end..);
        let total_len = (prefix.len() + replacement.len() + suffix.len()) as u64;
        Self {
            segments: [prefix, replacement, suffix],
            idx: 0,
            total_len,
        }
    }

    pub fn exact_len(&self) -> u64 {
        self.total_len
    }
}

impl Body for SegmentedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        while self.idx < self.segments.len() {
            let idx = self.idx;
            self.idx += 1;
            let seg = std::mem::take(&mut self.segments[idx]);
            if !seg.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(seg))));
            }
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.idx >= self.segments.len()
    }

    fn size_hint(&self) -> SizeHint {
        let remaining: u64 = self.segments[self.idx..]
            .iter()
            .map(|b| b.len() as u64)
            .sum();
        SizeHint::with_exact(remaining)
    }
}

pin_project! {
    /// Unified zero-heap-allocation body enum used across both upstream requests
    /// and downstream responses.
    #[project = ProxyBodyProj]
    pub enum ProxyBody {
        Empty { #[pin] inner: Empty<Bytes> },
        Full { #[pin] inner: Full<Bytes> },
        Incoming { #[pin] inner: Incoming },
        Tap { #[pin] inner: TapBody<Incoming> },
        Translated { #[pin] inner: TranslatedStreamBody<TapBody<Incoming>> },
        Segmented { #[pin] inner: SegmentedBody },
    }
}

impl ProxyBody {
    pub fn empty() -> Self {
        Self::Empty {
            inner: Empty::new(),
        }
    }

    pub fn full(bytes: Bytes) -> Self {
        Self::Full {
            inner: Full::new(bytes),
        }
    }

    pub fn incoming(incoming: Incoming) -> Self {
        Self::Incoming { inner: incoming }
    }

    pub fn tap(
        incoming: Incoming,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        is_stream: bool,
        started_at: Instant,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
    ) -> Self {
        Self::Tap {
            inner: TapBody::new(incoming, req_id, lifetime, status, is_stream, started_at, tap_tx),
        }
    }

    pub fn translated(
        incoming: Incoming,
        translator: SseTranslator,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        started_at: Instant,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
    ) -> Self {
        let tapped = TapBody::new(incoming, req_id, lifetime, status, true, started_at, tap_tx);
        Self::Translated {
            inner: TranslatedStreamBody::new(tapped, translator),
        }
    }

    pub fn segmented(seg: SegmentedBody) -> Self {
        Self::Segmented { inner: seg }
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            ProxyBodyProj::Empty { inner } => inner.poll_frame(cx).map_err(|never| match never {}),
            ProxyBodyProj::Full { inner } => inner.poll_frame(cx).map_err(|never| match never {}),
            ProxyBodyProj::Incoming { inner } => inner.poll_frame(cx),
            ProxyBodyProj::Tap { inner } => inner.poll_frame(cx),
            ProxyBodyProj::Translated { inner } => inner.poll_frame(cx),
            ProxyBodyProj::Segmented { inner } => inner.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty { inner } => inner.is_end_stream(),
            Self::Full { inner } => inner.is_end_stream(),
            Self::Incoming { inner } => inner.is_end_stream(),
            Self::Tap { inner } => inner.is_end_stream(),
            Self::Translated { inner } => inner.is_end_stream(),
            Self::Segmented { inner } => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty { inner } => inner.size_hint(),
            Self::Full { inner } => inner.size_hint(),
            Self::Incoming { inner } => inner.size_hint(),
            Self::Tap { inner } => inner.size_hint(),
            Self::Translated { inner } => inner.size_hint(),
            Self::Segmented { inner } => inner.size_hint(),
        }
    }
}
