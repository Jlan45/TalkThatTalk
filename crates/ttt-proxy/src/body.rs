use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::StatusCode;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use pin_project_lite::pin_project;
use tokio::sync::mpsc;
use ttt_core::{RequestId, StreamFailure, TapEvent};
use ttt_protocol::{NativeSse, SseTranslator, TranslatedStreamBody};

pub(crate) type UploadTiming = Arc<OnceLock<Instant>>;

pub(crate) fn upstream_ttft_ms(upload: Option<&UploadTiming>) -> Option<u64> {
    let upload = upload?;
    let received_at = Instant::now();
    let sent_at = *upload.get()?;
    Some(received_at.checked_duration_since(sent_at)?.as_millis() as u64)
}

pin_project! {
    pub struct UpstreamBody {
        #[pin]
        inner: ProxyBody,
        timing: Option<UploadTiming>,
        complete: bool,
    }

    impl PinnedDrop for UpstreamBody {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            // Hyper releases the request body after queuing its final frame for transport.
            if *this.complete && let Some(timing) = this.timing.take() {
                let _ = timing.set(Instant::now());
            }
        }
    }
}

impl UpstreamBody {
    pub(crate) fn new(inner: ProxyBody, timing: Option<UploadTiming>) -> Self {
        let complete = timing.is_some() && inner.is_end_stream();
        Self { inner, timing, complete }
    }
}

impl From<ProxyBody> for UpstreamBody {
    fn from(inner: ProxyBody) -> Self {
        Self::new(inner, None)
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let mut inner = this.inner;
        let result = inner.as_mut().poll_frame(cx);
        if this.timing.is_some() {
            match &result {
                Poll::Ready(None) => *this.complete = true,
                Poll::Ready(Some(Ok(frame))) => {
                    *this.complete = frame.is_trailers() || inner.is_end_stream();
                }
                _ => {}
            }
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    /// Forward upstream frames while emitting nonblocking telemetry.
    pub struct TapBody<B: Body> {
        #[pin]
        inner: B,
        state: TapState,
    }

    impl<B: Body> PinnedDrop for TapBody<B> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if this.state.finished {
                return;
            }
            let mut failure = this.state.stream_end_failure();
            if failure == Some(StreamFailure::Incomplete)
                && !this.inner.is_end_stream()
                && this.state.native_sse.as_deref().is_some_and(NativeSse::is_open)
            {
                failure = Some(StreamFailure::ClientDisconnected);
            }
            this.state.finish(failure);
        }
    }
}

struct TapState {
    req_id: RequestId,
    lifetime: Option<Arc<Instant>>,
    status: StatusCode,
    is_stream: bool,
    started_at: Instant,
    upload_timing: Option<UploadTiming>,
    ttft_ms: Option<u64>,
    total_bytes: u64,
    finished: bool,
    tap_tx: Option<mpsc::Sender<TapEvent>>,
    native_sse: Option<Box<NativeSse>>,
}

impl TapState {
    fn observe(&mut self, data: &Bytes) {
        if data.is_empty() {
            return;
        }
        if self.total_bytes == 0 {
            self.ttft_ms = upstream_ttft_ms(self.upload_timing.take().as_ref());
            if let Some(tx) = self.tap_tx.as_ref() {
                let _ = tx.try_send(TapEvent::ResponseFirstByte {
                    req_id: self.req_id,
                    status: self.status,
                    is_stream: self.is_stream,
                    ttft_ms: self.ttft_ms,
                });
            }
        }
        self.total_bytes += data.len() as u64;
        if let Some(tx) = self.tap_tx.as_ref() {
            let _ = tx.try_send(TapEvent::ResponseChunk {
                req_id: self.req_id,
                data: data.clone(),
            });
        }
        if let Some(sse) = self.native_sse.as_mut() {
            sse.push(data);
        }
    }

    fn stream_end_failure(&self) -> Option<StreamFailure> {
        let sse = self.native_sse.as_ref()?;
        if sse.has_error() {
            Some(StreamFailure::UpstreamError)
        } else if sse.is_incomplete() {
            Some(StreamFailure::Incomplete)
        } else {
            None
        }
    }

    fn finish(&mut self, stream_failure: Option<StreamFailure>) {
        self.finished = true;
        if let Some(tx) = self.tap_tx.take() {
            let _ = tx.try_send(TapEvent::ResponseEnd {
                req_id: self.req_id,
                lifetime: self.lifetime.take(),
                status: self.status,
                is_stream: self.is_stream,
                stream_failure,
                total_bytes: self.total_bytes,
                ttft_ms: self.ttft_ms,
                duration_ms: self.started_at.elapsed().as_millis() as u64,
            });
        }
    }
}

impl<B: Body> TapBody<B> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner: B,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        is_stream: bool,
        started_at: Instant,
        upload_timing: Option<UploadTiming>,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
        native_sse: Option<NativeSse>,
    ) -> Self {
        Self {
            inner,
            state: TapState {
                req_id,
                lifetime,
                status,
                is_stream,
                started_at,
                upload_timing,
                ttft_ms: None,
                total_bytes: 0,
                finished: false,
                tap_tx,
                native_sse: native_sse.map(Box::new),
            },
        }
    }
}

impl<B: Body<Data = Bytes>> Body for TapBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let state = this.state;
        if state.finished {
            return Poll::Ready(None);
        }
        let trailers = match this.inner.poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    state.observe(data);
                    return Poll::Ready(Some(Ok(frame)));
                }
                Some(frame)
            }
            Poll::Ready(Some(Err(err))) => {
                state.finish(state.is_stream.then_some(StreamFailure::UpstreamError));
                return Poll::Ready(Some(Err(err)));
            }
            Poll::Ready(None) => None,
        };
        let failure = state.stream_end_failure();
        state.finish(failure);
        if let Some(sse) = state.native_sse.as_deref().filter(|sse| sse.is_open()) {
            return Poll::Ready(Some(Ok(Frame::data(sse.incomplete_event()))));
        }
        Poll::Ready(trailers.map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.state.finished || (self.state.native_sse.is_none() && self.inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        if self.state.native_sse.is_some() {
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tap(
        incoming: Incoming,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        is_stream: bool,
        started_at: Instant,
        upload_timing: Option<UploadTiming>,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
        native_sse: Option<NativeSse>,
    ) -> Self {
        Self::Tap {
            inner: TapBody::new(
                incoming,
                req_id,
                lifetime,
                status,
                is_stream,
                started_at,
                upload_timing,
                tap_tx,
                native_sse,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn translated(
        incoming: Incoming,
        translator: SseTranslator,
        req_id: RequestId,
        lifetime: Option<Arc<Instant>>,
        status: StatusCode,
        started_at: Instant,
        upload_timing: Option<UploadTiming>,
        tap_tx: Option<mpsc::Sender<TapEvent>>,
    ) -> Self {
        let tapped = TapBody::new(
            incoming,
            req_id,
            lifetime,
            status,
            true,
            started_at,
            upload_timing,
            tap_tx,
            None,
        );
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
