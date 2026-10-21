//! H3 stream adapters that capture a bounded, bidirectional connection timeline.
//!
//! Captured bytes still flow to the H3 server unchanged. Request handlers keep references into the
//! shared event log so fingerprints and stream summaries do not duplicate decoded frames.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
    task::{Context, Poll},
    time::Instant,
};

use bytes::{Buf, Bytes};
use h3::quic::{
    BidiStream, Connection, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream,
    SendStreamUnframed, StreamErrorIncoming, StreamId, WriteBuf,
};
use pingly::h3::{Frame, HeadersFrame, Http3Parser, SettingsFrame, StreamTypeName};
use serde::{Serialize, Serializer};

use super::{HTTP3_DATA_PREVIEW_BYTES, MAX_REQUEST_STREAMS_PER_CONNECTION};

const HTTP3_CAPTURE_MAX_BYTES: usize = 1024 * 1024;
const HTTP3_CAPTURE_MAX_EVENTS: usize = 512;
const JSON_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;

/// Concurrent event storage shared by every stream on one QUIC connection.
pub(in crate::server) type Http3EventCapture = Arc<boxcar::Vec<Http3StreamEvent>>;

/// Direction of an HTTP/3 event relative to Pingly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(in crate::server) enum Http3EventDirection {
    /// An event observed from the client.
    ClientToServer,

    /// An event produced by Pingly.
    ServerToClient,
}

/// HTTP/3 stream role associated with a captured event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(in crate::server) enum Http3StreamKind {
    /// The critical unidirectional control stream.
    Control,

    /// A server push stream.
    Push,

    /// A QPACK encoder instruction stream.
    QpackEncoder,

    /// A QPACK decoder instruction stream.
    QpackDecoder,

    /// A WebTransport unidirectional stream.
    WebTransport,

    /// A client-initiated bidirectional request stream.
    Request,

    /// A reserved or unsupported unidirectional stream.
    Other,
}

/// Frame or QUIC stream-state transition retained in the connection timeline.
#[derive(Debug, Serialize)]
#[serde(tag = "event_type")]
pub(in crate::server) enum Http3EventData {
    /// A decoded HTTP/3 frame.
    Frame {
        /// Frame fields flattened beside the event metadata.
        #[serde(flatten)]
        frame: Frame,
    },

    /// The sender closed this direction cleanly with QUIC FIN.
    Finished,

    /// The sender abruptly terminated this direction.
    Reset {
        /// HTTP/3 application error code supplied to QUIC.
        error_code: u64,
    },

    /// The receiver requested that its peer stop sending this direction.
    StopSending {
        /// HTTP/3 application error code supplied to QUIC.
        error_code: u64,
    },
}

/// One timestamped HTTP/3 event observed on a decrypted QUIC stream.
#[derive(Debug, Serialize)]
pub(in crate::server) struct Http3StreamEvent {
    /// Microseconds elapsed since HTTP/3 inspection began.
    pub(in crate::server) elapsed_us: u64,

    /// Event direction relative to Pingly.
    pub(in crate::server) direction: Http3EventDirection,

    /// QUIC stream identifier scoped to this connection.
    #[serde(serialize_with = "serialize_stream_id")]
    pub(in crate::server) stream_id: u64,

    /// HTTP/3 role of the QUIC stream.
    pub(in crate::server) stream_kind: Http3StreamKind,

    /// Decoded frame or stream-state transition.
    #[serde(flatten)]
    pub(in crate::server) event: Http3EventData,
}

/// Shared bounds for parsing work and retained events on one connection.
struct Http3CaptureBudget {
    /// Decrypted HTTP/3 bytes admitted for inspection.
    bytes: AtomicUsize,

    /// Events admitted to the connection timeline.
    events: AtomicUsize,
}

impl Http3CaptureBudget {
    fn accept_bytes(&self, requested: usize) -> usize {
        reserve_bounded(&self.bytes, requested, HTTP3_CAPTURE_MAX_BYTES)
    }

    fn admit_event(&self) -> bool {
        reserve_bounded(&self.events, 1, HTTP3_CAPTURE_MAX_EVENTS) == 1
    }
}

/// Connection-level state shared by stream adapters and delayed response analysis.
struct Http3CaptureInner {
    /// Ordered events retained from all inspected streams.
    events: Http3EventCapture,

    /// Monotonic origin used for event timestamps.
    started_at: Instant,

    /// Shared resource limits for this connection.
    budget: Http3CaptureBudget,
}

/// Shared client SETTINGS captured from the HTTP/3 control stream.
#[derive(Clone)]
pub(in crate::server) struct SettingsCapture {
    /// One allocation containing the captured frame and its waiter.
    inner: Arc<SettingsCaptureInner>,
}

/// State shared by SETTINGS inspection and delayed response analysis.
struct SettingsCaptureInner {
    /// Position of the first client SETTINGS frame in the shared event log.
    event_index: OnceLock<usize>,

    /// Event storage that owns the indexed SETTINGS frame.
    events: Http3EventCapture,

    /// Wakes a request that arrived before the peer control stream.
    ready: tokio::sync::Notify,
}

impl SettingsCapture {
    /// Creates an empty capture shared by the connection and request handlers.
    fn new(events: Http3EventCapture) -> Self {
        Self {
            inner: Arc::new(SettingsCaptureInner {
                event_index: OnceLock::new(),
                events,
                ready: tokio::sync::Notify::new(),
            }),
        }
    }

    /// Returns the first client SETTINGS frame, if the control stream has supplied it.
    pub(in crate::server) fn get(&self) -> Option<&SettingsFrame> {
        let event = self.inner.events.get(*self.inner.event_index.get()?)?;
        match &event.event {
            Http3EventData::Frame {
                frame: Frame::Settings(frame),
            } => Some(frame),
            _ => None,
        }
    }

    /// Stores the first client SETTINGS event index and wakes pending request analysis.
    fn set(&self, event_index: usize) {
        if self.inner.event_index.set(event_index).is_ok() {
            self.inner.ready.notify_waiters();
        }
    }

    /// Waits until the client SETTINGS frame has been captured.
    pub(super) async fn wait(&self) {
        loop {
            if self.get().is_some() {
                return;
            }

            let notified = self.inner.ready.notified();
            if self.get().is_some() {
                return;
            }
            notified.await;
        }
    }
}

/// Shared first HEADERS frame captured from one request stream.
#[derive(Clone)]
pub(in crate::server) struct HeadersCapture {
    /// Position of the opening request HEADERS in the shared event log.
    event_index: Arc<OnceLock<usize>>,

    /// Event storage that owns the indexed HEADERS frame.
    events: Http3EventCapture,
}

impl HeadersCapture {
    fn new(events: Http3EventCapture) -> Self {
        Self {
            event_index: Arc::new(OnceLock::new()),
            events,
        }
    }

    /// Returns the opening request HEADERS frame, when available.
    pub(in crate::server) fn get(&self) -> Option<&HeadersFrame> {
        let event = self.events.get(*self.event_index.get()?)?;
        match &event.event {
            Http3EventData::Frame {
                frame: Frame::Headers(frame),
            } => Some(frame),
            _ => None,
        }
    }

    fn set(&self, event_index: usize) {
        let _ = self.event_index.set(event_index);
    }
}

/// Active request captures indexed by QUIC stream ID.
type RequestCaptures = Arc<Mutex<HashMap<StreamId, HeadersCapture>>>;

/// Shared connection-level capture state used by inspected QUIC streams.
#[derive(Clone)]
pub(in crate::server) struct Http3Capture {
    /// Event log, monotonic clock, and connection-wide resource budget.
    inner: Arc<Http3CaptureInner>,

    /// First SETTINGS frame from the peer control stream.
    settings: SettingsCapture,

    /// Bounded active request-stream captures indexed by QUIC stream ID.
    requests: RequestCaptures,
}

/// Removes a capture if its request stream ends before response analysis takes ownership.
pub(in crate::server) struct RequestCaptureGuard {
    /// Request stream whose capture is owned by this guard.
    stream_id: StreamId,

    /// Shared capture table updated when the stream is dropped.
    requests: RequestCaptures,
}

impl Drop for RequestCaptureGuard {
    fn drop(&mut self) {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.stream_id);
    }
}

impl Http3Capture {
    /// Creates empty connection-level SETTINGS and request-stream captures.
    pub(in crate::server) fn new() -> Self {
        let events = Arc::new(boxcar::Vec::new());
        Self {
            inner: Arc::new(Http3CaptureInner {
                events: events.clone(),
                started_at: Instant::now(),
                budget: Http3CaptureBudget {
                    bytes: AtomicUsize::new(0),
                    events: AtomicUsize::new(0),
                },
            }),
            settings: SettingsCapture::new(events),
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns a handle to the connection's client SETTINGS capture.
    pub(in crate::server) fn settings(&self) -> SettingsCapture {
        self.settings.clone()
    }

    /// Returns the shared connection event log.
    pub(in crate::server) fn events(&self) -> Http3EventCapture {
        self.inner.events.clone()
    }

    /// Snapshots initialized event slots without copying their frame data.
    ///
    /// Concurrent `boxcar` writers can finish out of index order, so a count alone cannot map
    /// sparse storage indices to a dense JSON array reliably.
    pub(in crate::server) fn event_snapshot(&self) -> Box<[usize]> {
        self.inner
            .events
            .iter()
            .map(|(event_index, _)| event_index)
            .collect()
    }

    /// Returns whether the connection budget can still retain frame data.
    pub(super) fn is_active(&self) -> bool {
        self.inner.budget.bytes.load(Ordering::Relaxed) < HTTP3_CAPTURE_MAX_BYTES
            && self.inner.budget.events.load(Ordering::Relaxed) < HTTP3_CAPTURE_MAX_EVENTS
    }

    /// Records one server response frame prepared by the HTTP/3 service layer.
    pub(super) fn record_server_frame(&self, stream_id: StreamId, frame: Frame) {
        let payload_len = frame.payload_len();
        if self.accept_bytes(payload_len) != payload_len {
            return;
        }
        let _ = self.record_frame(
            Http3EventDirection::ServerToClient,
            stream_id,
            Http3StreamKind::Request,
            frame,
        );
    }

    /// Removes and returns the HEADERS capture for `stream_id`.
    pub(super) fn take_headers(&self, stream_id: StreamId) -> Option<HeadersCapture> {
        self.requests().remove(&stream_id)
    }

    pub(in crate::server) fn register_request(
        &self,
        stream_id: StreamId,
    ) -> Option<(HeadersCapture, RequestCaptureGuard)> {
        let mut requests = self.requests();
        if requests.len() >= MAX_REQUEST_STREAMS_PER_CONNECTION {
            return None;
        }

        let headers = HeadersCapture::new(self.events());
        requests.insert(stream_id, headers.clone());
        Some((
            headers,
            RequestCaptureGuard {
                stream_id,
                requests: self.requests.clone(),
            },
        ))
    }

    fn requests(&self) -> MutexGuard<'_, HashMap<StreamId, HeadersCapture>> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn accept_bytes(&self, requested: usize) -> usize {
        self.inner.budget.accept_bytes(requested)
    }

    fn record_frame(
        &self,
        direction: Http3EventDirection,
        stream_id: StreamId,
        stream_kind: Http3StreamKind,
        mut frame: Frame,
    ) -> Option<usize> {
        if let Frame::Data(data) = &mut frame {
            data.truncate(HTTP3_DATA_PREVIEW_BYTES);
        }
        self.record(
            direction,
            stream_id,
            stream_kind,
            Http3EventData::Frame { frame },
        )
    }

    fn record_state(
        &self,
        direction: Http3EventDirection,
        stream_id: StreamId,
        stream_kind: Http3StreamKind,
        event: Http3EventData,
    ) {
        let _ = self.record(direction, stream_id, stream_kind, event);
    }

    fn record(
        &self,
        direction: Http3EventDirection,
        stream_id: StreamId,
        stream_kind: Http3StreamKind,
        event: Http3EventData,
    ) -> Option<usize> {
        if !self.inner.budget.admit_event() {
            return None;
        }

        let elapsed_us = self
            .inner
            .started_at
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        Some(self.inner.events.push(Http3StreamEvent {
            elapsed_us,
            direction,
            stream_id: stream_id.into_inner(),
            stream_kind,
            event,
        }))
    }
}

/// Event destination and immutable identity for one QUIC stream direction.
struct StreamRecorder {
    /// Connection capture that owns the event log.
    capture: Http3Capture,

    /// Direction represented by this recorder.
    direction: Http3EventDirection,

    /// QUIC stream identifier.
    stream_id: StreamId,

    /// HTTP/3 role of the stream.
    stream_kind: Http3StreamKind,

    /// Prevents duplicate FIN events when a future is polled again after completion.
    finished: bool,
}

impl StreamRecorder {
    fn new(
        capture: Http3Capture,
        direction: Http3EventDirection,
        stream_id: StreamId,
        stream_kind: Http3StreamKind,
    ) -> Self {
        Self {
            capture,
            direction,
            stream_id,
            stream_kind,
            finished: false,
        }
    }

    fn record_frame(&self, frame: Frame) -> Option<usize> {
        self.capture
            .record_frame(self.direction, self.stream_id, self.stream_kind, frame)
    }

    fn record(&self, event: Http3EventData) {
        self.capture
            .record_state(self.direction, self.stream_id, self.stream_kind, event);
    }

    fn finish(&mut self) {
        if !self.finished {
            self.record(Http3EventData::Finished);
            self.finished = true;
        }
    }

    fn terminate(&mut self, direction: Http3EventDirection, event: Http3EventData) {
        if !self.finished {
            self.capture
                .record_state(direction, self.stream_id, self.stream_kind, event);
            self.finished = true;
        }
    }
}

/// Incremental HTTP/3 parser and destinations for fingerprint inputs.
struct ActiveCapture {
    /// Parser selected for a control or request stream.
    parser: Http3Parser,

    /// Reused output allocation for completed frames.
    frames: Vec<Frame>,

    /// First client SETTINGS destination for a control stream.
    settings: Option<SettingsCapture>,

    /// Opening client HEADERS destination for a request stream.
    headers: Option<HeadersCapture>,
}

/// Optional parser plus stream-state recorder for one QUIC direction.
pub(in crate::server) struct CaptureParser {
    /// Parser disabled after malformed, ignored, or over-limit input.
    active: Option<ActiveCapture>,

    /// Recorder retained after parsing stops so QUIC FIN remains visible.
    recorder: Option<StreamRecorder>,
}

impl CaptureParser {
    pub(in crate::server) fn control(
        capture: Http3Capture,
        direction: Http3EventDirection,
        stream_id: StreamId,
        settings: Option<SettingsCapture>,
    ) -> Self {
        Self {
            active: Some(ActiveCapture {
                parser: Http3Parser::unidirectional(),
                frames: Vec::new(),
                settings,
                headers: None,
            }),
            recorder: Some(StreamRecorder::new(
                capture,
                direction,
                stream_id,
                Http3StreamKind::Other,
            )),
        }
    }

    pub(in crate::server) fn request(
        capture: Http3Capture,
        stream_id: StreamId,
        headers: HeadersCapture,
    ) -> Self {
        Self {
            active: Some(ActiveCapture {
                parser: Http3Parser::request().with_data_preview_limit(HTTP3_DATA_PREVIEW_BYTES),
                frames: Vec::new(),
                settings: None,
                headers: Some(headers),
            }),
            recorder: Some(StreamRecorder::new(
                capture,
                Http3EventDirection::ClientToServer,
                stream_id,
                Http3StreamKind::Request,
            )),
        }
    }

    fn state_only(recorder: StreamRecorder) -> Self {
        Self {
            active: None,
            recorder: Some(recorder),
        }
    }

    fn disabled() -> Self {
        Self {
            active: None,
            recorder: None,
        }
    }

    pub(in crate::server) fn inspect(&mut self, bytes: &[u8]) {
        let (Some(active), Some(recorder)) = (&mut self.active, &mut self.recorder) else {
            return;
        };
        if !recorder.capture.is_active() {
            self.active = None;
            return;
        }

        let admitted = recorder.capture.accept_bytes(bytes.len());
        if admitted == 0 {
            self.active = None;
            return;
        }

        let result = active
            .parser
            .push_into(&bytes[..admitted], &mut active.frames);
        if let Some(stream_type) = active.parser.stream_type() {
            recorder.stream_kind = match stream_type.name {
                StreamTypeName::Control => Http3StreamKind::Control,
                StreamTypeName::Push => Http3StreamKind::Push,
                StreamTypeName::QpackEncoder => Http3StreamKind::QpackEncoder,
                StreamTypeName::QpackDecoder => Http3StreamKind::QpackDecoder,
                StreamTypeName::WebTransport => Http3StreamKind::WebTransport,
                _ => Http3StreamKind::Other,
            };
        }
        for frame in active.frames.drain(..) {
            let is_settings = matches!(frame, Frame::Settings(_));
            let is_headers = matches!(frame, Frame::Headers(_));
            let event_index = recorder.record_frame(frame);
            if is_settings {
                if let (Some(settings), Some(event_index)) = (&active.settings, event_index) {
                    settings.set(event_index);
                }
            } else if is_headers {
                if let (Some(headers), Some(event_index)) = (&active.headers, event_index) {
                    headers.set(event_index);
                }
            }
        }

        if let Err(error) = result {
            tracing::debug!(
                ?error,
                direction = ?recorder.direction,
                stream_id = recorder.stream_id.into_inner(),
                "failed to inspect HTTP/3 stream"
            );
            self.active = None;
            return;
        }

        if admitted < bytes.len() || active.parser.is_ignored() || !recorder.capture.is_active() {
            self.active = None;
        }
    }

    pub(in crate::server) fn finish(&mut self) {
        if let Some(active) = self.active.take() {
            if let Err(error) = active.parser.finish() {
                if let Some(recorder) = &self.recorder {
                    tracing::debug!(
                        ?error,
                        direction = ?recorder.direction,
                        stream_id = recorder.stream_id.into_inner(),
                        "captured HTTP/3 stream ended with incomplete framing"
                    );
                }
            }
        }
        if let Some(recorder) = &mut self.recorder {
            recorder.finish();
        }
    }

    fn terminate_with_direction(&mut self, direction: Http3EventDirection, event: Http3EventData) {
        if let Some(recorder) = &mut self.recorder {
            recorder.terminate(direction, event);
        }
    }
}

/// H3 QUIC connection wrapper that observes decrypted incoming stream bytes.
pub(super) struct InspectedConnection {
    /// Quinn-backed H3 connection receiving the original stream operations.
    inner: h3_quinn::Connection,

    /// Shared destination for control and request stream captures.
    capture: Http3Capture,
}

impl InspectedConnection {
    /// Wraps a Quinn-backed H3 connection with shared capture state.
    pub(super) fn new(inner: h3_quinn::Connection, capture: Http3Capture) -> Self {
        Self { inner, capture }
    }
}

impl<B> Connection<B> for InspectedConnection
where
    B: Buf,
{
    type RecvStream = InspectedRecvStream;
    type OpenStreams = InspectedOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match Connection::<B>::poll_accept_recv(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => {
                let stream_id = RecvStream::recv_id(&stream);
                Poll::Ready(Ok(InspectedRecvStream {
                    inner: stream,
                    capture: CaptureParser::control(
                        self.capture.clone(),
                        Http3EventDirection::ClientToServer,
                        stream_id,
                        Some(self.capture.settings()),
                    ),
                    _request_capture: None,
                }))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match Connection::<B>::poll_accept_bidi(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => {
                let stream_id = RecvStream::recv_id(&stream);
                let (recv_capture, send_capture, request_capture) =
                    match self.capture.register_request(stream_id) {
                        Some((headers, guard)) => (
                            CaptureParser::request(self.capture.clone(), stream_id, headers),
                            CaptureParser::state_only(StreamRecorder::new(
                                self.capture.clone(),
                                Http3EventDirection::ServerToClient,
                                stream_id,
                                Http3StreamKind::Request,
                            )),
                            Some(guard),
                        ),
                        None => (CaptureParser::disabled(), CaptureParser::disabled(), None),
                    };
                Poll::Ready(Ok(InspectedBidiStream {
                    inner: stream,
                    recv_capture,
                    send_capture,
                    _request_capture: request_capture,
                }))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        InspectedOpenStreams {
            inner: Connection::<B>::opener(&self.inner),
            capture: self.capture.clone(),
        }
    }
}

impl<B> OpenStreams<B> for InspectedConnection
where
    B: Buf,
{
    type BidiStream = InspectedBidiStream<B>;
    type SendStream = InspectedSendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(InspectedBidiStream {
                inner: stream,
                recv_capture: CaptureParser::disabled(),
                send_capture: CaptureParser::disabled(),
                _request_capture: None,
            })),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match OpenStreams::<B>::poll_open_send(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => {
                let stream_id = SendStream::send_id(&stream);
                Poll::Ready(Ok(InspectedSendStream {
                    inner: stream,
                    capture: CaptureParser::control(
                        self.capture.clone(),
                        Http3EventDirection::ServerToClient,
                        stream_id,
                        None,
                    ),
                }))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

/// Outgoing-stream handle that preserves the inspected H3 stream types.
pub(super) struct InspectedOpenStreams {
    /// Quinn outgoing-stream handle delegated to by this wrapper.
    inner: h3_quinn::OpenStreams,

    /// Shared destination for newly opened server streams.
    capture: Http3Capture,
}

impl<B> OpenStreams<B> for InspectedOpenStreams
where
    B: Buf,
{
    type BidiStream = InspectedBidiStream<B>;
    type SendStream = InspectedSendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(InspectedBidiStream {
                inner: stream,
                recv_capture: CaptureParser::disabled(),
                send_capture: CaptureParser::disabled(),
                _request_capture: None,
            })),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match OpenStreams::<B>::poll_open_send(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => {
                let stream_id = SendStream::send_id(&stream);
                Poll::Ready(Ok(InspectedSendStream {
                    inner: stream,
                    capture: CaptureParser::control(
                        self.capture.clone(),
                        Http3EventDirection::ServerToClient,
                        stream_id,
                        None,
                    ),
                }))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

/// Send half that records server control frames and QUIC stream state.
pub(super) struct InspectedSendStream<B>
where
    B: Buf,
{
    /// Underlying Quinn send stream.
    inner: h3_quinn::SendStream<B>,

    /// Control-stream parser or request-stream state recorder.
    capture: CaptureParser,
}

impl<B> SendStream<B> for InspectedSendStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match SendStream::poll_ready(&mut self.inner, cx) {
            Poll::Ready(Err(error)) => {
                record_send_termination(&mut self.capture, &error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        let data = data.into();
        self.capture.inspect(data.chunk());
        SendStream::send_data(&mut self.inner, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match SendStream::poll_finish(&mut self.inner, cx) {
            Poll::Ready(Ok(())) => {
                self.capture.finish();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                record_send_termination(&mut self.capture, &error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn reset(&mut self, reset_code: u64) {
        self.capture.terminate_with_direction(
            Http3EventDirection::ServerToClient,
            Http3EventData::Reset {
                error_code: reset_code,
            },
        );
        SendStream::reset(&mut self.inner, reset_code);
    }

    fn send_id(&self) -> StreamId {
        SendStream::send_id(&self.inner)
    }
}

impl<B> SendStreamUnframed<B> for InspectedSendStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        SendStreamUnframed::poll_send(&mut self.inner, cx, buffer)
    }
}

/// Bidirectional H3 stream that observes received bytes before forwarding them.
pub(super) struct InspectedBidiStream<B>
where
    B: Buf,
{
    /// Underlying Quinn bidirectional stream.
    inner: h3_quinn::BidiStream<B>,

    /// Incremental parser assigned to the client-to-server direction.
    recv_capture: CaptureParser,

    /// Stream-state recorder assigned to the server-to-client direction.
    send_capture: CaptureParser,

    /// Removes an unfinished request capture when this stream is dropped.
    _request_capture: Option<RequestCaptureGuard>,
}

impl<B> RecvStream for InspectedBidiStream<B>
where
    B: Buf,
{
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        poll_inspected_data(&mut self.inner, &mut self.recv_capture, cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv_capture.terminate_with_direction(
            Http3EventDirection::ServerToClient,
            Http3EventData::StopSending { error_code },
        );
        RecvStream::stop_sending(&mut self.inner, error_code);
    }

    fn recv_id(&self) -> StreamId {
        RecvStream::recv_id(&self.inner)
    }
}

impl<B> SendStream<B> for InspectedBidiStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match SendStream::poll_ready(&mut self.inner, cx) {
            Poll::Ready(Err(error)) => {
                record_send_termination(&mut self.send_capture, &error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        SendStream::send_data(&mut self.inner, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match SendStream::poll_finish(&mut self.inner, cx) {
            Poll::Ready(Ok(())) => {
                self.send_capture.finish();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                record_send_termination(&mut self.send_capture, &error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn reset(&mut self, reset_code: u64) {
        self.send_capture.terminate_with_direction(
            Http3EventDirection::ServerToClient,
            Http3EventData::Reset {
                error_code: reset_code,
            },
        );
        SendStream::reset(&mut self.inner, reset_code);
    }

    fn send_id(&self) -> StreamId {
        SendStream::send_id(&self.inner)
    }
}

impl<B> SendStreamUnframed<B> for InspectedBidiStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        SendStreamUnframed::poll_send(&mut self.inner, cx, buffer)
    }
}

impl<B> BidiStream<B> for InspectedBidiStream<B>
where
    B: Buf,
{
    type SendStream = InspectedSendStream<B>;
    type RecvStream = InspectedRecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = BidiStream::split(self.inner);
        (
            InspectedSendStream {
                inner: send,
                capture: self.send_capture,
            },
            InspectedRecvStream {
                inner: recv,
                capture: self.recv_capture,
                _request_capture: self._request_capture,
            },
        )
    }
}

/// Receive half that observes decrypted H3 bytes before forwarding them.
pub(super) struct InspectedRecvStream {
    /// Underlying Quinn receive stream.
    inner: h3_quinn::RecvStream,

    /// Incremental parser assigned before the stream was split.
    capture: CaptureParser,

    /// Removes an unfinished request capture when this stream is dropped.
    _request_capture: Option<RequestCaptureGuard>,
}

impl RecvStream for InspectedRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        poll_inspected_data(&mut self.inner, &mut self.capture, cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.capture.terminate_with_direction(
            Http3EventDirection::ServerToClient,
            Http3EventData::StopSending { error_code },
        );
        RecvStream::stop_sending(&mut self.inner, error_code);
    }

    fn recv_id(&self) -> StreamId {
        RecvStream::recv_id(&self.inner)
    }
}

fn record_send_termination(capture: &mut CaptureParser, error: &StreamErrorIncoming) {
    if let StreamErrorIncoming::StreamTerminated { error_code } = error {
        capture.terminate_with_direction(
            Http3EventDirection::ClientToServer,
            Http3EventData::StopSending {
                error_code: *error_code,
            },
        );
    }
}

fn poll_inspected_data<S>(
    stream: &mut S,
    capture: &mut CaptureParser,
    cx: &mut Context<'_>,
) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>>
where
    S: RecvStream<Buf = Bytes>,
{
    match RecvStream::poll_data(stream, cx) {
        Poll::Ready(Ok(Some(bytes))) => {
            capture.inspect(&bytes);
            Poll::Ready(Ok(Some(bytes)))
        }
        Poll::Ready(Ok(None)) => {
            capture.finish();
            Poll::Ready(Ok(None))
        }
        Poll::Ready(Err(error)) => {
            if let StreamErrorIncoming::StreamTerminated { error_code } = &error {
                capture.terminate_with_direction(
                    Http3EventDirection::ClientToServer,
                    Http3EventData::Reset {
                        error_code: *error_code,
                    },
                );
            }
            Poll::Ready(Err(error))
        }
        Poll::Pending => Poll::Pending,
    }
}

fn reserve_bounded(counter: &AtomicUsize, requested: usize, limit: usize) -> usize {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let accepted = requested.min(limit.saturating_sub(current));
        if accepted == 0 {
            return 0;
        }

        match counter.compare_exchange_weak(
            current,
            current + accepted,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return accepted,
            Err(observed) => current = observed,
        }
    }
}

fn serialize_stream_id<S>(stream_id: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *stream_id <= JSON_SAFE_INTEGER_MAX {
        serializer.serialize_u64(*stream_id)
    } else {
        serializer.collect_str(stream_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use h3::quic::StreamId;
    use pingly::h3::Frame;

    use super::{
        CaptureParser, Http3Capture, Http3EventData, Http3EventDirection,
        MAX_REQUEST_STREAMS_PER_CONNECTION,
    };

    #[test]
    fn request_capture_slots_are_bounded_and_released() {
        let capture = Http3Capture::new();
        let mut guards = Vec::with_capacity(MAX_REQUEST_STREAMS_PER_CONNECTION);

        for index in 0..MAX_REQUEST_STREAMS_PER_CONNECTION {
            let stream_id = StreamId::try_from((index * 4) as u64).unwrap();
            let (_, guard) = capture.register_request(stream_id).unwrap();
            guards.push(guard);
        }

        let next = StreamId::try_from((MAX_REQUEST_STREAMS_PER_CONNECTION * 4) as u64).unwrap();
        assert!(capture.register_request(next).is_none());

        let first = StreamId::try_from(0).unwrap();
        let removed = capture.take_headers(first).unwrap();
        let (replacement, replacement_guard) = capture.register_request(next).unwrap();
        assert!(!Arc::ptr_eq(&removed.event_index, &replacement.event_index));

        drop(replacement_guard);
        drop(guards);
        assert!(capture.requests().is_empty());
    }

    #[tokio::test]
    async fn control_and_request_streams_share_one_bounded_timeline() {
        let capture = Http3Capture::new();
        let settings = capture.settings();
        let waiter = settings.clone();
        let task = tokio::spawn(async move { waiter.wait().await });

        let control_id = StreamId::try_from(2).unwrap();
        let mut control = CaptureParser::control(
            capture.clone(),
            Http3EventDirection::ClientToServer,
            control_id,
            Some(settings.clone()),
        );
        control.inspect(&[0x00, 0x04, 0x00]);
        control.finish();

        task.await.unwrap();
        assert!(settings.get().is_some());

        let request_id = StreamId::try_from(0).unwrap();
        let (headers, _guard) = capture.register_request(request_id).unwrap();
        let mut request = CaptureParser::request(capture.clone(), request_id, headers.clone());
        let mut wire = vec![0x01, 0x03, 0x00, 0x00, 0xd1, 0x00, 0x40, 0x41];
        wire.extend_from_slice(&[0xaa; 65]);
        request.inspect(&wire);
        request.finish();

        assert!(headers.get().is_some());
        assert_eq!(capture.event_snapshot().len(), 5);
        assert!(matches!(
            &capture.events().get(3).unwrap().event,
            Http3EventData::Frame {
                frame: Frame::Data(frame)
            } if frame.length == 65 && frame.data.len() == 64 && frame.truncated
        ));
    }
}
