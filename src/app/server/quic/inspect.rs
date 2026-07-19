use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use h3::quic::{
    BidiStream, Connection, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream,
    SendStreamUnframed, StreamErrorIncoming, StreamId, WriteBuf,
};
use pingly::h3::{Frame, HeadersFrame, Http3Parser, SettingsFrame};

/// Shared client SETTINGS captured from the HTTP/3 control stream.
#[derive(Clone)]
pub(in crate::server) struct SettingsCapture {
    /// One allocation containing the captured frame and its waiter.
    inner: Arc<SettingsCaptureInner>,
}

/// State shared by SETTINGS inspection and delayed response analysis.
struct SettingsCaptureInner {
    /// One-time SETTINGS value shared with response analysis.
    value: OnceLock<SettingsFrame>,

    /// Wakes a request that arrived before the peer control stream.
    ready: tokio::sync::Notify,
}

impl SettingsCapture {
    pub(in crate::server) fn new() -> Self {
        Self {
            inner: Arc::new(SettingsCaptureInner {
                value: OnceLock::new(),
                ready: tokio::sync::Notify::new(),
            }),
        }
    }

    pub(in crate::server) fn get(&self) -> Option<&SettingsFrame> {
        self.inner.value.get()
    }

    pub(in crate::server) fn set(&self, frame: SettingsFrame) {
        if self.inner.value.set(frame).is_ok() {
            self.inner.ready.notify_waiters();
        }
    }

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
pub(in crate::server) type HeadersCapture = Arc<OnceLock<HeadersFrame>>;

const HTTP3_CAPTURE_MAX_REQUESTS: usize = 128;

type RequestCaptures = Arc<Mutex<HashMap<StreamId, HeadersCapture>>>;

/// Shared connection-level capture state used by inspected QUIC streams.
#[derive(Clone)]
pub(super) struct Http3Capture {
    /// First SETTINGS frame from the peer control stream.
    settings: SettingsCapture,

    /// Bounded active request-stream captures indexed by QUIC stream ID.
    requests: RequestCaptures,
}

/// Removes a capture if its request stream ends before response analysis takes ownership.
struct RequestCaptureGuard {
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
    pub(super) fn new() -> Self {
        Self {
            settings: SettingsCapture::new(),
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) fn settings(&self) -> SettingsCapture {
        self.settings.clone()
    }

    pub(super) fn take_headers(&self, stream_id: StreamId) -> Option<HeadersCapture> {
        self.requests().remove(&stream_id)
    }

    fn register_request(
        &self,
        stream_id: StreamId,
    ) -> Option<(HeadersCapture, RequestCaptureGuard)> {
        let mut requests = self.requests();
        if requests.len() >= HTTP3_CAPTURE_MAX_REQUESTS {
            return None;
        }

        let headers = Arc::new(OnceLock::new());
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
}

enum CaptureParser {
    Control {
        parser: Http3Parser,
        settings: SettingsCapture,
    },
    Request {
        parser: Http3Parser,
        headers: HeadersCapture,
    },
    Disabled,
}

impl CaptureParser {
    fn control(settings: SettingsCapture) -> Self {
        Self::Control {
            parser: Http3Parser::unidirectional(),
            settings,
        }
    }

    fn request(headers: HeadersCapture) -> Self {
        Self::Request {
            parser: Http3Parser::request(),
            headers,
        }
    }

    fn inspect(&mut self, bytes: &[u8]) {
        let disable = match self {
            Self::Control { parser, settings } => inspect_control(parser, settings, bytes),
            Self::Request { parser, headers } => inspect_request(parser, headers, bytes),
            Self::Disabled => false,
        };
        if disable {
            *self = Self::Disabled;
        }
    }
}

fn inspect_control(parser: &mut Http3Parser, settings: &SettingsCapture, bytes: &[u8]) -> bool {
    let (frames, error) = match parser.push(bytes) {
        Ok(frames) => (frames, None),
        Err(error) => {
            let (frames, error) = error.into_parts();
            (frames, Some(error))
        }
    };

    for frame in frames {
        if let Frame::Settings(frame) = frame {
            settings.set(frame);
            return true;
        }
    }

    if let Some(error) = error {
        tracing::debug!(?error, "failed to inspect HTTP/3 control stream");
        return true;
    }
    parser.is_ignored()
}

fn inspect_request(parser: &mut Http3Parser, headers: &HeadersCapture, bytes: &[u8]) -> bool {
    let (frames, error) = match parser.push(bytes) {
        Ok(frames) => (frames, None),
        Err(error) => {
            let (frames, error) = error.into_parts();
            (frames, Some(error))
        }
    };

    for frame in frames {
        if let Frame::Headers(frame) = frame {
            let _ = headers.set(frame);
            return true;
        }
    }

    if let Some(error) = error {
        tracing::debug!(?error, "failed to inspect HTTP/3 request stream");
        return true;
    }
    false
}

/// H3 QUIC connection wrapper that observes decrypted incoming stream bytes.
pub(super) struct InspectedConnection {
    /// Quinn-backed H3 connection receiving the original stream operations.
    inner: h3_quinn::Connection,

    /// Shared destination for control and request stream captures.
    capture: Http3Capture,
}

impl InspectedConnection {
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
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(InspectedRecvStream {
                inner: stream,
                capture: CaptureParser::control(self.capture.settings()),
                _request_capture: None,
            })),
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
                let (capture, request_capture) = match self.capture.register_request(stream_id) {
                    Some((headers, guard)) => (CaptureParser::request(headers), Some(guard)),
                    None => (CaptureParser::Disabled, None),
                };
                Poll::Ready(Ok(InspectedBidiStream {
                    inner: stream,
                    capture,
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
        }
    }
}

impl<B> OpenStreams<B> for InspectedConnection
where
    B: Buf,
{
    type BidiStream = InspectedBidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(InspectedBidiStream {
                inner: stream,
                capture: CaptureParser::Disabled,
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
        OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

/// Outgoing-stream handle that preserves the inspected H3 stream types.
pub(super) struct InspectedOpenStreams {
    /// Quinn outgoing-stream handle delegated to by this wrapper.
    inner: h3_quinn::OpenStreams,
}

impl<B> OpenStreams<B> for InspectedOpenStreams
where
    B: Buf,
{
    type BidiStream = InspectedBidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(InspectedBidiStream {
                inner: stream,
                capture: CaptureParser::Disabled,
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
        OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

/// Bidirectional H3 stream that observes received bytes before forwarding them.
pub(super) struct InspectedBidiStream<B>
where
    B: Buf,
{
    /// Underlying Quinn bidirectional stream.
    inner: h3_quinn::BidiStream<B>,

    /// Incremental parser assigned to this incoming stream.
    capture: CaptureParser,

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
        poll_inspected_data(&mut self.inner, &mut self.capture, cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
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
        SendStream::poll_ready(&mut self.inner, cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        SendStream::send_data(&mut self.inner, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        SendStream::poll_finish(&mut self.inner, cx)
    }

    fn reset(&mut self, reset_code: u64) {
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
    type SendStream = h3_quinn::SendStream<B>;
    type RecvStream = InspectedRecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = BidiStream::split(self.inner);
        (
            send,
            InspectedRecvStream {
                inner: recv,
                capture: self.capture,
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
        RecvStream::stop_sending(&mut self.inner, error_code);
    }

    fn recv_id(&self) -> StreamId {
        RecvStream::recv_id(&self.inner)
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
        Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Pending => Poll::Pending,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use h3::quic::StreamId;
    use pingly::h3::{FrameType, SettingsFrame};

    use super::{Http3Capture, SettingsCapture, HTTP3_CAPTURE_MAX_REQUESTS};

    #[test]
    fn completed_request_captures_are_reused_past_the_connection_limit() {
        let capture = Http3Capture::new();

        for index in 0..(HTTP3_CAPTURE_MAX_REQUESTS * 2) {
            let stream_id = StreamId::try_from((index * 4) as u64).unwrap();
            let (registered, _guard) = capture.register_request(stream_id).unwrap();
            assert!(Arc::ptr_eq(
                &capture.take_headers(stream_id).unwrap(),
                &registered
            ));
        }

        assert!(capture.requests().is_empty());
    }

    #[test]
    fn dropped_request_stream_releases_its_capture() {
        let capture = Http3Capture::new();
        let stream_id = StreamId::try_from(0).unwrap();
        let (_, guard) = capture.register_request(stream_id).unwrap();

        assert_eq!(capture.requests().len(), 1);
        drop(guard);
        assert!(capture.requests().is_empty());
    }

    #[test]
    fn request_capture_limit_applies_only_to_concurrent_streams() {
        let capture = Http3Capture::new();
        let mut guards = Vec::with_capacity(HTTP3_CAPTURE_MAX_REQUESTS);

        for index in 0..HTTP3_CAPTURE_MAX_REQUESTS {
            let stream_id = StreamId::try_from((index * 4) as u64).unwrap();
            let (_, guard) = capture.register_request(stream_id).unwrap();
            guards.push(guard);
        }

        let next = StreamId::try_from((HTTP3_CAPTURE_MAX_REQUESTS * 4) as u64).unwrap();
        assert!(capture.register_request(next).is_none());

        drop(guards.pop());
        assert!(capture.register_request(next).is_some());
    }

    #[tokio::test]
    async fn settings_waiter_is_notified_when_control_stream_arrives() {
        let capture = SettingsCapture::new();
        let waiter = capture.clone();
        let task = tokio::spawn(async move { waiter.wait().await });

        capture.set(SettingsFrame {
            frame_type: FrameType::Settings,
            length: 0,
            settings: Vec::new(),
        });

        task.await.unwrap();
        assert!(capture.get().is_some());
    }
}
