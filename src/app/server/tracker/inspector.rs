//! Stream adapters that retain protocol bytes for delayed analysis.
//!
//! Each adapter forwards reads and writes unchanged. Capture work on the I/O path is limited to
//! bounded buffering and incremental framing.

use std::{
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{self, Poll},
    time::Instant,
};

use bytes::{Buf, BytesMut};
use pin_project_lite::pin_project;
pub use pingly::tls::{ClientHello, ClientHelloBuffer};
use pingly::{
    h1::Http1HeadBuffer,
    h2::{frame, frame::Frame, HTTP2_CLIENT_PREFACE},
};
use serde::Serialize;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

/// Shared storage for one raw HTTP/1 request head.
pub type Http1RequestCapture = Arc<OnceLock<Http1HeadBuffer>>;

/// Concurrent storage for HTTP/2 frame events captured from one connection.
pub type Http2Capture = Arc<boxcar::Vec<Http2FrameEvent>>;

/// Direction of an HTTP/2 frame relative to Pingly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Http2FrameDirection {
    /// A frame sent by the client to Pingly.
    ClientToServer,

    /// A frame sent by Pingly to the client.
    ServerToClient,
}

/// One timestamped HTTP/2 frame observed on the decrypted connection.
#[derive(Debug, Serialize)]
pub struct Http2FrameEvent {
    /// Microseconds elapsed since HTTP/2 inspection began.
    pub elapsed_us: u64,

    /// Frame direction relative to Pingly.
    pub direction: Http2FrameDirection,

    /// Decoded frame fields and retained payload bytes.
    #[serde(flatten)]
    pub frame: Frame,
}

const HTTP2_CAPTURE_MAX_BYTES: usize = 1024 * 1024;
const HTTP2_CAPTURE_MAX_FRAMES: usize = 512;
const HTTP2_DATA_PREVIEW_BYTES: usize = 64;

#[derive(Default)]
struct Http2CaptureBudget {
    /// Number of bytes admitted to this direction's capture buffer.
    bytes: usize,

    /// Number of complete wire frames observed.
    frames: usize,

    /// Whether this direction no longer needs inspection.
    stopped: bool,
}

impl Http2CaptureBudget {
    #[inline]
    fn is_active(&self) -> bool {
        !self.stopped
    }

    fn accept_bytes(&mut self, requested: usize) -> usize {
        if self.stopped {
            return 0;
        }

        let accepted = requested.min(HTTP2_CAPTURE_MAX_BYTES.saturating_sub(self.bytes));
        self.bytes += accepted;
        accepted
    }

    #[inline]
    fn byte_limit_reached(&self) -> bool {
        self.bytes >= HTTP2_CAPTURE_MAX_BYTES
    }

    /// Admits one complete wire frame when the event limit has room.
    fn admit_frame(&mut self) -> bool {
        if self.frames >= HTTP2_CAPTURE_MAX_FRAMES {
            return false;
        }

        self.frames += 1;
        true
    }

    #[inline]
    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// Incremental parser and resource budget for one HTTP/2 wire direction.
struct Http2WireCapture {
    /// Bytes waiting for a complete preface or frame.
    buffer: BytesMut,

    /// Stateful frame and HPACK decoder for this direction.
    parser: frame::FrameParser,

    /// Whether the expected client connection preface has been consumed.
    preface_complete: bool,

    /// Bounds retained bytes and parsing work for this direction.
    budget: Http2CaptureBudget,
}

impl Http2WireCapture {
    fn client() -> Self {
        Self::new(true)
    }

    fn server() -> Self {
        Self::new(false)
    }

    fn new(expects_preface: bool) -> Self {
        Self {
            buffer: BytesMut::new(),
            parser: frame::FrameParser::default(),
            preface_complete: !expects_preface,
            budget: Http2CaptureBudget::default(),
        }
    }

    fn inspect(
        &mut self,
        bytes: &[u8],
        direction: Http2FrameDirection,
        started_at: Instant,
        events: &boxcar::Vec<Http2FrameEvent>,
    ) -> Option<u32> {
        if !self.budget.is_active() || bytes.is_empty() {
            return None;
        }

        let admitted = self.budget.accept_bytes(bytes.len());
        self.buffer.extend_from_slice(&bytes[..admitted]);
        if !self.consume_preface() {
            self.stop();
            return None;
        }

        let mut header_table_size = None;
        while self.preface_complete && !self.buffer.is_empty() {
            let (consumed, frame) = match self.parser.parse(&self.buffer) {
                Ok(outcome) => (outcome.consumed(), outcome.into_frame()),
                Err(error) => {
                    tracing::debug!(?error, ?direction, "failed to parse captured HTTP/2 frame");
                    (error.consumed, None)
                }
            };
            if consumed == 0 {
                break;
            }
            self.buffer.advance(consumed.min(self.buffer.len()));

            if !self.budget.admit_frame() {
                self.stop();
                return header_table_size;
            }
            if let Some(mut frame) = frame {
                if let Frame::Settings(settings) = &frame {
                    header_table_size = settings
                        .settings
                        .iter()
                        .rev()
                        .find_map(|setting| match setting.value() {
                            (1, value) => Some(value),
                            _ => None,
                        })
                        .or(header_table_size);
                }
                if let Frame::Data(data) = &mut frame {
                    data.truncate(HTTP2_DATA_PREVIEW_BYTES);
                }
                let elapsed_us = started_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                events.push(Http2FrameEvent {
                    elapsed_us,
                    direction,
                    frame,
                });
            }
        }

        if self.budget.byte_limit_reached() || self.budget.frames >= HTTP2_CAPTURE_MAX_FRAMES {
            self.stop();
        }

        header_table_size
    }

    fn set_max_header_table_size(&mut self, size: u32) {
        self.parser.set_max_header_table_size(size);
    }

    fn consume_preface(&mut self) -> bool {
        if self.preface_complete {
            return true;
        }

        let prefix_len = self.buffer.len().min(HTTP2_CLIENT_PREFACE.len());
        if self.buffer[..prefix_len] != HTTP2_CLIENT_PREFACE[..prefix_len] {
            return false;
        }
        if prefix_len == HTTP2_CLIENT_PREFACE.len() {
            self.buffer.advance(HTTP2_CLIENT_PREFACE.len());
            self.preface_complete = true;
        }

        true
    }

    fn stop(&mut self) {
        self.budget.stop();
        self.buffer = BytesMut::new();
        self.parser.reset();
    }
}

/// HTTP stream selected after TLS ALPN negotiation.
///
/// Both variants implement [`AsyncRead`] and [`AsyncWrite`] by forwarding operations to their
/// wrapped TLS stream.
#[allow(clippy::large_enum_variant)]
pub enum Inspector<S> {
    /// HTTP/1 stream with request-head capture.
    Http1(Http1Inspector<S>),

    /// HTTP/2 stream with frame capture.
    Http2(Http2Inspector<S>),
}

impl<I> AsyncRead for Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_read(cx, buf),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_read(cx, buf),
        }
    }
}

impl<I> AsyncWrite for Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_write(cx, buf),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_flush(cx),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_shutdown(cx),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_shutdown(cx),
        }
    }
}

pin_project! {
    /// Stream wrapper that retains the first TLS ClientHello while forwarding all I/O.
    pub struct TlsInspector<I> {
        // Accepted TCP stream.
        #[pin]
        inner: I,

        // Bounded TLS-record capture removed after the handshake.
        client_hello: Option<ClientHelloBuffer>,
    }
}

impl<I> TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Wraps an accepted stream with ClientHello capture.
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            client_hello: Some(ClientHelloBuffer::new()),
        }
    }

    /// Takes the buffered ClientHello capture.
    ///
    /// Later calls return `None`.
    #[inline]
    #[must_use]
    pub fn client_hello(&mut self) -> Option<ClientHelloBuffer> {
        self.client_hello.take()
    }
}

impl<I> AsyncRead for TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf.filled().len();
        let this = self.project();
        let poll = this.inner.poll_read(cx, buf);

        if let Some(client_hello) = this.client_hello {
            if !client_hello.is_complete() && !client_hello.is_invalid() && !client_hello.is_full()
            {
                client_hello.extend(&buf.filled()[len..]);
            }
        }

        poll
    }
}

impl<I> AsyncWrite for TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pin_project! {
    /// A TLS stream wrapper that captures an HTTP/1 request head for delayed analysis.
    ///
    /// The read path only locates the empty line ending the field section. Field validation and
    /// owned model construction are deferred until the response is built. HTTP/1 message framing
    /// is defined by
    /// [RFC 9112, Section 2.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.1).
    pub struct Http1Inspector<I> {
        // TLS stream forwarded to Hyper.
        #[pin]
        inner: TlsStream<TlsInspector<I>>,

        // Request bytes retained until the head completes or reaches its limit.
        capture: Option<Http1HeadBuffer>,

        // Completed raw head shared with response analysis.
        request_capture: Http1RequestCapture,
    }
}

impl<I> Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Wraps a TLS stream with bounded HTTP/1 request-head capture.
    #[inline]
    pub fn new(inner: TlsStream<TlsInspector<I>>) -> Self {
        Self {
            inner,
            capture: Some(Http1HeadBuffer::request()),
            request_capture: Arc::new(OnceLock::new()),
        }
    }

    /// Returns the raw HTTP/1 request head shared with delayed analysis.
    #[inline]
    pub fn request_capture(&self) -> Http1RequestCapture {
        self.request_capture.clone()
    }
}

impl<I> AsyncRead for Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let prev_len = buf.filled().len();
        let poll = this.inner.poll_read(cx, buf);

        let new_data = &buf.filled()[prev_len..];
        if !new_data.is_empty() {
            if let Some(capture) = this.capture.as_mut() {
                capture.extend(new_data);
            }

            let capture_ready = this
                .capture
                .as_ref()
                .is_some_and(|capture| capture.is_complete() || capture.is_full());
            if capture_ready {
                if let Some(capture) = this.capture.take() {
                    if this.request_capture.set(capture).is_err() {
                        tracing::debug!("HTTP/1 request head was already captured");
                    }
                }
            }
        }

        poll
    }
}

impl<I> AsyncWrite for Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pin_project! {
    /// TLS stream wrapper that captures a bounded, bidirectional HTTP/2 frame timeline.
    ///
    /// Client and server directions keep separate HPACK state. Reads and writes continue normally
    /// after either direction reaches its byte or frame limit.
    pub struct Http2Inspector<I> {
        // TLS stream forwarded to Hyper.
        #[pin]
        inner: TlsStream<TlsInspector<I>>,

        // Incremental parser for client-to-server frames.
        inbound: Http2WireCapture,

        // Incremental parser for server-to-client frames.
        outbound: Http2WireCapture,

        // Complete frame events shared with delayed response analysis.
        capture: Http2Capture,

        // Monotonic origin used for event timestamps in both directions.
        started_at: Instant,
    }
}

impl<I> Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Wraps a TLS stream with bounded HTTP/2 frame capture.
    #[inline]
    pub fn new(inner: TlsStream<TlsInspector<I>>) -> Self {
        Self {
            inner,
            inbound: Http2WireCapture::client(),
            outbound: Http2WireCapture::server(),
            capture: Arc::new(boxcar::Vec::new()),
            started_at: Instant::now(),
        }
    }

    /// Returns shared storage for captured HTTP/2 frame events.
    #[inline]
    pub fn capture(&self) -> Http2Capture {
        self.capture.clone()
    }
}

impl<I> AsyncRead for Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf.filled().len();
        let this = self.project();
        let poll = this.inner.poll_read(cx, buf);
        let new_data = &buf.filled()[len..];
        if let Some(size) = this.inbound.inspect(
            new_data,
            Http2FrameDirection::ClientToServer,
            *this.started_at,
            this.capture,
        ) {
            this.outbound.set_max_header_table_size(size);
        }

        poll
    }
}

impl<I> AsyncWrite for Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this.inner.poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if let Some(written_bytes) = buf.get(..written) {
                    if let Some(size) = this.outbound.inspect(
                        written_bytes,
                        Http2FrameDirection::ServerToClient,
                        *this.started_at,
                        this.capture,
                    ) {
                        this.inbound.set_max_header_table_size(size);
                    }
                } else {
                    tracing::debug!(written, available = buf.len(), "invalid AsyncWrite result");
                }
                Poll::Ready(Ok(written))
            }
            poll => poll,
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use pingly::h2::{Frame, HTTP2_CLIENT_PREFACE};

    use super::{
        Http2CaptureBudget, Http2FrameDirection, Http2WireCapture, HTTP2_CAPTURE_MAX_BYTES,
        HTTP2_CAPTURE_MAX_FRAMES,
    };

    #[test]
    fn http2_capture_is_incremental_bidirectional_and_bounded() {
        let mut budget = Http2CaptureBudget::default();

        assert_eq!(
            budget.accept_bytes(HTTP2_CAPTURE_MAX_BYTES - 1),
            HTTP2_CAPTURE_MAX_BYTES - 1
        );
        assert_eq!(budget.accept_bytes(usize::MAX), 1);
        assert!(budget.byte_limit_reached());
        assert_eq!(budget.accept_bytes(1), 0);

        for _ in 0..HTTP2_CAPTURE_MAX_FRAMES {
            assert!(budget.admit_frame());
        }
        assert!(!budget.admit_frame());

        let events = boxcar::Vec::new();
        let started_at = Instant::now();
        let settings = [0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0];
        let mut client_bytes = HTTP2_CLIENT_PREFACE.to_vec();
        client_bytes.extend_from_slice(&settings);

        let mut client = Http2WireCapture::client();
        let mut header_table_size = None;
        for chunk in client_bytes.chunks(7) {
            header_table_size = client
                .inspect(
                    chunk,
                    Http2FrameDirection::ClientToServer,
                    started_at,
                    &events,
                )
                .or(header_table_size);
        }
        let mut server = Http2WireCapture::server();
        server.set_max_header_table_size(header_table_size.unwrap());
        let headers = [
            0, 0, 5, 0x01, 0x04, 0, 0, 0, 1, 0x3f, 0xe1, 0xff, 0x03, 0x88,
        ];
        let _ = server.inspect(
            &headers,
            Http2FrameDirection::ServerToClient,
            started_at,
            &events,
        );

        assert_eq!(events.count(), 2);
        assert!(matches!(
            events.get(0).map(|event| &event.frame),
            Some(Frame::Settings(_))
        ));
        assert_eq!(
            events.get(1).map(|event| event.direction),
            Some(Http2FrameDirection::ServerToClient)
        );
        assert!(matches!(
            events.get(1).map(|event| &event.frame),
            Some(Frame::Headers(_))
        ));
    }
}
