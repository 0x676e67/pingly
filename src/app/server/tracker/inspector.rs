//! Stream adapters that retain protocol bytes for delayed analysis.
//!
//! Each adapter forwards reads and writes unchanged. Capture work on the I/O path is limited to
//! bounded buffering and incremental framing.

use std::{
    ops::Deref,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{self, Poll},
};

use pin_project_lite::pin_project;
pub use pingly::tls::{ClientHello, ClientHelloBuffer};
use pingly::{
    h1::Http1HeadBuffer,
    h2::{frame, frame::Frame, HTTP2_CLIENT_PREFACE},
};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

/// Shared storage for one raw HTTP/1 request head.
pub type Http1RequestCapture = Arc<OnceLock<Http1HeadBuffer>>;

/// Concurrent storage for HTTP/2 frames captured from one connection.
pub type Http2Frame = Arc<boxcar::Vec<Frame>>;

const HTTP2_CAPTURE_MAX_BYTES: usize = 1024 * 1024;
const HTTP2_CAPTURE_MAX_FRAMES: usize = 128;
const HTTP2_CAPTURE_MAX_HEADER_BLOCKS: usize = 2;

#[derive(Default)]
struct Http2CaptureBudget {
    /// Number of client bytes admitted to the capture buffer.
    bytes: usize,

    /// Number of complete wire frames observed.
    frames: usize,

    /// Number of complete HEADERS field sections observed.
    header_blocks: usize,

    /// Whether this connection no longer needs inspection.
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

    /// Records one complete wire frame and reports whether capture may continue.
    fn record_frame(&mut self) -> bool {
        if self.frames < HTTP2_CAPTURE_MAX_FRAMES {
            self.frames += 1;
        }
        self.frames < HTTP2_CAPTURE_MAX_FRAMES
    }

    /// Allows the UI warm-up request before the WebSocket Extended CONNECT field section.
    ///
    /// The warm-up gives the browser an HTTP/2 connection to reuse for the WebSocket stream.
    fn record_header_block(&mut self) -> bool {
        self.header_blocks = self.header_blocks.saturating_add(1);
        self.header_blocks >= HTTP2_CAPTURE_MAX_HEADER_BLOCKS
    }

    #[inline]
    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// HTTP stream selected after TLS ALPN negotiation.
///
/// Both variants implement [`AsyncRead`] and [`AsyncWrite`] by forwarding operations to their
/// wrapped TLS stream.
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
    /// TLS stream wrapper that captures the initial HTTP/2 client frame sequence.
    ///
    /// Capture stops after an Extended CONNECT or the second complete HEADERS block. Byte and
    /// frame limits provide the remaining bounds. Reads and writes continue normally afterward.
    pub struct Http2Inspector<I> {
        // TLS stream forwarded to Hyper.
        #[pin]
        inner: TlsStream<TlsInspector<I>>,

        // Bytes waiting for a complete preface or frame.
        buf: Vec<u8>,

        // Complete client frames shared with response analysis.
        frames: Http2Frame,

        // Stateful frame and HPACK decoder.
        parser: frame::FrameParser,

        // Per-connection bounds for capture work and retained data.
        capture_budget: Http2CaptureBudget,
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
            buf: Vec::new(),
            frames: Arc::new(boxcar::Vec::new()),
            parser: frame::FrameParser::default(),
            capture_budget: Http2CaptureBudget::default(),
        }
    }

    /// Returns shared storage for captured HTTP/2 frames.
    #[inline]
    pub fn frames(&self) -> Http2Frame {
        self.frames.clone()
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

        if !this.capture_budget.is_active() {
            return poll;
        }

        let new_data = &buf.filled()[len..];
        let inspected_len = this.capture_budget.accept_bytes(new_data.len());
        this.buf.extend_from_slice(&new_data[..inspected_len]);
        let byte_limit_reached = this.capture_budget.byte_limit_reached();
        let mut stop_capture = false;

        let plen = HTTP2_CLIENT_PREFACE.len();
        let not_http2 = this.buf.len() >= plen && !this.buf.starts_with(HTTP2_CLIENT_PREFACE);
        if not_http2 {
            stop_capture = true;
        } else {
            let frames = this.frames.deref();
            while this.buf.len() > plen {
                let (frame_len, frame) = match this.parser.parse(&this.buf[plen..]) {
                    Ok(parsed) => (parsed.consumed(), parsed.into_frame()),
                    Err(error) => {
                        tracing::debug!(?error, "failed to parse HTTP/2 frame");
                        (error.consumed, None)
                    }
                };
                if frame_len > 0 {
                    this.buf.drain(plen..plen + frame_len);
                    if !this.capture_budget.record_frame() {
                        stop_capture = true;
                    }

                    let headers_complete = match frame.as_ref() {
                        Some(Frame::Headers(headers)) => {
                            let limit_reached = this.capture_budget.record_header_block();
                            headers.is_extended_connect(b"websocket") || limit_reached
                        }
                        _ => false,
                    };
                    if let Some(frame) = frame {
                        frames.push(frame);
                    }
                    if headers_complete {
                        stop_capture = true;
                    }
                    if stop_capture {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        if stop_capture || byte_limit_reached {
            this.capture_budget.stop();
            *this.buf = Vec::new();
            *this.parser = frame::FrameParser::default();
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

#[cfg(test)]
mod tests {
    use super::{
        Http2CaptureBudget, HTTP2_CAPTURE_MAX_BYTES, HTTP2_CAPTURE_MAX_FRAMES,
        HTTP2_CAPTURE_MAX_HEADER_BLOCKS,
    };

    #[test]
    fn http2_capture_budget_caps_cumulative_bytes() {
        let mut budget = Http2CaptureBudget::default();

        assert_eq!(
            budget.accept_bytes(HTTP2_CAPTURE_MAX_BYTES - 1),
            HTTP2_CAPTURE_MAX_BYTES - 1
        );
        assert_eq!(budget.accept_bytes(usize::MAX), 1);
        assert!(budget.byte_limit_reached());
        assert_eq!(budget.accept_bytes(1), 0);
    }

    #[test]
    fn http2_capture_budget_caps_wire_frames() {
        let mut budget = Http2CaptureBudget::default();

        for _ in 1..HTTP2_CAPTURE_MAX_FRAMES {
            assert!(budget.record_frame());
        }
        assert!(!budget.record_frame());
        assert!(!budget.record_frame());
    }

    #[test]
    fn http2_capture_budget_allows_a_warm_up_header_block() {
        let mut budget = Http2CaptureBudget::default();

        for _ in 1..HTTP2_CAPTURE_MAX_HEADER_BLOCKS {
            assert!(!budget.record_header_block());
        }
        assert!(budget.record_header_block());
    }
}
