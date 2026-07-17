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
pub type Http2Frame = Arc<boxcar::Vec<Frame>>;

const HTTP2_CAPTURE_MAX_BYTES: usize = 1024 * 1024;
const HTTP2_CAPTURE_MAX_FRAMES: usize = 128;

#[derive(Default)]
struct Http2CaptureBudget {
    bytes: usize,

    frames: usize,

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

    #[inline]
    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// `Inspector` is an enum that wraps protocol-specific inspectors (such as `Http1Inspector` and
/// `Http2Inspector`) to provide a unified interface for inspecting and tracking different protocol
/// streams. Implements `AsyncRead` and `AsyncWrite` by delegating to the underlying
pub enum Inspector<S> {
    Http1(Http1Inspector<S>),
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
    /// A wrapper over a TLS stream that inspects TLS client hello messages.
    /// It buffers incoming data, parses the client hello message,
    /// and records the parsed client hello for later inspection or analysis.
    /// Does not interfere with normal stream reading or writing.
    pub struct TlsInspector<I> {
        #[pin]
        inner: I,

        client_hello: Option<ClientHelloBuffer>,
    }
}

impl<I> TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new [`TlsInspector`] instance.
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            client_hello: Some(ClientHelloBuffer::new()),
        }
    }

    /// Extracts and takes ownership of the buffered ClientHello payload,
    /// leaving `None` in its place.
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
        #[pin]
        inner: TlsStream<TlsInspector<I>>,

        // Request bytes retained until the head is complete or reaches its limit.
        capture: Option<Http1HeadBuffer>,

        // Completed raw head shared with response analysis.
        request_capture: Http1RequestCapture,
    }
}

impl<I> Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Creates a new [Http1Inspector] instance.
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
    /// A wrapper over a TLS stream that inspects HTTP/2 traffic.
    /// It buffers incoming data, parses HTTP/2 frames (including the connection preface),
    /// and records parsed frames for later inspection or analysis.
    /// Does not interfere with normal stream reading
    pub struct Http2Inspector<I> {
        #[pin]
        inner: TlsStream<TlsInspector<I>>,

        buf: Vec<u8>,

        frames: Http2Frame,

        parser: frame::FrameParser,

        capture_budget: Http2CaptureBudget,
    }
}

impl<I> Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new [`Http2Inspector`] instance.
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

    /// Get previously parsed HTTP/2 frames.
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

                    let headers_complete = matches!(frame, Some(Frame::Headers(_)));
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
    use super::{Http2CaptureBudget, HTTP2_CAPTURE_MAX_BYTES, HTTP2_CAPTURE_MAX_FRAMES};

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
}
