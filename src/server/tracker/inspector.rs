use std::{
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::Bytes;
use pin_project_lite::pin_project;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

pub use crate::proto::http2::Http2Frame;
use crate::proto::http2::{frame, frame::Frame};
pub use crate::proto::tls::{ClientHello, LazyClientHello};

pub type Http1Headers = Arc<boxcar::Vec<(Bytes, Bytes)>>;

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
        client_hello: Option<LazyClientHello>,
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
            client_hello: Some(LazyClientHello::new()),
        }
    }

    /// Extracts and takes ownership of the buffered ClientHello payload,
    /// leaving `None` in its place.
    #[inline]
    #[must_use]
    pub fn client_hello(&mut self) -> Option<LazyClientHello> {
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
            if !client_hello.is_max_record_len() {
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
    /// A wrapper over a TLS stream that inspects HTTP/1.x traffic.
    /// It buffers incoming data, parses HTTP/1 request headers,
    /// and records parsed headers for later inspection or analysis.
    /// Does not interfere with normal stream reading or writing.
    pub struct Http1Inspector<I> {
        #[pin]
        inner: TlsStream<TlsInspector<I>>,
        buf: Vec<u8>,
        headers: Http1Headers,
    }
}

impl<I> Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new [`Http1Inspector`] instance.
    #[inline]
    pub fn new(inner: TlsStream<TlsInspector<I>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            headers: Arc::new(boxcar::Vec::new()),
        }
    }

    /// Get previously parsed HTTP/1 headers
    #[inline]
    pub fn headers(&self) -> Http1Headers {
        self.headers.clone()
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

        // Only process new data
        let new_data = &buf.filled()[prev_len..];
        if !new_data.is_empty() {
            this.buf.extend_from_slice(new_data);
            // Try to parse headers
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            if let Ok(httparse::Status::Complete(_header_len)) = req.parse(this.buf) {
                let headers = this.headers.deref();
                for h in req.headers.iter() {
                    headers.push((
                        Bytes::from(h.name.to_owned()),
                        Bytes::copy_from_slice(h.value),
                    ));
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
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

        let plen = HTTP2_PREFACE.len();
        let not_http2 = this.buf.len() >= plen && !this.buf.starts_with(HTTP2_PREFACE);
        if not_http2 {
            stop_capture = true;
        } else {
            let frames = this.frames.deref();
            while this.buf.len() > plen {
                let (frame_len, frame) = this.parser.parse(&this.buf[plen..]);
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
