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

pub use crate::http2::Http2Frame;
use crate::http2::{frame, frame::Frame};
pub use crate::tls::{ClientHello, LazyClientHello};

pub type Http1Headers = Arc<boxcar::Vec<(Bytes, Bytes)>>;

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

        let plen = HTTP2_PREFACE.len();
        let not_http2 = this.buf.len() >= plen && !this.buf.starts_with(HTTP2_PREFACE);
        if !not_http2 {
            this.buf.extend(&buf.filled()[len..]);
            let frames = this.frames.deref();
            while this.buf.len() > plen {
                let last = frames.iter().last().map(|f| f.1);
                if matches!(last, Some(Frame::Headers(_))) {
                    break;
                }
                let (frame_len, frame) = frame::parse(&this.buf[plen..]);
                if frame_len > 0 {
                    this.buf.drain(plen..plen + frame_len);
                    if let Some(frame) = frame {
                        frames.push(frame);
                    }
                } else {
                    break;
                }
            }
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
