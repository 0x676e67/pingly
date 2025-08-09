pub mod frame;

use std::{ops::Deref, pin::Pin, sync::Arc, task, task::Poll};

use frame::Frame;
use pin_project_lite::pin_project;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

use super::tls::TlsInspector;

pub type Http2Frame = Arc<boxcar::Vec<Frame>>;

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
