mod http1;
mod http2;
mod tls;

use std::{pin::Pin, task, task::Poll};

pub use http1::{Http1Headers, Http1Inspector};
pub use http2::{frame::Frame, Http2Frame, Http2Inspector};
pub use tls::{ClientHello, TlsInspector};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

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
