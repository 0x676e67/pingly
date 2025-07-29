#[macro_use]
mod macros;
mod enums;
mod hello;
mod parser;

use std::{pin::Pin, task, task::Poll};

pub use hello::{ClientHello, LazyClientHello};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

pin_project_lite::pin_project! {
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
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
