use std::{ops::Deref, pin::Pin, sync::Arc, task, task::Poll};

use bytes::Bytes;
use pin_project_lite::pin_project;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

use super::tls::TlsInspector;

pub type Http1Headers = Arc<boxcar::Vec<(Bytes, Bytes)>>;

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
