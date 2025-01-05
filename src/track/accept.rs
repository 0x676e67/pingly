use super::{ConnectTrack, Http2Inspector, TlsInspector};
use axum::middleware::AddExtension;
use axum::Extension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use futures_util::future::BoxFuture;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;

#[derive(Clone)]
pub struct TrackAcceptor(RustlsAcceptor);

impl TrackAcceptor {
    pub fn new(acceptor: RustlsAcceptor) -> Self {
        Self(acceptor)
    }
}

impl<I, S> Accept<I, S> for TrackAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = Http2Inspector<I>;
    type Service = AddExtension<S, ConnectTrack>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.0.clone();
        Box::pin(async move {
            let (mut stream, service) = acceptor.accept(TlsInspector::new(stream), service).await?;
            let client_hello = stream.get_mut().0.client_hello();

            let stream = Http2Inspector::new(stream);
            let http2_frames = stream.frames();

            let track = ConnectTrack::new(client_hello, http2_frames);
            let service = Extension(track).layer(service);

            Ok((stream, service))
        })
    }
}
