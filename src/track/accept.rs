use std::io;

use axum::{middleware::AddExtension, Extension};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;

use super::{ConnectionTrack, Http2Inspector, TlsInspector};
use crate::track::inspector::{Http1Inspector, Inspector};

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
    type Stream = Inspector<I>;
    type Service = AddExtension<S, ConnectionTrack>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.0.clone();
        Box::pin(async move {
            let (mut stream, service) = acceptor.accept(TlsInspector::new(stream), service).await?;
            // Create a new ConnectTrack instance
            let mut connect_track = ConnectionTrack::default();
            connect_track.set_client_hello(stream.get_mut().0.client_hello());

            // Check the ALPN protocol and create the appropriate inspector
            let stream = match stream.get_ref().1.alpn_protocol() {
                // If ALPN is set to HTTP/2, use Http2Inspector
                Some(b"h2") => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/2");
                    let inspector = Http2Inspector::new(stream);
                    connect_track.set_http2_frames(inspector.frames());
                    Inspector::Http2(inspector)
                }
                //  If ALPN is not set, default to HTTP/1.1
                Some(b"http/1.1") | _ => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/1.1 or not set");
                    let inspector = Http1Inspector::new(stream);
                    connect_track.set_http1_headers(inspector.headers());
                    Inspector::Http1(inspector)
                }
            };

            let service = Extension(connect_track).layer(service);
            Ok((stream, service))
        })
    }
}
