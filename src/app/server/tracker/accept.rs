use std::{io, time::Instant};

use axum::{middleware::AddExtension, Extension};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Layer;

use super::{
    info::ConnectionTrack,
    inspector::{Http1Inspector, Http2Inspector, Inspector, TlsInspector},
};
use crate::server::{
    accept::{Accept, AcceptOutcome},
    tls::rustls::RustlsAcceptor,
};

/// TrackAcceptor is a wrapper around RustlsAcceptor that inspects incoming TLS connections,
/// automatically detects the negotiated ALPN protocol (such as HTTP/1.1 or HTTP/2),
/// and wraps the stream with the appropriate Inspector type (Http1Inspector or Http2Inspector).
#[derive(Clone)]
pub struct TrackAcceptor(RustlsAcceptor);

impl TrackAcceptor {
    /// Create a new [`TrackAcceptor`] with the provided RustlsAcceptor.
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
    type Future = BoxFuture<'static, io::Result<AcceptOutcome<Self::Stream, Self::Service>>>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.0.clone();
        Box::pin(async move {
            let handshake_started = Instant::now();
            let (mut stream, service) =
                match acceptor.accept(TlsInspector::new(stream), service).await? {
                    AcceptOutcome::Serve { stream, service } => (stream, service),
                    AcceptOutcome::Handled => return Ok(AcceptOutcome::Handled),
                };
            let mut connect_track = ConnectionTrack::default();
            connect_track.set_tls_handshake_duration(handshake_started.elapsed());
            connect_track.set_client_hello(stream.get_mut().0.client_hello());
            connect_track.set_tls_version_negotiated(stream.get_ref().1.protocol_version());

            let stream = match stream.get_ref().1.alpn_protocol() {
                // If ALPN is set to HTTP/2, use Http2Inspector
                Some(b"h2") => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/2");
                    let inspector = Http2Inspector::new(stream);
                    connect_track.set_http2_frames(inspector.frames());
                    Inspector::Http2(inspector)
                }
                //  If ALPN is not set, default to HTTP/1.1
                _ => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/1.1 or not set");
                    let inspector = Http1Inspector::new(stream);
                    connect_track.set_http1_request_capture(inspector.request_capture());
                    Inspector::Http1(inspector)
                }
            };

            Ok(AcceptOutcome::Serve {
                stream,
                service: Extension(connect_track).layer(service),
            })
        })
    }
}
