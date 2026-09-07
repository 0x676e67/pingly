//! TLS acceptor that selects an HTTP inspector from the negotiated ALPN protocol.
//!
//! HTTP/2 over TLS uses the `h2` protocol identifier defined by
//! [RFC 9113, Section 3.2](https://www.rfc-editor.org/rfc/rfc9113#section-3.2).

use std::{
    io,
    task::{Context, Poll},
    time::Instant,
};

use axum::http::Request;
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Service;

use super::{
    info::ConnectionTrack,
    inspector::{Http1Inspector, Http2Inspector, Inspector, TlsInspector},
};
use crate::server::{
    accept::{Accept, AcceptOutcome},
    tls::rustls::RustlsAcceptor,
};

/// Adds TLS, HTTP/1, and HTTP/2 capture to accepted HTTPS connections.
#[derive(Clone)]
pub struct TrackAcceptor(RustlsAcceptor);

impl TrackAcceptor {
    /// Wraps the TLS acceptor used by the server.
    pub fn new(acceptor: RustlsAcceptor) -> Self {
        Self(acceptor)
    }
}

/// Adds request-scoped connection metadata before Hyper starts polling the response future.
#[derive(Clone)]
pub struct TrackService<S> {
    /// Per-connection router service.
    inner: S,

    /// Metadata shared by requests accepted on this connection.
    connection_track: ConnectionTrack,
}

impl<S> TrackService<S> {
    fn new(inner: S, connection_track: ConnectionTrack) -> Self {
        Self {
            inner,
            connection_track,
        }
    }
}

impl<S, B> Service<Request<B>> for TrackService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let track = self.connection_track.claim_request(&request);
        request.extensions_mut().insert(track);
        self.inner.call(request)
    }
}

impl<I, S> Accept<I, S> for TrackAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = Inspector<I>;
    type Service = TrackService<S>;
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
                Some(b"h2") => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/2");
                    let inspector = Http2Inspector::new(stream);
                    connect_track.set_http2_capture(inspector.capture());
                    Inspector::Http2(inspector)
                }
                _ => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/1.1 or not set");
                    let inspector = Http1Inspector::new(stream);
                    connect_track.set_http1_request_capture(inspector.request_capture());
                    Inspector::Http1(inspector)
                }
            };

            Ok(AcceptOutcome::Serve {
                stream,
                service: TrackService::new(service, connect_track),
            })
        })
    }
}
