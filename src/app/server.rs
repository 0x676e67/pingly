//! Axum routes served through Hyper connections.
//!
//! Axum owns routing and middleware. Hyper serves accepted sockets. Pingora runtime scheduling is
//! kept in [`runtime`].

mod accept;
mod certificate;
mod handle;
pub(crate) mod routes;
mod tls;
mod tracker;

pub(crate) mod runtime;

pub(crate) use handle::Handle;
pub(crate) use tracker::accept::TrackAcceptor;

use std::{convert::Infallible, io, net::SocketAddr, path::Path, time::Duration};

use axum::{
    body::Body, extract::ConnectInfo, http::Request, middleware::AddExtension, response::Response,
    Router,
};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use pingora_runtime::current_handle;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tower::{Service, ServiceExt};

use self::{
    accept::{Accept, DefaultAcceptor},
    tls::rustls::RustlsAcceptor,
};
use crate::Result;

const MAX_HEADER_LIST_SIZE: usize = 8 * 1024;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

type ConnectInfoService = AddExtension<Router, ConnectInfo<SocketAddr>>;

/// HTTP accept loop for a concrete stream acceptor.
pub(crate) struct HttpServer<A = DefaultAcceptor> {
    listener: TcpListener,

    router: Router,

    acceptor: A,

    builder: Builder<TokioExecutor>,
}

impl HttpServer<DefaultAcceptor> {
    /// Binds the TCP listener and builds the shared Hyper connection settings.
    pub(crate) async fn new(
        bind: SocketAddr,
        router: Router,
        keep_alive_timeout: u64,
    ) -> Result<Self> {
        let mut builder = Builder::new(TokioExecutor::new());
        let keep_alive_timeout = Duration::from_secs(keep_alive_timeout);

        builder
            .http1()
            .max_buf_size(MAX_HEADER_LIST_SIZE)
            .timer(TokioTimer::new());
        let mut http2 = builder.http2();
        http2
            .max_header_list_size(MAX_HEADER_LIST_SIZE as _)
            .timer(TokioTimer::new())
            .auto_date_header(true);
        if !keep_alive_timeout.is_zero() {
            http2
                .keep_alive_interval(keep_alive_timeout)
                .keep_alive_timeout(keep_alive_timeout);
        }

        Ok(Self {
            listener: TcpListener::bind(bind).await?,
            router,
            acceptor: DefaultAcceptor,
            builder,
        })
    }

    /// Configures HTTPS from the supplied PEM files or a reusable self-signed certificate.
    pub(crate) fn with_rustls(
        self,
        files: Option<(&Path, &Path)>,
    ) -> Result<HttpServer<RustlsAcceptor>> {
        let config = match files {
            Some((cert, key)) => certificate::config_from_pem_chain_file(cert, key)?,
            None => certificate::config_self_signed()?,
        };

        Ok(self.map_acceptor(|_| RustlsAcceptor::new(config)))
    }
}

impl<A> HttpServer<A> {
    /// Replaces the stream acceptor while preserving the listener, router, and Hyper settings.
    pub(crate) fn map_acceptor<B>(self, map: impl FnOnce(A) -> B) -> HttpServer<B> {
        HttpServer {
            listener: self.listener,
            router: self.router,
            acceptor: map(self.acceptor),
            builder: self.builder,
        }
    }
}

impl<A> HttpServer<A>
where
    A: Accept<TcpStream, ConnectInfoService> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service:
        Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    <A::Service as Service<Request<Body>>>::Future: Send + 'static,
    A::Future: Send,
{
    /// Waits for the next TCP connection.
    ///
    /// Transient listener errors are logged and retried after a short backoff, matching the
    /// approach used by axum-server. This keeps a temporary accept failure from stopping the
    /// whole server; shutdown is handled by the `serve` select loop that polls this future.
    async fn accept(&self) -> (TcpStream, SocketAddr) {
        loop {
            match self.listener.accept().await {
                Ok(stream) => return stream,
                Err(error) => {
                    // axum-server retries transient listener accept errors after a short backoff.
                    // https://docs.rs/axum-server/0.8.0/src/axum_server/server.rs.html#370-376
                    tracing::warn!(%error, "failed to accept TCP connection");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
    }

    /// Runs the accept loop until graceful shutdown starts.
    ///
    /// Each accepted socket is configured, passed through the selected stream acceptor, and then
    /// served on a runtime worker. Per-connection accept and Hyper serve errors are logged in the
    /// spawned task instead of being returned, so one bad connection does not stop the server.
    pub(crate) async fn serve(self, handle: Handle) {
        loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => {
                    break;
                }
                accepted = self.accept() => {
                    let (stream, remote_addr) = accepted;
                    if let Err(error) = stream.set_nodelay(true) {
                        tracing::warn!(%error, %remote_addr, "failed to enable TCP_NODELAY");
                    }

                    let acceptor = self.acceptor.clone();
                    let builder = self.builder.clone();
                    let router = self.router.clone();
                    let handle = handle.clone();

                    // Pingora strategy: inside a no-steal runtime, `current_handle()` randomly
                    // selects a worker from the runtime pool.
                    // https://docs.rs/pingora-runtime/0.8.1/src/pingora_runtime/lib.rs.html#88-102
                    current_handle().spawn(async move {
                        let service = router
                            .into_make_service_with_connect_info::<SocketAddr>()
                            .oneshot(remote_addr)
                            .await
                            .unwrap_or_else(|error| match error {});

                        match acceptor.accept(stream, service).await {
                            Ok((stream, service)) => {
                                if let Err(error) = serve_connection(
                                    builder,
                                    stream,
                                    service,
                                    handle,
                                )
                                .await
                                {
                                    tracing::warn!(%error, %remote_addr, "failed to serve connection stream");
                                }
                            }
                            Err(error) => {
                                tracing::warn!(%error, %remote_addr, "failed to accept connection stream");
                            }
                        }
                    });
                }
            }
        }
    }
}

async fn serve_connection<I, S>(
    builder: Builder<TokioExecutor>,
    stream: I,
    service: S,
    handle: Handle,
) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let service = service.map_request(|request: Request<Incoming>| request.map(Body::new));
    let service = TowerToHyperService::new(service);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let mut shutting_down = false;

    loop {
        tokio::select! {
            result = connection.as_mut() => {
                return result.map_err(io::Error::other);
            }
            _ = handle.wait_graceful_shutdown(), if !shutting_down => {
                shutting_down = true;
                connection.as_mut().graceful_shutdown();
            }
        }
    }
}
