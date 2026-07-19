//! Axum routes served through coordinated HTTP/1, HTTP/2, and HTTP/3 listeners.
//!
//! Axum owns routing and middleware. Hyper serves TCP connections, while h3 and Quinn serve QUIC
//! connections. Pingora runtime scheduling is kept in [`runtime`].

mod accept;
mod certificate;
mod handle;
mod tls;
mod tracker;

pub(crate) mod routes;
pub(crate) mod runtime;

use std::{convert::Infallible, io, net::SocketAddr, time::Duration};

use axum::{body::Body, http::Request, response::Response, Router};
use pingora_runtime::current_handle;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    task::JoinError,
};
use tower::Service;

use self::{
    accept::{Accept, DefaultAcceptor},
    tcp::ConnectInfoService,
};
pub(crate) use self::{
    handle::Handle,
    tls::{acme::AcmeRuntime, rustls::RustlsAcceptor},
    tracker::accept::TrackAcceptor,
};
use crate::Result;

const MAX_HEADER_LIST_SIZE: usize = 8 * 1024;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Coordinates the TCP HTTP/1 and HTTP/2 listener with an optional UDP HTTP/3 listener.
pub(crate) struct HttpServer<A = RustlsAcceptor> {
    /// TCP listener accepting HTTP/1 and HTTP/2 connections.
    tcp_listener: TcpListener,
    /// Application routes shared by every HTTP version.
    router: Router,
    /// Adapter responsible for plain TCP or TLS setup and request inspection.
    acceptor: A,
    /// Hyper connection settings shared by accepted TCP streams.
    tcp_builder: tcp::ConnectionBuilder,
    /// Whether one response should gracefully close its underlying connection.
    close_after_first_request: bool,
    /// Optional QUIC endpoint serving HTTP/3 on the matching port.
    quic_endpoint: Option<quinn::Endpoint>,
}

enum ListenerExit {
    Tcp(std::result::Result<(), JoinError>),
    Quic(std::result::Result<Result<()>, JoinError>),
}

impl HttpServer<RustlsAcceptor> {
    /// Construct a new [`HttpServer<RustlsAcceptor>`].
    pub(crate) async fn new(
        bind: SocketAddr,
        keep_alive_timeout: u64,
        acceptor: RustlsAcceptor,
        router: Router,
    ) -> Result<Self> {
        let rustls = acceptor.default_config();
        let mut server = Self::bind_tcp(bind, router, keep_alive_timeout, acceptor).await?;
        server.quic_endpoint = Some(quic::bind(server.tcp_listener.local_addr()?, rustls)?);
        Ok(server)
    }

    /// Construct a new [`HttpServer<DefaultAcceptor>`].
    pub(crate) async fn new_plain(
        bind: SocketAddr,
        router: Router,
        keep_alive_timeout: u64,
    ) -> Result<HttpServer<DefaultAcceptor>> {
        HttpServer::bind_tcp(bind, router, keep_alive_timeout, DefaultAcceptor).await
    }
}

impl<A> HttpServer<A> {
    async fn bind_tcp(
        bind: SocketAddr,
        router: Router,
        keep_alive_timeout: u64,
        acceptor: A,
    ) -> Result<Self> {
        let (tcp_builder, close_after_first_request) = tcp::connection_builder(keep_alive_timeout);
        let tcp_listener = bind_tcp_listener(bind).await?;
        Ok(Self {
            tcp_listener,
            router,
            acceptor,
            tcp_builder,
            close_after_first_request,
            quic_endpoint: None,
        })
    }

    pub(crate) fn map_acceptor<B>(self, map: impl FnOnce(A) -> B) -> HttpServer<B> {
        HttpServer {
            tcp_listener: self.tcp_listener,
            router: self.router,
            acceptor: map(self.acceptor),
            tcp_builder: self.tcp_builder,
            close_after_first_request: self.close_after_first_request,
            quic_endpoint: self.quic_endpoint,
        }
    }
}

async fn bind_tcp_listener(bind: SocketAddr) -> Result<TcpListener> {
    if bind.is_ipv4() {
        return Ok(TcpListener::bind(bind).await?);
    }

    bind_ipv6_tcp(bind).map_err(Into::into)
}

/// The IPv6 wildcard opts into IPv4-mapped connections; concrete addresses do not.
///
/// https://www.rfc-editor.org/rfc/rfc3493#section-5.3
fn bind_ipv6_tcp(bind: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(!bind.ip().is_unspecified())?;
    socket.bind(&bind.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;

    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
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
    pub(crate) async fn serve(self, handle: Handle) -> Result<()> {
        let Self {
            tcp_listener,
            router,
            acceptor,
            tcp_builder,
            close_after_first_request,
            quic_endpoint,
        } = self;

        let Some(quic_endpoint) = quic_endpoint else {
            tcp::serve(
                tcp_listener,
                router,
                acceptor,
                tcp_builder,
                close_after_first_request,
                handle,
            )
            .await;
            return Ok(());
        };

        let mut tcp_task = current_handle().spawn(tcp::serve(
            tcp_listener,
            router.clone(),
            acceptor,
            tcp_builder,
            close_after_first_request,
            handle.clone(),
        ));

        let mut quic_task = current_handle().spawn(quic::serve(
            quic_endpoint,
            router,
            close_after_first_request,
            handle.clone(),
        ));

        let first_exit = tokio::select! {
            result = &mut tcp_task => ListenerExit::Tcp(result),
            result = &mut quic_task => ListenerExit::Quic(result),
        };

        // A listener stopping unexpectedly must also stop its sibling. This avoids continuing to
        // advertise HTTP/3 after the UDP endpoint has failed and gives both protocols time to
        // drain.
        handle.request_graceful_shutdown();
        let (tcp_result, quic_result) = match first_exit {
            ListenerExit::Tcp(result) => (result, quic_task.await),
            ListenerExit::Quic(result) => (tcp_task.await, result),
        };

        tcp_result?;
        quic_result??;
        Ok(())
    }
}

mod tcp {
    //! HTTP/1 and HTTP/2 service over TCP.

    use std::{convert::Infallible, io, net::SocketAddr, time::Duration};

    use axum::{
        body::Body, extract::ConnectInfo, http::Request, middleware::AddExtension,
        response::Response, Router,
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
        sync::watch,
        task::{JoinError, JoinSet},
        time::timeout,
    };
    use tower::{Service, ServiceExt};

    use super::{
        accept::{Accept, AcceptOutcome},
        Handle, ACCEPT_ERROR_BACKOFF, MAX_HEADER_LIST_SIZE,
    };

    const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

    pub(super) type ConnectionBuilder = Builder<TokioExecutor>;
    pub(super) type ConnectInfoService = AddExtension<Router, ConnectInfo<SocketAddr>>;

    /// Builds the shared Hyper settings for HTTP/1 and HTTP/2 connections.
    pub(super) fn connection_builder(keep_alive_timeout: u64) -> (ConnectionBuilder, bool) {
        let mut builder = Builder::new(TokioExecutor::new());
        let keep_alive_interval = Duration::from_secs(keep_alive_timeout);
        let close_after_first_request = keep_alive_interval.is_zero();

        builder
            .http1()
            .timer(TokioTimer::new())
            .keep_alive(!close_after_first_request)
            .max_buf_size(MAX_HEADER_LIST_SIZE);

        let mut http2 = builder.http2();
        http2
            .timer(TokioTimer::new())
            .auto_date_header(true)
            .max_header_list_size(MAX_HEADER_LIST_SIZE as _);

        if close_after_first_request {
            http2.keep_alive_interval(None).max_concurrent_streams(1);
        } else {
            http2
                .keep_alive_interval(Some(keep_alive_interval))
                .keep_alive_timeout(keep_alive_interval);
        }

        (builder, close_after_first_request)
    }

    /// Waits for the next TCP connection.
    ///
    /// Transient listener errors are logged and retried after a short backoff, matching the
    /// approach used by axum-server. This keeps a temporary accept failure from stopping the
    /// whole server; shutdown is handled by the serve select loop that polls this future.
    async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
        loop {
            match listener.accept().await {
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

    /// Runs the HTTP/1 and HTTP/2 accept loop until graceful shutdown starts.
    pub(super) async fn serve<A>(
        listener: TcpListener,
        router: Router,
        acceptor: A,
        builder: ConnectionBuilder,
        close_after_first_request: bool,
        handle: Handle,
    ) where
        A: Accept<TcpStream, ConnectInfoService> + Clone + Send + Sync + 'static,
        A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        A::Service: Service<Request<Body>, Response = Response, Error = Infallible>
            + Clone
            + Send
            + 'static,
        <A::Service as Service<Request<Body>>>::Future: Send + 'static,
        A::Future: Send,
    {
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => break,
                finished = connections.join_next(), if !connections.is_empty() => {
                    if let Some(result) = finished {
                        log_connection_task(result);
                    }
                }
                accepted = accept(&listener) => {
                    let (stream, remote_addr) = accepted;
                    if let Err(error) = stream.set_nodelay(true) {
                        tracing::warn!(%error, %remote_addr, "failed to enable TCP_NODELAY");
                    }

                    let acceptor = acceptor.clone();
                    let builder = builder.clone();
                    let router = router.clone();
                    let connection_handle = handle.clone();

                    // Pingora strategy: inside a no-steal runtime, `current_handle()` randomly
                    // selects a worker from the runtime pool.
                    // https://docs.rs/pingora-runtime/0.8.1/src/pingora_runtime/lib.rs.html#88-102
                    connections.spawn_on(async move {
                        let service = router
                            .into_make_service_with_connect_info::<SocketAddr>()
                            .oneshot(remote_addr)
                            .await
                            .unwrap_or_else(|error| match error {});

                        match acceptor.accept(stream, service).await {
                            Ok(AcceptOutcome::Serve { stream, service }) => {
                                if let Err(error) = serve_connection(
                                    builder,
                                    stream,
                                    service,
                                    connection_handle,
                                    close_after_first_request,
                                )
                                .await
                                {
                                    tracing::debug!(%error, %remote_addr, "failed to serve connection stream");
                                }
                            }
                            Ok(AcceptOutcome::Handled) => {}
                            Err(error) => {
                                tracing::debug!(%error, %remote_addr, "failed to accept connection stream");
                            }
                        }
                    }, &current_handle());
                }
            }
        }

        if timeout(
            CONNECTION_DRAIN_TIMEOUT,
            drain_connection_tasks(&mut connections),
        )
        .await
        .is_err()
        {
            tracing::debug!("HTTP/1 and HTTP/2 connection drain timed out");
            connections.abort_all();
            drain_connection_tasks(&mut connections).await;
        }
    }

    async fn serve_connection<I, S>(
        builder: Builder<TokioExecutor>,
        stream: I,
        service: S,
        handle: Handle,
        close_after_first_request: bool,
    ) -> io::Result<()>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
        S::Future: Send + 'static,
    {
        let (first_request_tx, mut first_request_rx) = if close_after_first_request {
            let (sender, receiver) = watch::channel(false);
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let service = service.map_request(move |request: Request<Incoming>| {
            if let Some(sender) = first_request_tx.as_ref() {
                sender.send_replace(true);
            }
            request.map(Body::new)
        });
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
                _ = wait_for_first_request(&mut first_request_rx),
                    if close_after_first_request && !shutting_down =>
                {
                    shutting_down = true;
                    connection.as_mut().graceful_shutdown();
                }
            }
        }
    }

    async fn wait_for_first_request(receiver: &mut Option<watch::Receiver<bool>>) {
        let Some(receiver) = receiver.as_mut() else {
            std::future::pending::<()>().await;
            return;
        };

        let first_request_seen = *receiver.borrow_and_update();
        if !first_request_seen {
            let _ = receiver.changed().await;
        }
    }

    async fn drain_connection_tasks(connections: &mut JoinSet<()>) {
        while let Some(result) = connections.join_next().await {
            log_connection_task(result);
        }
    }

    fn log_connection_task(result: std::result::Result<(), JoinError>) {
        if let Err(error) = result {
            if !error.is_cancelled() {
                tracing::debug!(%error, "HTTP/1 or HTTP/2 connection task failed");
            }
        }
    }
}

mod quic {
    //! HTTP/3 service over Quinn with decrypted-stream fingerprint capture.

    pub mod crypto;
    pub mod inspect;

    use std::{
        convert::Infallible,
        error::Error as StdError,
        io,
        net::{SocketAddr, UdpSocket},
        sync::{Arc, OnceLock},
        time::Duration,
    };

    use axum::{
        body::Body,
        http::{Request, Response},
        Router,
    };
    use bytes::Bytes;
    use h3::error::Code;
    use http_body_util::BodyExt;
    use pingly::tls::ClientHelloHandshakeBuffer;
    use pingora_runtime::current_handle;
    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::{
        task::{JoinError, JoinSet},
        time::timeout,
    };
    use tokio_rustls::rustls::{ProtocolVersion, ServerConfig};
    use tower::{Service, ServiceExt};

    use self::{
        crypto::HandshakeData,
        inspect::{Http3Capture, InspectedBidiStream, InspectedConnection},
    };
    use super::{tracker::info::ConnectionTrack, Handle, MAX_HEADER_LIST_SIZE};
    use crate::Result;

    type Http3Connection = h3::server::Connection<InspectedConnection, Bytes>;
    type RequestStream = h3::server::RequestStream<InspectedBidiStream<Bytes>, Bytes>;
    type RequestResolver = h3::server::RequestResolver<InspectedConnection, Bytes>;
    type BoxError = Box<dyn StdError + Send + Sync>;

    const SETTINGS_CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const CONNECTION_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
    const SERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

    // HTTP/3 application error codes are carried as QUIC variable-length integers.
    // https://www.rfc-editor.org/rfc/rfc9114#section-8.1
    const H3_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x100);

    /// Binds a QUIC endpoint with H3 ALPN and ClientHello capture.
    pub(super) fn bind(bind: SocketAddr, rustls: Arc<ServerConfig>) -> Result<quinn::Endpoint> {
        let config = crypto::server_config((*rustls).clone())?;
        if bind.is_ipv6() {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(!bind.ip().is_unspecified())?;
            socket.bind(&bind.into())?;
            socket.set_nonblocking(true)?;

            let socket: UdpSocket = socket.into();
            return Ok(quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(config),
                socket,
                Arc::new(quinn::TokioRuntime),
            )?);
        }

        Ok(quinn::Endpoint::server(config, bind)?)
    }

    /// Accepts QUIC connections until graceful shutdown starts.
    pub(super) async fn serve(
        endpoint: quinn::Endpoint,
        router: Router,
        close_after_first_request: bool,
        handle: Handle,
    ) -> Result<()> {
        let mut connections = JoinSet::new();

        let endpoint_closed = loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => break false,
                finished = connections.join_next(), if !connections.is_empty() => {
                    if let Some(result) = finished {
                        log_connection_task(result);
                    }
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break true;
                    };
                    let remote_addr = incoming.remote_address();
                    let router = router.clone();
                    let connection_handle = handle.clone();

                    connections.spawn_on(async move {
                        let accepted = tokio::select! {
                            _ = connection_handle.wait_graceful_shutdown() => return,
                            accepted = incoming => accepted,
                        };

                        match accepted {
                            Ok(connection) => {
                                serve_connection(
                                    connection,
                                    remote_addr,
                                    router,
                                    connection_handle,
                                    close_after_first_request,
                                )
                                .await;
                            }
                            Err(error) => {
                                tracing::debug!(%error, %remote_addr, "failed to accept QUIC connection");
                            }
                        }
                    }, &current_handle());
                }
            }
        };

        if endpoint_closed {
            handle.request_graceful_shutdown();
        }

        endpoint.set_server_config(None);
        if timeout(
            SERVER_DRAIN_TIMEOUT,
            drain_connection_tasks(&mut connections),
        )
        .await
        .is_err()
        {
            tracing::debug!("HTTP/3 connection drain timed out");
            endpoint.close(H3_NO_ERROR, b"server shutdown timeout");
            connections.abort_all();
            drain_connection_tasks(&mut connections).await;
        } else {
            endpoint.close(H3_NO_ERROR, b"server shutdown");
        }
        endpoint.wait_idle().await;

        if endpoint_closed {
            return Err(io::Error::other("HTTP/3 endpoint closed unexpectedly").into());
        }
        Ok(())
    }

    async fn serve_connection(
        connection: quinn::Connection,
        remote_addr: SocketAddr,
        router: Router,
        handle: Handle,
        close_after_first_request: bool,
    ) {
        let transport = connection.clone();
        let client_hello = connection
            .handshake_data()
            .and_then(|data| data.downcast::<HandshakeData>().ok())
            .map(|data| data.client_hello());

        let capture = Http3Capture::new();
        let inspected =
            InspectedConnection::new(h3_quinn::Connection::new(connection), capture.clone());
        let mut builder = h3::server::builder();
        builder.max_field_section_size(MAX_HEADER_LIST_SIZE as u64);
        let connection = match builder.build(inspected).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::debug!(%error, %remote_addr, "failed to initialize HTTP/3 connection");
                return;
            }
        };
        let service = router
            .into_make_service_with_connect_info::<SocketAddr>()
            .oneshot(remote_addr)
            .await
            .unwrap_or_else(|error| match error {});

        if close_after_first_request {
            serve_single_request_connection(
                connection,
                transport,
                remote_addr,
                service,
                capture,
                client_hello,
                handle,
            )
            .await;
        } else {
            serve_reusable_connection(
                connection,
                transport,
                remote_addr,
                service,
                capture,
                client_hello,
                handle,
            )
            .await;
        }
    }

    async fn serve_single_request_connection<S>(
        mut connection: Http3Connection,
        transport: quinn::Connection,
        remote_addr: SocketAddr,
        service: S,
        capture: Http3Capture,
        client_hello: Option<Arc<OnceLock<ClientHelloHandshakeBuffer>>>,
        handle: Handle,
    ) where
        S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        let accepted = tokio::select! {
            _ = handle.wait_graceful_shutdown() => {
                begin_connection_shutdown(&mut connection, remote_addr).await;
                wait_for_peer_close(&mut connection, &transport, remote_addr).await;
                return;
            }
            accepted = connection.accept() => accepted,
        };
        let resolver = match accepted {
            Ok(Some(resolver)) => resolver,
            Ok(None) => return,
            Err(error) => {
                tracing::debug!(%error, %remote_addr, "failed to accept HTTP/3 request");
                return;
            }
        };

        // GOAWAY identifies the first request stream that will not be processed. A zero grace count
        // keeps the accepted stream valid while rejecting every later request stream.
        // https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        begin_connection_shutdown(&mut connection, remote_addr).await;

        let request = serve_request(resolver, remote_addr, service, capture, client_hello);
        tokio::pin!(request);

        loop {
            tokio::select! {
                _ = request.as_mut() => break,
                accepted = connection.accept() => {
                    match accepted {
                        Ok(Some(_)) => {
                            tracing::trace!(%remote_addr, "discarded HTTP/3 request after GOAWAY");
                        }
                        Ok(None) => {
                            request.as_mut().await;
                            break;
                        }
                        Err(error) => {
                            tracing::debug!(%error, %remote_addr, "HTTP/3 connection ended while serving request");
                            request.as_mut().await;
                            break;
                        }
                    }
                }
            }
        }

        wait_for_peer_close(&mut connection, &transport, remote_addr).await;
    }

    async fn serve_reusable_connection<S>(
        mut connection: Http3Connection,
        transport: quinn::Connection,
        remote_addr: SocketAddr,
        service: S,
        capture: Http3Capture,
        client_hello: Option<Arc<OnceLock<ClientHelloHandshakeBuffer>>>,
        handle: Handle,
    ) where
        S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        let mut requests = JoinSet::new();
        let graceful = loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => {
                    begin_connection_shutdown(&mut connection, remote_addr).await;
                    break true;
                }
                finished = requests.join_next(), if !requests.is_empty() => {
                    if let Some(result) = finished {
                        log_request_task(result, remote_addr);
                    }
                }
                accepted = connection.accept() => {
                    let resolver = match accepted {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) => break false,
                        Err(error) => {
                            tracing::debug!(%error, %remote_addr, "failed to accept HTTP/3 request");
                            break false;
                        }
                    };

                    requests.spawn_on(
                        serve_request(
                            resolver,
                            remote_addr,
                            service.clone(),
                            capture.clone(),
                            client_hello.clone(),
                        ),
                        &current_handle(),
                    );
                }
            }
        };

        if graceful {
            if timeout(
                CONNECTION_DRAIN_TIMEOUT,
                drain_requests_while_driving(&mut connection, &mut requests, remote_addr),
            )
            .await
            .is_err()
            {
                tracing::debug!(%remote_addr, "HTTP/3 request drain timed out");
                requests.abort_all();
                drain_request_tasks(&mut requests, remote_addr).await;
            }

            wait_for_peer_close(&mut connection, &transport, remote_addr).await;
        } else {
            if timeout(
                CONNECTION_DRAIN_TIMEOUT,
                drain_request_tasks(&mut requests, remote_addr),
            )
            .await
            .is_err()
            {
                requests.abort_all();
                drain_request_tasks(&mut requests, remote_addr).await;
            }
        }
    }

    async fn begin_connection_shutdown(connection: &mut Http3Connection, remote_addr: SocketAddr) {
        // h3 adds this request count to the last accepted stream ID. Advancing once identifies the
        // first request stream that was not accepted, so the current response remains valid.
        // https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        if let Err(error) = connection.shutdown(1).await {
            tracing::debug!(%error, %remote_addr, "failed to send HTTP/3 GOAWAY");
        }
    }

    async fn drain_requests_while_driving(
        connection: &mut Http3Connection,
        requests: &mut JoinSet<()>,
        remote_addr: SocketAddr,
    ) {
        while !requests.is_empty() {
            tokio::select! {
                finished = requests.join_next() => {
                    if let Some(result) = finished {
                        log_request_task(result, remote_addr);
                    }
                }
                accepted = connection.accept() => {
                    match accepted {
                        Ok(Some(_)) => {
                            tracing::trace!(%remote_addr, "discarded HTTP/3 request after GOAWAY");
                        }
                        Ok(None) => {
                            drain_request_tasks(requests, remote_addr).await;
                            return;
                        }
                        Err(error) => {
                            tracing::debug!(%error, %remote_addr, "HTTP/3 connection ended during drain");
                            drain_request_tasks(requests, remote_addr).await;
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn wait_for_peer_close(
        connection: &mut Http3Connection,
        transport: &quinn::Connection,
        remote_addr: SocketAddr,
    ) {
        // Once accepted responses are complete, the endpoint can close with H3_NO_ERROR. The
        // timeout prevents a peer that keeps QUIC alive after GOAWAY from retaining this
        // connection forever. https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        let closed = timeout(CONNECTION_CLOSE_TIMEOUT, async {
            loop {
                tokio::select! {
                    _ = transport.closed() => return,
                    accepted = connection.accept() => {
                        match accepted {
                            Ok(Some(_)) => {}
                            Ok(None) | Err(_) => return,
                        }
                    }
                }
            }
        })
        .await;

        if closed.is_err() {
            tracing::trace!(%remote_addr, "HTTP/3 peer close timed out");
        }

        if transport.close_reason().is_none() {
            transport.close(H3_NO_ERROR, b"HTTP/3 graceful shutdown");
        }
    }

    async fn serve_request<S>(
        resolver: RequestResolver,
        remote_addr: SocketAddr,
        service: S,
        capture: Http3Capture,
        client_hello: Option<Arc<OnceLock<ClientHelloHandshakeBuffer>>>,
    ) where
        S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
        S::Future: Send,
    {
        if timeout(
            REQUEST_TIMEOUT,
            serve_request_inner(resolver, remote_addr, service, capture, client_hello),
        )
        .await
        .is_err()
        {
            tracing::debug!(%remote_addr, "HTTP/3 request timed out");
        }
    }

    async fn serve_request_inner<S>(
        resolver: RequestResolver,
        remote_addr: SocketAddr,
        service: S,
        capture: Http3Capture,
        client_hello: Option<Arc<OnceLock<ClientHelloHandshakeBuffer>>>,
    ) where
        S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
        S::Future: Send,
    {
        let (request, stream) = match resolver.resolve_request().await {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(%error, %remote_addr, "failed to resolve HTTP/3 request");
                return;
            }
        };

        let mut track = ConnectionTrack::default();
        track.set_tls_version_negotiated(Some(ProtocolVersion::TLSv1_3));
        if let Some(client_hello) = client_hello {
            track.set_client_hello_handshake(client_hello);
        }

        if let Some(headers) = capture.take_headers(stream.id()) {
            let settings = capture.settings();

            // Control and request streams can arrive independently. Wait briefly for the mandatory
            // peer SETTINGS before response analysis rather than dropping HTTP/3 data due to
            // ordering. https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
            if timeout(SETTINGS_CAPTURE_TIMEOUT, settings.wait())
                .await
                .is_ok()
            {
                track.set_http3_capture(settings, headers);
            } else {
                tracing::debug!(%remote_addr, "HTTP/3 SETTINGS capture timed out");
            }
        }

        let mut request = request.map(|_| Body::empty());
        request.extensions_mut().insert(track);
        let response = service
            .oneshot(request)
            .await
            .unwrap_or_else(|error| match error {});

        if let Err(error) = send_response(stream, response).await {
            tracing::debug!(%error, %remote_addr, "failed to serve HTTP/3 response");
        }
    }

    async fn send_response(
        mut stream: RequestStream,
        response: Response<Body>,
    ) -> std::result::Result<(), BoxError> {
        // Analysis routes do not consume request bodies.
        stream.stop_sending(Code::H3_NO_ERROR);

        let (parts, body) = response.into_parts();
        stream
            .send_response(Response::from_parts(parts, ()))
            .await?;

        let mut body = body;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(data) => stream.send_data(data).await?,
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        stream.send_trailers(trailers).await?;
                        break;
                    }
                }
            }
        }
        stream.finish().await?;
        Ok(())
    }

    async fn drain_connection_tasks(connections: &mut JoinSet<()>) {
        while let Some(result) = connections.join_next().await {
            log_connection_task(result);
        }
    }

    async fn drain_request_tasks(requests: &mut JoinSet<()>, remote_addr: SocketAddr) {
        while let Some(result) = requests.join_next().await {
            log_request_task(result, remote_addr);
        }
    }

    fn log_connection_task(result: std::result::Result<(), JoinError>) {
        if let Err(error) = result {
            if !error.is_cancelled() {
                tracing::debug!(%error, "HTTP/3 connection task failed");
            }
        }
    }

    fn log_request_task(result: std::result::Result<(), JoinError>, remote_addr: SocketAddr) {
        if let Err(error) = result {
            if !error.is_cancelled() {
                tracing::debug!(%error, %remote_addr, "HTTP/3 request task failed");
            }
        }
    }
}
