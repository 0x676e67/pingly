mod certificate;
mod signal;
mod tracker;

use std::{net::SocketAddr, str::FromStr, time::Duration};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::any,
    Extension, Router,
};
use axum_extra::response::ErasedJson;
use axum_server::Handle;
use hyper_util::rt::TokioTimer;
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};

use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use tracker::{
    accept::TrackAcceptor,
    info::{ConnectionTrack, Track, TrackInfo},
};

#[cfg(target_os = "linux")]
use tracker::capture::TcpCaptureTrack;

use crate::{error::Error, Args, Result};

#[tokio::main]
pub async fn run(args: Args) -> Result<()> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .with_max_level(Level::from_str(&args.log).unwrap_or(Level::INFO))
            .finish(),
    )?;

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Concurrent limit: {}", args.concurrent);
    tracing::info!("Bind address: {}", args.bind);

    // Init global layer
    let global_layer = ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::WARN)),
        )
        .layer(
            CorsLayer::new()
                .allow_credentials(true)
                .allow_headers(AllowHeaders::mirror_request())
                .allow_methods(AllowMethods::mirror_request())
                .allow_origin(AllowOrigin::mirror_request()),
        )
        .layer(ConcurrencyLimitLayer::new(args.concurrent));

    // Create the router with the tracking endpoints
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut router = Router::new()
        .route("/api/all", any(track))
        .route("/api/tls", any(tls_track))
        .route("/api/http1", any(http1_track))
        .route("/api/http2", any(http2_track));

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Add TCP tracking layer
    #[cfg(target_os = "linux")]
    {
        let mut tcp_capture_track: Option<TcpCaptureTrack> = None;
        if args.tcp_capture_packet {
            tracing::info!("Enabling TCP/IP packet capture (requires root)");
            let capture = TcpCaptureTrack::new(128, args.bind.port());
            if let Err(err) = capture.start_capture(args.tcp_capture_interface.clone()) {
                tracing::error!("Failed to start TCP/IP packet capture: {err}");
            } else {
                if let Some(iface) = args.tcp_capture_interface {
                    tracing::info!(
                        "TCP/IP packet capture started successfully on interface {iface}"
                    );
                }
                tcp_capture_track = Some(capture);
            }
        }

        if let Some(capture) = tcp_capture_track.clone() {
            router = router
                .route("/api/tcp", any(tcp_track))
                .layer(Extension(capture));
        }

        tokio::spawn(signal::graceful_shutdown(
            handle.clone(),
            tcp_capture_track.clone(),
        ));
    }

    // Spawn a task to gracefully shutdown server.
    #[cfg(not(target_os = "linux"))]
    tokio::spawn(signal::graceful_shutdown(handle.clone()));

    // Load TLS configuration with HTTP/2 ALPN preference
    let config = match (args.tls_cert.as_ref(), args.tls_key.as_ref()) {
        (Some(cert_path), Some(key_path)) => {
            // Load TLS configuration from PEM files
            certificate::config_from_pem_chain_file(cert_path, key_path).await?
        }
        _ => {
            // Generate self-signed certificate configuration
            certificate::config_self_signed().await?
        }
    };

    // Use TLS configuration to create a secure server
    let mut server = axum_server::bind_rustls(args.bind, config);
    server
        .http_builder()
        .http2()
        .timer(TokioTimer::new())
        .auto_date_header(true)
        .keep_alive_interval(Duration::from_secs(0))
        .keep_alive_timeout(Duration::from_secs(0));

    server
        .handle(handle)
        .map(TrackAcceptor::new)
        .serve(
            router
                .layer(global_layer)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(Into::into)
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        tracing::warn!("server track error: {}", self);
        (StatusCode::INTERNAL_SERVER_ERROR).into_response()
    }
}

#[inline]
pub async fn track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    #[cfg(target_os = "linux")] tcp_capture: Option<Extension<TcpCaptureTrack>>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    // get TCP packets if capture is available
    #[cfg(target_os = "linux")]
    let tcp_packets = if let Some(Extension(capture)) = tcp_capture {
        // small delay to capture packets
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_ip = addr.ip().to_string();
        let client_port = addr.port();

        let packets = capture.get_packets_for_client(&client_ip, client_port);
        capture.clear_packets_for_client(&client_ip, client_port);
        packets
    } else {
        Vec::new()
    };

    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || {
            TrackInfo::new_with_tcp(Track::All, addr, req, track, tcp_packets)
        })
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
    }

    #[cfg(not(target_os = "linux"))]
    {
        tokio::task::spawn_blocking(move || TrackInfo::new(Track::All, addr, req, track))
            .await
            .map(ErasedJson::pretty)
            .map_err(Error::from)
    }
}

#[inline]
pub async fn tls_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::Tls, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub async fn http1_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::HTTP1, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub async fn http2_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::HTTP2, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
#[cfg(target_os = "linux")]
pub async fn tcp_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(capture): Extension<TcpCaptureTrack>,
) -> Result<ErasedJson> {
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_ip = addr.ip().to_string();
    let client_port = addr.port();

    let packets = capture.get_packets_for_client(&client_ip, client_port);

    capture.clear_packets_for_client(&client_ip, client_port);

    Ok(ErasedJson::pretty(&packets))
}
