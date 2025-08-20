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
use tower::limit::ConcurrencyLimitLayer;
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

use crate::capture::PacketCapture;
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
    tracing::info!("Keep alive: {}s", args.keep_alive_timeout);
    tracing::info!("Concurrent limit: {}", args.concurrent);
    tracing::info!("Bind address: {}", args.bind);

    // Initialize packet capture if enabled
    let packet_capture = if args.capture_packets {
        tracing::info!("Packet capture enabled - requires root privileges");
        let capture = PacketCapture::new(128, args.bind.port()); // Keep last 1000 packets
        if let Err(e) = capture.start_capture(args.capture_interface.clone()) {
            tracing::error!("Failed to start packet capture: {}", e);
            tracing::warn!("Continuing without packet capture...");
            None
        } else {
            tracing::info!("Packet capture started successfully");
            Some(capture)
        }
    } else {
        None
    };

    // init global layer provider
    let global_layer = tower::ServiceBuilder::new()
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

    let mut router = Router::new()
        .route("/api/all", any(track))
        .route("/api/tls", any(tls_track))
        .route("/api/http1", any(http1_track))
        .route("/api/http2", any(http2_track));

    // Add packet capture endpoints if enabled
    if let Some(capture) = packet_capture.clone() {
        router = router
            .route("/api/packets", axum::routing::get(get_packets))
            .layer(Extension(capture));
    }

    let router = router.layer(global_layer);

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Spawn a task to gracefully shutdown server.
    tokio::spawn(signal::graceful_shutdown(
        handle.clone(),
        packet_capture.clone(),
    ));

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
        .keep_alive_timeout(Duration::from_secs(args.keep_alive_timeout));

    server
        .handle(handle)
        .map(TrackAcceptor::new)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
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
    req: Request<Body>,
) -> Result<ErasedJson> {
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::All, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
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
pub async fn get_packets(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(capture): Extension<PacketCapture>,
) -> Result<ErasedJson> {
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_ip = addr.ip().to_string();
    let client_port = addr.port();

    let packets = capture.get_packets_for_client(&client_ip, client_port);

    capture.clear_packets_for_client(&client_ip, client_port);

    Ok(ErasedJson::pretty(&packets))
}
