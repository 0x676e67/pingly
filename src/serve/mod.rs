mod cert;
mod signal;
mod track;

use std::{net::SocketAddr, str::FromStr, time::Duration};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
    Extension, Router,
};
use axum_extra::response::ErasedJson;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use track::{accept::TrackAcceptor, ConnectionTrack};

use crate::{error::Error, serve::track::info::TrackInfo, Args, Result};

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

    let router = Router::new()
        .route("/api/all", get(track))
        .route("/api/tls", get(tls_track))
        .route("/api/http1", get(http1_headers))
        .route("/api/http2", get(http2_frames))
        .layer(global_layer);

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Spawn a task to gracefully shutdown server.
    tokio::spawn(signal::graceful_shutdown(handle.clone()));

    // Load TLS configuration
    let tls_config = match (args.tls_cert.as_ref(), args.tls_key.as_ref()) {
        (Some(cert), Some(key)) => RustlsConfig::from_pem_chain_file(cert, key).await,
        _ => {
            let (cert, key) = cert::get_self_signed_cert()?;
            RustlsConfig::from_pem(cert, key).await
        }
    }?;

    // Use TLS configuration to create a secure server
    let mut server = axum_server::bind_rustls(args.bind, tls_config);
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
    let (tls, http1, http2) = tokio::task::spawn_blocking(move || track.into_track_info()).await?;
    let info = TrackInfo::new(addr, &req, tls, http1, http2);
    Ok(ErasedJson::pretty(info))
}

#[inline]
pub async fn tls_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let tls = tokio::task::spawn_blocking(move || track.into_tls_track_info()).await?;
    let info = TrackInfo::new_tls_track(addr, &req, tls);
    Ok(ErasedJson::pretty(info))
}

#[inline]
pub async fn http1_headers(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let http1 = tokio::task::spawn_blocking(move || track.into_http1_headers()).await?;
    let info = TrackInfo::new_http1_track(addr, &req, http1);
    Ok(ErasedJson::pretty(info))
}

#[inline]
pub async fn http2_frames(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let http2 = tokio::task::spawn_blocking(move || track.into_http2_track_info()).await?;
    let info = TrackInfo::new_http2_track(addr, &req, http2);
    Ok(ErasedJson::pretty(info))
}
