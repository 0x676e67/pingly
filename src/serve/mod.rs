mod cert;
mod route;
mod signal;
mod track;

use std::net::SocketAddr;
use std::{str::FromStr, time::Duration};

use crate::Result;
use crate::{config::Config, track::TrackAcceptor};
use axum::routing::get;
use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main]
pub async fn run(config: Config) -> Result<()> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .with_max_level(Level::from_str(&config.log).unwrap_or(Level::INFO))
            .finish(),
    )?;

    tracing::info!("OS: {}", std::env::consts::OS);
    tracing::info!("Arch: {}", std::env::consts::ARCH);
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Keep alive: {}s", config.keep_alive_timeout);
    tracing::info!("Concurrent limit: {}", config.concurrent);
    tracing::info!("Bind address: {}", config.bind);

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
        .layer(ConcurrencyLimitLayer::new(config.concurrent));

    let router = Router::new()
        .route("/api/all", get(route::track))
        .route("/api/tls", get(route::tls_track))
        .route("/api/http2", get(route::http2_frames))
        .layer(global_layer);

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Spawn a task to gracefully shutdown server.
    tokio::spawn(signal::graceful_shutdown(handle.clone()));

    // Load TLS configuration
    let tls_config = match (config.tls_cert.as_ref(), config.tls_key.as_ref()) {
        (Some(cert), Some(key)) => RustlsConfig::from_pem_chain_file(cert, key).await,
        _ => {
            let (cert, key) = cert::get_self_signed_cert()?;
            RustlsConfig::from_pem(cert, key).await
        }
    }?;

    // Use TLS configuration to create a secure server
    let mut server = axum_server::bind_rustls(config.bind, tls_config);
    server
        .http_builder()
        .http1()
        .title_case_headers(true)
        .preserve_header_case(true)
        .http2()
        .keep_alive_timeout(Duration::from_secs(config.keep_alive_timeout));

    server
        .handle(handle)
        .map(TrackAcceptor::new)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(Into::into)
}
