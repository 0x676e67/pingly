mod certificate;
mod signal;
mod tracker;

use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::any,
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
use tracker::{
    accept::TrackAcceptor,
    info::{ConnectionTrack, Track, TrackInfo},
};

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
        .route("/api/all", any(track))
        .route("/api/tls", any(tls_track))
        .route("/api/http1", any(http1_track))
        .route("/api/http2", any(http2_track))
        .layer(global_layer);

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Spawn a task to gracefully shutdown server.
    tokio::spawn(signal::graceful_shutdown(handle.clone()));

    // Load TLS configuration with HTTP/2 ALPN preference
    let tls_config = match (args.tls_cert.as_ref(), args.tls_key.as_ref()) {
        (Some(cert_path), Some(key_path)) => {
            // Load certificate and key from files
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            create_rustls_config_with_h2_alpn(cert_pem, key_pem).await?
        }
        _ => {
            // Generate self-signed certificate
            let (cert_pem, key_pem) = certificate::get_self_signed_cert()?;
            create_rustls_config_with_h2_alpn(cert_pem, key_pem).await?
        }
    };

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

/// Create RustlsConfig with HTTP/2 ALPN preference
async fn create_rustls_config_with_h2_alpn(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
) -> Result<RustlsConfig> {
    use tokio_rustls::rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    };

    // Parse certificates/PK
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Other(format!("Failed to parse certificate: {}", e)))?;

    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| Error::Other(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| Error::Other("No private key found".to_string()))?;

    // Create server config with ALPN protocols (HTTP/2 first)
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Other(format!("Failed to create TLS config: {}", e)))?;

    // Set ALPN protocols with HTTP/2 preference
    let mut config = config;
    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
        b"http/0.9".to_vec(),
    ];

    tracing::info!("TLS configured with ALPN protocols: h2 (HTTP/2), http/1.1, http/1.0, http/0.9");

    Ok(RustlsConfig::from_config(Arc::new(config)))
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
