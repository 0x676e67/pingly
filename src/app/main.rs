mod alloc;
mod args;
#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod server;
#[cfg(target_os = "linux")]
mod tcp;

use std::str::FromStr;

use args::{AppArgs, Command, ServerArgs};
#[cfg(target_os = "linux")]
use axum::Extension;
use axum::{routing::any, Router};
use clap::Parser;
use error::Result;
#[cfg(target_os = "linux")]
use pingora_runtime::current_handle;
use server::{
    routes::{http1_track, http2_track, tls_track, track},
    runtime::Runtime,
    HttpServer, TrackAcceptor,
};
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[cfg(target_os = "linux")]
use crate::{server::routes::tcp_track, tcp::TcpCaptureTrack};

const APP_NAME: &str = env!("CARGO_PKG_NAME");

fn main() -> Result<()> {
    let args = AppArgs::parse();
    #[cfg(target_family = "unix")]
    let daemon = daemon::Daemon::default();
    match args.command {
        Command::Run(args) => run(args),
        #[cfg(target_family = "unix")]
        Command::Start(args) => daemon.start(args),
        #[cfg(target_family = "unix")]
        Command::Restart(args) => daemon.restart(args),
        #[cfg(target_family = "unix")]
        Command::Stop => daemon.stop(),
        #[cfg(target_family = "unix")]
        Command::Ps => daemon.status(),
        #[cfg(target_family = "unix")]
        Command::Log => daemon.log(),
    }
}

fn log_filter(default_level: &str) -> EnvFilter {
    let directives = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_default();
    log_filter_from(default_level, &directives)
}

fn log_filter_from(default_level: &str, directives: &str) -> EnvFilter {
    let default_level = Level::from_str(default_level).unwrap_or(Level::INFO);
    if directives.is_empty() {
        EnvFilter::new(default_level.as_str())
    } else {
        EnvFilter::builder().parse_lossy(format!("{default_level},{directives}"))
    }
}

pub(crate) fn run(args: ServerArgs) -> Result<()> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(log_filter(&args.log))
            .finish(),
    )?;

    let threads = std::thread::available_parallelism()?;

    let layer = ServiceBuilder::new()
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

    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut router = Router::new()
        .route("/api/all", any(track))
        .route("/api/tls", any(tls_track))
        .route("/api/http1", any(http1_track))
        .route("/api/http2", any(http2_track));

    Runtime::new(threads).block_on(move |handle| async move {
        #[cfg(target_os = "linux")]
        {
            let mut tcp_capture_track: Option<TcpCaptureTrack> = None;
            if args.tcp_capture_packet {
                tracing::info!("Enabling TCP/IP packet capture (requires root)");
                let capture = TcpCaptureTrack::new(128, args.bind.port());
                if let Err(error) = capture.start_capture(args.tcp_capture_interface.clone()) {
                    tracing::error!(%error, "failed to start TCP/IP packet capture");
                } else {
                    if let Some(interface) = args.tcp_capture_interface {
                        tracing::info!(%interface, "TCP/IP packet capture started");
                    }
                    tcp_capture_track = Some(capture);
                }
            }

            if let Some(capture) = tcp_capture_track.as_ref() {
                router = router
                    .route("/api/tcp", any(tcp_track))
                    .layer(Extension(capture.clone()));
            }

            if let Some(capture) = tcp_capture_track {
                let shutdown = handle.clone();
                current_handle().spawn(async move {
                    shutdown.wait_graceful_shutdown().await;
                    capture.shutdown();
                });
            }
        }

        let server =
            HttpServer::new(args.bind, router.layer(layer), args.keep_alive_timeout).await?;
        let tls_certs = args.tls_cert.as_deref().zip(args.tls_key.as_deref());

        tracing::info!(
            threads = threads.get(),
            concurrent_limit = args.concurrent,
            keep_alive_timeout_secs = args.keep_alive_timeout,
            "starting {APP_NAME} on {}",
            args.bind,
        );

        let server = server
            .with_rustls(tls_certs)?
            .map_acceptor(TrackAcceptor::new);

        server.serve(handle).await;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::log_filter_from;

    #[test]
    fn log_filter_keeps_default_and_target_directives() {
        let filter = log_filter_from("info", "pingly::tls=trace").to_string();
        assert!(filter.split(',').any(|value| value == "info"));
        assert!(filter.split(',').any(|value| value == "pingly::tls=trace"));

        let overridden = log_filter_from("info", "warn,pingly::tls=trace").to_string();
        assert!(!overridden.split(',').any(|value| value == "info"));
        assert!(overridden.split(',').any(|value| value == "warn"));
    }
}
