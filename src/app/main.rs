mod alloc;
mod args;
mod error;
mod server;
mod state;
#[cfg(target_os = "linux")]
mod systemd;
#[cfg(target_os = "linux")]
mod tcp;

use std::str::FromStr;

#[cfg(target_os = "linux")]
use args::SystemdCommand;
use args::{AppArgs, Command, ServerArgs, TlsSource};
use clap::Parser;
use error::Result;
use pingora_runtime::current_handle;
use server::{routes, runtime::Runtime, AcmeRuntime, HttpServer, TrackAcceptor};
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[cfg(target_os = "linux")]
use crate::tcp::TcpCaptureTrack;

const APP_NAME: &str = env!("CARGO_PKG_NAME");

fn main() -> Result<()> {
    let args = AppArgs::parse();
    match args.command {
        Command::Run(args) => run(args),
        #[cfg(target_os = "linux")]
        Command::Systemd(command) => match command {
            SystemdCommand::Start(args) => systemd::start(args, systemd_server_arguments()),
            SystemdCommand::Restart(args) => systemd::restart(args, systemd_server_arguments()),
            SystemdCommand::Stop => systemd::stop(),
            SystemdCommand::Logs => systemd::log(),
            SystemdCommand::Status => systemd::status(),
        },
    }
}

/// Returns the server arguments after Clap validates `pingly systemd <action>`.
#[cfg(target_os = "linux")]
fn systemd_server_arguments() -> impl Iterator<Item = std::ffi::OsString> {
    std::env::args_os().skip(3)
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

pub(crate) fn run(mut args: ServerArgs) -> Result<()> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(log_filter(&args.log))
            .finish(),
    )?;
    let tls_source = args.take_tls_source()?;

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
        .layer(CompressionLayer::new())
        .layer(ConcurrencyLimitLayer::new(args.concurrent));

    Runtime::new(threads).block_on(move |handle| async move {
        #[cfg(target_os = "linux")]
        let tcp_capture_track = {
            let mut track = None;
            if args.tcp_capture_packet {
                tracing::info!("Enabling TCP/IP packet capture (requires root)");
                let capture = TcpCaptureTrack::new(128, args.bind.port());
                if let Err(error) = capture.start_capture(args.tcp_capture_interface.clone()) {
                    tracing::error!(%error, "failed to start TCP/IP packet capture");
                } else {
                    if let Some(interface) = args.tcp_capture_interface {
                        tracing::info!(%interface, "TCP/IP packet capture started");
                    }
                    track = Some(capture);
                }
            }
            track
        };

        let router = routes::router(
            #[cfg(target_os = "linux")]
            tcp_capture_track.as_ref(),
        );

        #[cfg(target_os = "linux")]
        if let Some(capture) = tcp_capture_track {
            let shutdown = handle.clone();
            current_handle().spawn(async move {
                shutdown.wait_graceful_shutdown().await;
                capture.shutdown();
            });
        }

        let server =
            HttpServer::new(args.bind, router.layer(layer), args.keep_alive_timeout).await?;

        let server = match tls_source {
            TlsSource::SelfSigned => server.with_rustls(None)?,
            TlsSource::Files { cert, key } => {
                server.with_rustls(Some((cert.as_path(), key.as_path())))?
            }
            TlsSource::Acme(options) => {
                let acme = AcmeRuntime::new(options)?;
                let (acceptor, http01, state) = acme.into_parts(handle.clone());

                if let Some(challenge) = http01 {
                    let bind = challenge.bind();
                    let challenge_server =
                        HttpServer::new(bind, challenge.into_router(), args.keep_alive_timeout)
                            .await?;

                    tracing::info!("starting ACME HTTP-01 challenge listener on {bind}");
                    current_handle().spawn(challenge_server.serve(handle.clone()));
                }

                current_handle().spawn(state);
                server.map_acceptor(|_| acceptor)
            }
        }
        .map_acceptor(TrackAcceptor::new);

        tracing::info!(
            threads = threads.get(),
            concurrent_limit = args.concurrent,
            keep_alive_timeout_secs = args.keep_alive_timeout,
            "starting {APP_NAME} on {}",
            args.bind,
        );

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
