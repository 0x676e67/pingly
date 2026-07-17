//! Command-line arguments for the pingly process.

use std::{io, net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[clap(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct AppArgs {
    #[clap(subcommand)]
    pub(crate) command: Command,
}

/// ACME challenge used to prove control of the configured domains.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum AcmeChallenge {
    /// Validate through the acme-tls/1 ALPN protocol on public TCP port 443.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8737
    #[default]
    #[value(name = "tls-alpn-01")]
    TlsAlpn01,

    /// Serve key authorization over plain HTTP on public TCP port 80.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8555#section-8.3
    #[value(name = "http-01")]
    Http01,
}

/// ACME settings shared by TLS-ALPN-01 and HTTP-01 validation.
#[derive(clap::Args, Default)]
pub(crate) struct AcmeArgs {
    /// Domain to include in the certificate; may be supplied more than once
    #[arg(
        long = "acme-domain",
        value_name = "DOMAIN",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        conflicts_with_all = ["tls_cert", "tls_key"]
    )]
    domains: Vec<String>,

    /// ACME account email; may be supplied more than once
    #[arg(
        long = "acme-email",
        value_name = "EMAIL",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        requires = "domains"
    )]
    emails: Vec<String>,

    /// ACME challenge type
    #[arg(
        long = "acme-challenge",
        value_enum,
        default_value_t,
        requires = "domains"
    )]
    challenge: AcmeChallenge,

    /// Address for the HTTP-01 challenge listener
    #[arg(long = "acme-http-bind", value_name = "ADDR", requires = "domains")]
    http_bind: Option<SocketAddr>,

    /// Directory used to cache the ACME account and certificate
    #[arg(long = "acme-cache", value_name = "PATH", requires = "domains")]
    cache: Option<PathBuf>,

    /// Use the production ACME directory instead of staging
    #[arg(long = "acme-production", requires = "domains")]
    production: bool,
}

/// Validated ACME settings consumed by the server.
pub(crate) struct AcmeOptions {
    /// DNS names requested in the certificate.
    pub(crate) domains: Vec<String>,

    /// ACME account contacts in mailto URI form.
    pub(crate) contacts: Vec<String>,

    /// Persistent account and certificate cache.
    pub(crate) cache_dir: PathBuf,

    /// Domain-control validation method.
    pub(crate) challenge: AcmeChallenge,

    /// HTTP listener used only by HTTP-01 validation.
    pub(crate) http_bind: Option<SocketAddr>,

    /// Whether to use the production ACME directory.
    pub(crate) production: bool,
}

/// TLS certificate source selected by the command line.
pub(crate) enum TlsSource {
    /// Reusable self-signed certificate stored in the application state directory.
    SelfSigned,

    /// Certificate chain and private key loaded from user-supplied PEM files.
    Files {
        /// Certificate chain file.
        cert: PathBuf,

        /// Private key file.
        key: PathBuf,
    },

    /// Certificate acquired and renewed through ACME.
    Acme(AcmeOptions),
}

#[derive(clap::Args)]
pub(crate) struct ServerArgs {
    /// Debug mode
    #[arg(long, default_value = "info", env = "PINGLY_LOG")]
    pub(crate) log: String,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:8181")]
    pub(crate) bind: SocketAddr,

    /// Concurrent connections
    #[arg(short, long, default_value = "1024")]
    pub(crate) concurrent: usize,

    /// Keep alive timeout (seconds)
    #[arg(short, long, default_value = "60")]
    pub(crate) keep_alive_timeout: u64,

    /// TLS certificate file path
    #[arg(short = 'C', long, requires = "tls_key", conflicts_with = "domains")]
    pub(crate) tls_cert: Option<PathBuf>,

    /// TLS private key file path (EC/PKCS8/RSA)
    #[arg(short = 'K', long, requires = "tls_cert", conflicts_with = "domains")]
    pub(crate) tls_key: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) acme: AcmeArgs,

    /// Enable packet capture for TCP/IP analysis (requires root privileges)
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'T')]
    pub(crate) tcp_capture_packet: bool,

    /// Network interface to capture packets from (default: auto-detect)
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'I')]
    pub(crate) tcp_capture_interface: Option<String>,
}

impl ServerArgs {
    /// Takes the validated TLS certificate source from the parsed arguments.
    pub(crate) fn take_tls_source(&mut self) -> crate::Result<TlsSource> {
        match (self.tls_cert.take(), self.tls_key.take()) {
            (Some(cert), Some(key)) => Ok(TlsSource::Files { cert, key }),
            (None, None) if self.acme.domains.is_empty() => Ok(TlsSource::SelfSigned),
            (None, None) => Ok(TlsSource::Acme(self.acme.take_options()?)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS certificate and private key must be supplied together",
            )
            .into()),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn acme_cache_path(&self) -> Option<&std::path::Path> {
        self.acme.cache.as_deref()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn requires_privileged_bind(&self) -> bool {
        self.bind.port() < 1024
            || (self.acme.challenge == AcmeChallenge::Http01
                && self
                    .acme
                    .http_bind
                    .unwrap_or(AcmeArgs::DEFAULT_HTTP_BIND)
                    .port()
                    < 1024)
    }
}

impl AcmeArgs {
    const DEFAULT_HTTP_BIND: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 80);

    fn take_options(&mut self) -> crate::Result<AcmeOptions> {
        let http_bind = match (self.challenge, self.http_bind) {
            (AcmeChallenge::Http01, bind) => Some(bind.unwrap_or(Self::DEFAULT_HTTP_BIND)),
            (AcmeChallenge::TlsAlpn01, None) => None,
            (AcmeChallenge::TlsAlpn01, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--acme-http-bind is only valid with --acme-challenge http-01",
                )
                .into());
            }
        };

        let cache_dir = self
            .cache
            .take()
            .unwrap_or_else(|| crate::state::directory().join("acme"));

        let contacts = std::mem::take(&mut self.emails)
            .into_iter()
            .map(|email| {
                if email.starts_with("mailto:") {
                    email
                } else {
                    format!("mailto:{email}")
                }
            })
            .collect();

        Ok(AcmeOptions {
            domains: std::mem::take(&mut self.domains),
            contacts,
            cache_dir,
            challenge: self.challenge,
            http_bind,
            production: self.production,
        })
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Run tracking server
    Run(ServerArgs),

    /// Manage the systemd service
    #[cfg(target_os = "linux")]
    #[command(subcommand)]
    Systemd(SystemdCommand),
}

#[cfg(target_os = "linux")]
#[derive(Subcommand)]
pub(crate) enum SystemdCommand {
    /// Install, enable, and start the systemd service
    Start(ServerArgs),

    /// Update and restart the systemd service
    Restart(ServerArgs),

    /// Stop the systemd service
    Stop,

    /// Show recent systemd logs and follow new entries
    Logs,

    /// Show the systemd service status
    Status,
}
