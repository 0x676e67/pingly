//! Command-line arguments for the pingly process.

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct AppArgs {
    #[clap(subcommand)]
    pub(crate) command: Command,
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
    #[arg(short = 'C', long)]
    pub(crate) tls_cert: Option<PathBuf>,

    /// TLS private key file path (EC/PKCS8/RSA)
    #[arg(short = 'K', long)]
    pub(crate) tls_key: Option<PathBuf>,

    /// Enable packet capture for TCP/IP analysis (requires root privileges)
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'T')]
    pub(crate) tcp_capture_packet: bool,

    /// Network interface to capture packets from (default: auto-detect)
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'I')]
    pub(crate) tcp_capture_interface: Option<String>,
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
