#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod alloc;
#[cfg(target_family = "unix")]
mod daemon;
mod error;
mod server;

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use error::Result;

#[derive(Parser)]
#[clap(author, version, about, arg_required_else_help = true)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Opt {
    #[clap(subcommand)]
    pub commands: Commands,
}

#[derive(clap::Args, Clone)]
pub struct Args {
    /// Debug mode
    #[arg(long, default_value = "info", env = "PINGLY_LOG")]
    pub log: String,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:8181")]
    pub bind: SocketAddr,

    /// Concurrent connections
    #[arg(short, long, default_value = "1024")]
    pub concurrent: usize,

    /// Keep alive timeout (seconds)
    #[arg(short, long, default_value = "60")]
    pub keep_alive_timeout: u64,

    /// TLS certificate file path
    #[arg(short = 'C', long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file path (EC/PKCS8/RSA)
    #[arg(short = 'K', long)]
    pub tls_key: Option<PathBuf>,

    /// Enable packet capture for TCP/IP analysis (requires root privileges)
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'T')]
    pub tcp_capture_packet: bool,

    /// Network interface to capture packets from (default: auto-detect)
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'I')]
    pub tcp_capture_interface: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run tracking server
    Run(Args),

    /// Start tracking server daemon
    #[cfg(target_family = "unix")]
    Start(Args),

    /// Restart tracking server daemon
    #[cfg(target_family = "unix")]
    Restart(Args),

    /// Stop tracking server daemon
    #[cfg(target_family = "unix")]
    Stop,

    /// Show tracking server daemon log
    #[cfg(target_family = "unix")]
    Log,

    /// Show tracking server daemon process
    #[cfg(target_family = "unix")]
    PS,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    #[cfg(target_family = "unix")]
    let daemon = daemon::Daemon::default();
    match opt.commands {
        Commands::Run(config) => server::run(config),
        #[cfg(target_family = "unix")]
        Commands::Start(config) => daemon.start(config),
        #[cfg(target_family = "unix")]
        Commands::Restart(config) => daemon.restart(config),
        #[cfg(target_family = "unix")]
        Commands::Stop => daemon.stop(),
        #[cfg(target_family = "unix")]
        Commands::PS => daemon.status(),
        #[cfg(target_family = "unix")]
        Commands::Log => daemon.log(),
    }
}
