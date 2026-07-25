//! Error types shared by command handling and server startup.

/// Application result using [`Error`] by default.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors that can stop a Pingly command or server task.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Filesystem, socket, or runtime I/O failed.
    #[error(transparent)]
    IO(#[from] std::io::Error),

    /// A configured socket address could not be parsed.
    #[error(transparent)]
    AddressParse(#[from] std::net::AddrParseError),

    /// A tracing filter directive was invalid.
    #[error(transparent)]
    LogParse(#[from] tracing_subscriber::filter::ParseError),

    /// Another global tracing subscriber was already installed.
    #[error(transparent)]
    LogSetGlobalDefault(#[from] tracing::subscriber::SetGlobalDefaultError),

    /// An Axum JSON request body could not be extracted.
    #[error(transparent)]
    JsonExtractorRejection(#[from] axum::extract::rejection::JsonRejection),

    /// An HTTP response or route value could not be built.
    #[error(transparent)]
    Http(#[from] axum::http::Error),

    /// Self-signed certificate generation failed.
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    /// A spawned asynchronous task was cancelled or panicked.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// A systemd D-Bus operation failed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Systemd(#[from] unitbus::Error),

    /// Reading or following the systemd journal failed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Journal(#[from] sdjournal::SdJournalError),
}
