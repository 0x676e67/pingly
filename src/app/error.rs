pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    AddressParse(#[from] std::net::AddrParseError),

    #[error(transparent)]
    LogParse(#[from] tracing_subscriber::filter::ParseError),

    #[error(transparent)]
    LogSetGlobalDefault(#[from] tracing::subscriber::SetGlobalDefaultError),

    #[error(transparent)]
    JsonExtractorRejection(#[from] axum::extract::rejection::JsonRejection),

    #[error(transparent)]
    Http(#[from] axum::http::Error),

    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Systemd(#[from] unitbus::Error),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Journal(#[from] sdjournal::SdJournalError),
}
