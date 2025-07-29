pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    AddressParse(#[from] std::net::AddrParseError),

    #[cfg(target_family = "unix")]
    #[error(transparent)]
    Nix(#[from] nix::Error),

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
}
