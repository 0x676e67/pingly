//! rustls support for HTTPS connections.

use std::{io, sync::Arc, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{rustls::ServerConfig, server::TlsStream};

use super::future::RustlsAcceptorFuture;
use crate::server::accept::Accept;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Acceptor that upgrades TCP streams to TLS.
#[derive(Clone)]
pub(crate) struct RustlsAcceptor {
    config: RustlsConfig,

    handshake_timeout: Duration,
}

impl RustlsAcceptor {
    /// Creates a rustls acceptor.
    pub(in crate::server) fn new(config: RustlsConfig) -> Self {
        Self {
            config,
            handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        }
    }
}

impl<I, S> Accept<I, S> for RustlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = S;
    type Future = RustlsAcceptorFuture<std::future::Ready<io::Result<(I, S)>>, I, S>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        RustlsAcceptorFuture::new(
            std::future::ready(Ok((stream, service))),
            self.config.clone(),
            self.handshake_timeout,
        )
    }
}

/// Shared rustls server configuration.
#[derive(Clone)]
pub(crate) struct RustlsConfig {
    inner: Arc<ServerConfig>,
}

impl RustlsConfig {
    /// Wraps an existing rustls server configuration.
    pub(crate) fn from_config(inner: Arc<ServerConfig>) -> Self {
        Self { inner }
    }

    /// Returns the shared rustls config.
    pub(super) fn inner(&self) -> Arc<ServerConfig> {
        self.inner.clone()
    }
}
