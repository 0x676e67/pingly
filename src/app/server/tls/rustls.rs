//! rustls support for HTTPS connections.

use std::{path::Path, sync::Arc, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{rustls::ServerConfig, server::TlsStream};

use super::future::RustlsAcceptorFuture;
use crate::server::accept::Accept;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Acceptor that upgrades TCP streams to TLS.
#[derive(Clone)]
pub(crate) struct RustlsAcceptor {
    /// TLS configuration selected for fixed certificates or ACME challenges.
    mode: RustlsMode,

    /// Maximum time allowed for ClientHello inspection and the TLS handshake.
    handshake_timeout: Duration,
}

#[derive(Clone)]
enum RustlsMode {
    Fixed(Arc<ServerConfig>),
    Acme {
        default_config: Arc<ServerConfig>,

        challenge_config: Arc<ServerConfig>,
    },
}

impl RustlsAcceptor {
    /// Creates an acceptor with Pingly's reusable self-signed certificate.
    pub(crate) fn self_signed() -> crate::Result<Self> {
        Ok(Self::new(crate::server::certificate::config_self_signed()?))
    }

    /// Creates an acceptor from a PEM certificate chain and private key.
    pub(crate) fn from_pem_files(cert: &Path, key: &Path) -> crate::Result<Self> {
        Ok(Self::new(
            crate::server::certificate::config_from_pem_chain_file(cert, key)?,
        ))
    }

    /// Creates an acceptor with one fixed rustls configuration.
    pub(in crate::server) fn new(config: RustlsConfig) -> Self {
        Self {
            mode: RustlsMode::Fixed(config.inner),
            handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        }
    }

    /// Creates an acceptor that selects the ACME challenge configuration from ClientHello.
    pub(super) fn new_acme(
        default_config: Arc<ServerConfig>,
        challenge_config: Arc<ServerConfig>,
    ) -> Self {
        Self {
            mode: RustlsMode::Acme {
                default_config,
                challenge_config,
            },
            handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        }
    }

    /// Returns the certificate configuration used for regular HTTPS connections.
    pub(in crate::server) fn default_config(&self) -> Arc<ServerConfig> {
        match &self.mode {
            RustlsMode::Fixed(config) => config.clone(),
            RustlsMode::Acme { default_config, .. } => default_config.clone(),
        }
    }
}

impl<I, S> Accept<I, S> for RustlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = S;
    type Future = RustlsAcceptorFuture<I, S>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        match &self.mode {
            RustlsMode::Fixed(config) => {
                RustlsAcceptorFuture::new(stream, service, config.clone(), self.handshake_timeout)
            }
            RustlsMode::Acme {
                default_config,
                challenge_config,
            } => RustlsAcceptorFuture::new_acme(
                stream,
                service,
                default_config.clone(),
                challenge_config.clone(),
                self.handshake_timeout,
            ),
        }
    }
}

/// Sets the application protocols accepted by Pingly HTTP connections.
///
/// ALPN allows the client and server to select HTTP/2 or HTTP/1 during the TLS handshake.
/// https://www.rfc-editor.org/rfc/rfc7301
pub(in crate::server) fn set_http_alpn_protocols(config: &mut ServerConfig) {
    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
        b"http/0.9".to_vec(),
    ];
}

/// Shared rustls server configuration.
pub(crate) struct RustlsConfig {
    /// Server configuration shared by accepted connections.
    inner: Arc<ServerConfig>,
}

impl RustlsConfig {
    /// Wraps an existing rustls server configuration.
    pub(crate) fn from_config(inner: Arc<ServerConfig>) -> Self {
        Self { inner }
    }
}
