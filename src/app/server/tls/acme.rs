//! ACME certificate acquisition and renewal for the rustls server backend.

use std::{future::Future, io, net::SocketAddr, sync::Arc};

use axum::Router;
use futures_util::StreamExt;
use rustls_acme::{
    caches::DirCache, tower::TowerHttp01ChallengeService, AcmeConfig, AcmeState, UseChallenge,
};

use super::rustls::{set_http_alpn_protocols, RustlsAcceptor, RustlsConfig};
use crate::{
    args::{AcmeChallenge, AcmeOptions},
    server::Handle,
};

const HTTP01_CHALLENGE_PATH: &str = "/.well-known/acme-challenge/{challenge_token}";

/// ACME state and protocol adapters prepared for the server.
pub(crate) struct AcmeRuntime {
    /// TLS acceptor backed by the current ACME certificate resolver.
    acceptor: RustlsAcceptor,

    /// Dedicated HTTP-01 challenge endpoint when that challenge is selected.
    http01: Option<Http01Challenge>,

    /// State stream that acquires and renews the configured certificate.
    state: AcmeState<io::Error>,
}

impl AcmeRuntime {
    /// Builds certificate state for TLS-ALPN-01 or HTTP-01 validation.
    pub(crate) fn new(options: AcmeOptions) -> crate::Result<Self> {
        let AcmeOptions {
            domains,
            contacts,
            challenge,
            http_bind,
            production,
        } = options;

        let cache_dir = crate::state::directory().join("acme");
        crate::state::prepare_private_directory(&cache_dir)?;

        let challenge_type = match challenge {
            AcmeChallenge::TlsAlpn01 => UseChallenge::TlsAlpn01,
            AcmeChallenge::Http01 => UseChallenge::Http01,
        };
        let state = AcmeConfig::new(domains)
            .contact(contacts)
            .cache(DirCache::new(cache_dir))
            .directory_lets_encrypt(production)
            .challenge_type(challenge_type)
            .state();

        let mut default_config = state.default_rustls_config();
        let config = Arc::get_mut(&mut default_config).ok_or_else(|| {
            io::Error::other("ACME rustls configuration was shared before initialization")
        })?;
        set_http_alpn_protocols(config);

        let (acceptor, http01) = match challenge {
            AcmeChallenge::TlsAlpn01 => (
                RustlsAcceptor::new_acme(default_config, state.challenge_rustls_config()),
                None,
            ),
            AcmeChallenge::Http01 => {
                let bind = http_bind.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HTTP-01 requires a challenge listener address",
                    )
                })?;
                let service = state.http01_challenge_tower_service();

                (
                    RustlsAcceptor::new(RustlsConfig::from_config(default_config)),
                    Some(Http01Challenge { bind, service }),
                )
            }
        };

        Ok(Self {
            acceptor,
            http01,
            state,
        })
    }

    /// Splits the prepared adapters from the state driver.
    pub(crate) fn into_parts(
        self,
        shutdown: Handle,
    ) -> (
        RustlsAcceptor,
        Option<Http01Challenge>,
        impl Future<Output = ()> + Send + 'static,
    ) {
        (
            self.acceptor,
            self.http01,
            drive_state(self.state, shutdown),
        )
    }
}

/// Plain HTTP listener used only for HTTP-01 challenge responses.
///
/// The token and key authorization exchange follows RFC 8555 section 8.3.
/// https://www.rfc-editor.org/rfc/rfc8555#section-8.3
pub(crate) struct Http01Challenge {
    /// Address of the dedicated plain HTTP listener.
    bind: SocketAddr,

    /// Service that returns the active challenge's key authorization.
    service: TowerHttp01ChallengeService,
}

impl Http01Challenge {
    /// Returns the dedicated plain HTTP listener address.
    pub(crate) fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Builds a router containing only the standardized challenge endpoint.
    pub(crate) fn into_router(self) -> Router {
        Router::new().route_service(HTTP01_CHALLENGE_PATH, self.service)
    }
}

async fn drive_state(mut state: AcmeState<io::Error>, shutdown: Handle) {
    loop {
        tokio::select! {
            _ = shutdown.wait_graceful_shutdown() => return,
            event = state.next() => match event {
                Some(Ok(event)) => {
                    tracing::info!(?event, "ACME certificate state changed");
                }
                Some(Err(error)) => {
                    tracing::error!(%error, "ACME certificate operation failed");
                }
                None => {
                    tracing::warn!("ACME certificate state stream ended");
                    return;
                }
            },
        }
    }
}
