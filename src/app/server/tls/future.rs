//! Futures used by TLS acceptors.

use std::{
    future::Future,
    io,
    io::ErrorKind,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use rustls_acme::is_tls_alpn_challenge;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{timeout_at, Instant, Timeout},
};
use tokio_rustls::{
    rustls::ServerConfig, server::TlsStream, Accept as RustlsAccept, LazyConfigAcceptor,
    TlsAcceptor,
};

use crate::server::accept::AcceptOutcome;

pin_project! {
    /// Future that selects a TLS configuration and performs the handshake.
    pub(crate) struct RustlsAcceptorFuture<I, S> {
        // Current ClientHello inspection, handshake, or challenge shutdown phase.
        #[pin]
        state: RustlsAcceptState<I, S>,
    }
}

impl<I, S> RustlsAcceptorFuture<I, S>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a TLS accept future for a fixed server configuration.
    pub(super) fn new(
        stream: I,
        service: S,
        config: Arc<ServerConfig>,
        handshake_timeout: Duration,
    ) -> Self {
        let deadline = Instant::now() + handshake_timeout;
        let acceptor = TlsAcceptor::from(config);

        Self {
            state: RustlsAcceptState::Handshaking {
                future: timeout_at(deadline, acceptor.accept(stream)),
                service: Some(service),
                challenge: false,
            },
        }
    }

    /// Creates a TLS accept future that can answer TLS-ALPN-01 challenges.
    pub(super) fn new_acme(
        stream: I,
        service: S,
        default_config: Arc<ServerConfig>,
        challenge_config: Arc<ServerConfig>,
        handshake_timeout: Duration,
    ) -> Self {
        let deadline = Instant::now() + handshake_timeout;

        Self {
            state: RustlsAcceptState::Inspecting {
                future: timeout_at(
                    deadline,
                    LazyConfigAcceptor::new(Default::default(), stream),
                ),
                service: Some(service),
                default_config,
                challenge_config,
                deadline,
            },
        }
    }
}

pin_project! {
    #[project = RustlsAcceptStateProj]
    enum RustlsAcceptState<I, S> {
        Inspecting {
            #[pin]
            future: Timeout<LazyConfigAcceptor<I>>,
            service: Option<S>,
            default_config: Arc<ServerConfig>,
            challenge_config: Arc<ServerConfig>,
            deadline: Instant,
        },
        Handshaking {
            #[pin]
            future: Timeout<RustlsAccept<I>>,
            service: Option<S>,
            challenge: bool,
        },
        Closing {
            #[pin]
            stream: TlsStream<I>,
        },
        Done,
    }
}

impl<I, S> Future for RustlsAcceptorFuture<I, S>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<AcceptOutcome<TlsStream<I>, S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                RustlsAcceptStateProj::Inspecting {
                    future,
                    service,
                    default_config,
                    challenge_config,
                    deadline,
                } => {
                    let start = match future.poll(cx) {
                        Poll::Ready(Ok(Ok(start))) => start,
                        Poll::Ready(Ok(Err(error))) => {
                            this.state.set(RustlsAcceptState::Done);
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Err(error)) => {
                            this.state.set(RustlsAcceptState::Done);
                            return Poll::Ready(Err(io::Error::new(ErrorKind::TimedOut, error)));
                        }
                        Poll::Pending => return Poll::Pending,
                    };

                    // RFC 8737 requires acme-tls/1 to be the only offered ALPN value.
                    // https://www.rfc-editor.org/rfc/rfc8737#section-3
                    let challenge = is_tls_alpn_challenge(&start.client_hello());
                    let config = if challenge {
                        challenge_config.clone()
                    } else {
                        default_config.clone()
                    };
                    let Some(service) = service.take() else {
                        this.state.set(RustlsAcceptState::Done);
                        return Poll::Ready(Err(io::Error::other(
                            "TLS acceptor service is missing before handshake",
                        )));
                    };

                    let deadline = *deadline;
                    this.state.set(RustlsAcceptState::Handshaking {
                        future: timeout_at(deadline, start.into_stream(config)),
                        service: Some(service),
                        challenge,
                    });
                }
                RustlsAcceptStateProj::Handshaking {
                    future,
                    service,
                    challenge,
                } => {
                    let stream = match future.poll(cx) {
                        Poll::Ready(Ok(Ok(stream))) => stream,
                        Poll::Ready(Ok(Err(error))) => {
                            this.state.set(RustlsAcceptState::Done);
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Err(error)) => {
                            this.state.set(RustlsAcceptState::Done);
                            return Poll::Ready(Err(io::Error::new(ErrorKind::TimedOut, error)));
                        }
                        Poll::Pending => return Poll::Pending,
                    };

                    if *challenge {
                        if service.take().is_none() {
                            this.state.set(RustlsAcceptState::Done);
                            return Poll::Ready(Err(io::Error::other(
                                "TLS acceptor service is missing after challenge handshake",
                            )));
                        }

                        // The validation connection carries no application data and ends after
                        // the handshake.
                        // https://www.rfc-editor.org/rfc/rfc8737#section-3
                        this.state.set(RustlsAcceptState::Closing { stream });
                        continue;
                    }

                    let service = service.take();
                    this.state.set(RustlsAcceptState::Done);
                    return Poll::Ready(match service {
                        Some(service) => Ok(AcceptOutcome::Serve { stream, service }),
                        None => Err(io::Error::other(
                            "TLS acceptor service is missing after handshake",
                        )),
                    });
                }
                RustlsAcceptStateProj::Closing { stream } => match stream.poll_shutdown(cx) {
                    Poll::Ready(result) => {
                        this.state.set(RustlsAcceptState::Done);
                        return Poll::Ready(result.map(|()| AcceptOutcome::Handled));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                RustlsAcceptStateProj::Done => {
                    return Poll::Ready(Err(io::Error::other(
                        "TLS accept future polled after completion",
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertificateParams, KeyPair, SanType};
    use tokio::io::{duplex, AsyncReadExt};
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
            ClientConfig, RootCertStore, ServerConfig,
        },
        TlsConnector,
    };

    use crate::server::{
        accept::{Accept, AcceptOutcome},
        tls::rustls::RustlsAcceptor,
    };

    #[tokio::test]
    async fn regular_tls_connection_is_forwarded_to_hyper() {
        let (default_config, default_cert) = server_config(b"h2");
        let (challenge_config, _) = server_config(b"acme-tls/1");
        let acceptor = RustlsAcceptor::new_acme(default_config, challenge_config);
        let connector = client_connector(default_cert, b"h2");
        let server_name = ServerName::try_from("localhost").expect("valid DNS name");

        let (client_io, server_io) = duplex(32 * 1024);
        let (server, client) = tokio::join!(
            acceptor.accept(server_io, 42_u8),
            connector.connect(server_name, client_io),
        );

        let client = client.expect("regular handshake should succeed");
        let AcceptOutcome::Serve { stream, service } =
            server.expect("regular server handshake should succeed")
        else {
            panic!("regular TLS connection should be forwarded to Hyper");
        };

        assert_eq!(service, 42);
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    }

    #[tokio::test]
    async fn tls_alpn_challenge_is_handled_without_hyper() {
        let (default_config, _) = server_config(b"h2");
        let (challenge_config, challenge_cert) = server_config(b"acme-tls/1");
        let acceptor = RustlsAcceptor::new_acme(default_config, challenge_config);

        let connector = client_connector(challenge_cert, b"acme-tls/1");

        let (client_io, server_io) = duplex(32 * 1024);
        let server = acceptor.accept(server_io, ());
        let client = async move {
            let server_name = ServerName::try_from("localhost").expect("valid DNS name");
            let mut stream = connector
                .connect(server_name, client_io)
                .await
                .expect("challenge handshake should succeed");
            let negotiated = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            let mut byte = [0];
            let read = stream
                .read(&mut byte)
                .await
                .expect("challenge connection should close cleanly");
            (negotiated, read)
        };

        let (server, (negotiated, read)) = tokio::join!(server, client);

        assert!(matches!(server, Ok(AcceptOutcome::Handled)));
        assert_eq!(negotiated.as_deref(), Some(&b"acme-tls/1"[..]));
        assert_eq!(read, 0);
    }

    fn client_connector(certificate: CertificateDer<'static>, alpn: &[u8]) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate)
            .expect("server certificate should be trusted");
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];

        TlsConnector::from(Arc::new(config))
    }

    fn server_config(alpn: &[u8]) -> (Arc<ServerConfig>, CertificateDer<'static>) {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName(
            "localhost".try_into().expect("valid DNS name"),
        )];
        let key_pair = KeyPair::generate().expect("key generation should succeed");
        let certificate = params
            .self_signed(&key_pair)
            .expect("certificate generation should succeed");
        let certificate_der = certificate.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .expect("server certificate should be valid");
        config.alpn_protocols = vec![alpn.to_vec()];

        (Arc::new(config), certificate_der)
    }
}
