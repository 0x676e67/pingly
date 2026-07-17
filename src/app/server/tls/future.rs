//! Futures used by TLS acceptors.

use std::{
    future::Future,
    io,
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{timeout, Timeout},
};
use tokio_rustls::{server::TlsStream, Accept as RustlsAccept, TlsAcceptor};

use super::rustls::RustlsConfig;

pin_project! {
    /// Future that waits for an accepted stream and then performs the TLS handshake.
    pub(crate) struct RustlsAcceptorFuture<F, I, S> {
        #[pin]
        state: RustlsAcceptState<F, I, S>,

        config: RustlsConfig,
    }
}

impl<F, I, S> RustlsAcceptorFuture<F, I, S> {
    /// Creates a TLS accept future with a handshake timeout.
    pub(super) fn new(future: F, config: RustlsConfig, handshake_timeout: Duration) -> Self {
        Self {
            state: RustlsAcceptState::Waiting {
                future,
                handshake_timeout,
            },
            config,
        }
    }
}

pin_project! {
    #[project = RustlsAcceptStateProj]
    enum RustlsAcceptState<F, I, S> {
        Waiting {
            #[pin]
            future: F,

            handshake_timeout: Duration,
        },
        Handshaking {
            #[pin]
            future: Timeout<RustlsAccept<I>>,

            service: Option<S>,
        },
        Done,
    }
}

impl<F, I, S> Future for RustlsAcceptorFuture<F, I, S>
where
    F: Future<Output = io::Result<(I, S)>>,
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<(TlsStream<I>, S)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                RustlsAcceptStateProj::Waiting {
                    future,
                    handshake_timeout,
                } => match future.poll(cx) {
                    Poll::Ready(Ok((stream, service))) => {
                        let acceptor = TlsAcceptor::from(this.config.inner());
                        let accept = timeout(*handshake_timeout, acceptor.accept(stream));
                        this.state.set(RustlsAcceptState::Handshaking {
                            future: accept,
                            service: Some(service),
                        });
                    }
                    Poll::Ready(Err(error)) => {
                        this.state.set(RustlsAcceptState::Done);
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                RustlsAcceptStateProj::Handshaking { future, service } => {
                    let stream = match future.poll(cx) {
                        Poll::Ready(Ok(Ok(stream))) => Ok(stream),
                        Poll::Ready(Ok(Err(error))) => Err(error),
                        Poll::Ready(Err(error)) => Err(io::Error::new(ErrorKind::TimedOut, error)),
                        Poll::Pending => return Poll::Pending,
                    };
                    let service = service.take();
                    this.state.set(RustlsAcceptState::Done);

                    return Poll::Ready(match (stream, service) {
                        (Ok(stream), Some(service)) => Ok((stream, service)),
                        (Err(error), _) => Err(error),
                        (Ok(_), None) => Err(io::Error::other(
                            "TLS acceptor service is missing after handshake",
                        )),
                    });
                }
                RustlsAcceptStateProj::Done => {
                    return Poll::Ready(Err(io::Error::other(
                        "TLS accept future polled after completion",
                    )));
                }
            }
        }
    }
}
