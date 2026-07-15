//! Accepted-socket adapters for plain HTTP and TLS.

use std::{
    future::{Future, Ready},
    io,
};

/// Transforms an accepted IO stream and its per-connection service before Hyper serves it.
pub(crate) trait Accept<I, S> {
    /// IO stream produced by the acceptor.
    type Stream;

    /// Service produced by the acceptor.
    type Service;

    /// Future returned by the acceptor.
    type Future: Future<Output = io::Result<(Self::Stream, Self::Service)>>;

    /// Processes the accepted stream and service.
    fn accept(&self, stream: I, service: S) -> Self::Future;
}

/// No-op acceptor for plain HTTP.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DefaultAcceptor;

impl<I, S> Accept<I, S> for DefaultAcceptor {
    type Stream = I;
    type Service = S;
    type Future = Ready<io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        std::future::ready(Ok((stream, service)))
    }
}
