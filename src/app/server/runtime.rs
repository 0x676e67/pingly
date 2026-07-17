//! Pingora runtime management for the HTTP server.
//!
//! This keeps Pingora scheduling and shutdown details out of routing and HTTP/TLS code.

use std::{
    any::Any, future::Future, io, num::NonZeroUsize, panic::AssertUnwindSafe, time::Duration,
};

use futures_util::FutureExt;
use tokio::sync::oneshot;

use super::Handle;
use crate::Result;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Process-level Pingora runtime.
pub(crate) struct Runtime(pingora_runtime::Runtime);

impl Runtime {
    /// Creates a no-steal runtime with the selected thread count.
    pub(crate) fn new(threads: NonZeroUsize) -> Self {
        const RUNTIME_NAME: &str = env!("CARGO_PKG_NAME");

        Self(pingora_runtime::Runtime::new_no_steal(
            threads.get(),
            RUNTIME_NAME,
        ))
    }

    /// Runs `serve` with a shutdown handle and blocks until it returns.
    ///
    /// A process shutdown signal asks the handle to start graceful shutdown. Server panics are
    /// returned as errors.
    pub(crate) fn block_on<F, Fut>(self, serve: F) -> Result<()>
    where
        F: FnOnce(Handle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handle = Handle::new();
        let (finish, finished) = oneshot::channel();

        // `get_handle()` selects a random worker from the no-steal runtime pool.
        // https://docs.rs/pingora-runtime/0.8.1/src/pingora_runtime/lib.rs.html#63-72
        let runtime = self.0.get_handle();
        runtime.spawn(handle.clone().graceful_shutdown());
        runtime.spawn(async move {
            let result = AssertUnwindSafe(serve(handle))
                .catch_unwind()
                .await
                .unwrap_or_else(server_panic_error);
            if finish.send(result).is_err() {
                tracing::warn!("failed to send server result");
            }
        });

        let result = finished
            .blocking_recv()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))?;
        self.0.shutdown_timeout(SHUTDOWN_TIMEOUT);
        result
    }
}

fn server_panic_error(payload: Box<dyn Any + Send>) -> Result<()> {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("server task panicked");

    Err(io::Error::other(format!("server task panicked: {message}")).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_returns_server_result() {
        let runtime = Runtime::new(NonZeroUsize::new(2).expect("thread count is non-zero"));

        let result = runtime.block_on(|_| async { Err(io::Error::other("test error").into()) });

        assert!(matches!(result, Err(crate::error::Error::IO(_))));
    }

    #[test]
    fn block_on_returns_server_panic() {
        let runtime = Runtime::new(NonZeroUsize::new(2).expect("thread count is non-zero"));

        let result = runtime.block_on(|_| async {
            if std::hint::black_box(true) {
                panic!("test panic");
            }

            Ok(())
        });

        assert!(matches!(result, Err(crate::error::Error::IO(_))));
    }
}
