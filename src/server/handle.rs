//! Shutdown coordination for the HTTP server.
//!
//! Runtime code owns the Ctrl+C listener, while connection tasks wait for the same shutdown signal.
//! The signal is backed by `watch`, so tasks that start waiting after shutdown was requested still
//! return immediately.

use tokio::sync::watch;

/// Shared handle for graceful server shutdown.
///
/// Clones point at the same shutdown state. Once [`Handle::graceful_shutdown`] observes Ctrl+C,
/// the listener stops accepting new sockets and active connections are asked to drain once.
#[derive(Clone)]
pub(crate) struct Handle {
    graceful_shutdown: watch::Sender<bool>,
}

impl Handle {
    /// Creates a handle in the running state.
    pub(super) fn new() -> Self {
        let (graceful_shutdown, _) = watch::channel(false);
        Self { graceful_shutdown }
    }

    /// Waits until graceful shutdown is requested.
    ///
    /// This method is safe to use in `tokio::select!`: if the future is cancelled and recreated,
    /// the shutdown state is still kept in the handle.
    pub(crate) async fn wait_graceful_shutdown(&self) {
        let mut graceful_shutdown = self.graceful_shutdown.subscribe();
        loop {
            if *graceful_shutdown.borrow() || graceful_shutdown.changed().await.is_err() {
                return;
            }
        }
    }

    /// Waits for Ctrl+C and then requests graceful shutdown.
    ///
    /// If installing or polling the signal handler fails, the server still starts shutdown. That is
    /// the safer outcome for a process that no longer knows whether it can receive future signals.
    pub(super) async fn graceful_shutdown(self) {
        match tokio::signal::ctrl_c().await {
            Ok(()) => tracing::info!("received graceful shutdown signal"),
            Err(error) => tracing::warn!(%error, "failed to listen for shutdown signal"),
        }
        self.graceful_shutdown.send_replace(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_graceful_shutdown_returns_after_shutdown() {
        let handle = Handle::new();
        let waiter = handle.clone();
        let task = tokio::spawn(async move {
            waiter.wait_graceful_shutdown().await;
        });

        request_graceful_shutdown(&handle);

        task.await.expect("waiter should finish");
    }

    #[tokio::test]
    async fn late_waiter_returns_after_shutdown() {
        let handle = Handle::new();
        request_graceful_shutdown(&handle);

        handle.wait_graceful_shutdown().await;
    }

    fn request_graceful_shutdown(handle: &Handle) {
        handle.graceful_shutdown.send_replace(true);
    }
}
