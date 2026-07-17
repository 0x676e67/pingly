//! Shutdown coordination for the HTTP server.
//!
//! Runtime code owns the process signal listener, while connection tasks wait for the same shutdown
//! state. The state is backed by `watch`, so tasks that start waiting after shutdown was requested
//! still return immediately.

use tokio::sync::watch;

/// Shared handle for graceful server shutdown.
///
/// Clones point at the same shutdown state. Once [`Handle::graceful_shutdown`] observes an
/// interrupt or termination signal, the listener stops accepting new sockets and active
/// connections are asked to drain once.
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

    /// Waits for a process shutdown signal and then requests graceful shutdown.
    ///
    /// If installing or polling the signal handler fails, the server still starts shutdown. That is
    /// the safer outcome for a process that no longer knows whether it can receive future signals.
    pub(super) async fn graceful_shutdown(self) {
        match shutdown_signal().await {
            Ok(signal) => tracing::info!(signal, "received graceful shutdown signal"),
            Err(error) => tracing::warn!(%error, "failed to listen for shutdown signal"),
        }
        self.graceful_shutdown.send_replace(true);
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;

    tokio::select! {
        received = interrupt.recv() => signal_name(received, "SIGINT"),
        received = terminate.recv() => signal_name(received, "SIGTERM"),
    }
}

#[cfg(unix)]
fn signal_name(received: Option<()>, name: &'static str) -> std::io::Result<&'static str> {
    received
        .map(|()| name)
        .ok_or_else(|| std::io::Error::other(format!("{name} signal stream closed")))
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("Ctrl+C")
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
