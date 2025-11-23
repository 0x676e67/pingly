use std::time::Duration;

use axum_server::Handle;
use tokio::time::sleep;
use tracing::info;

#[cfg(target_os = "linux")]
use super::tracker::capture::TcpCaptureTrack;

pub(super) async fn graceful_shutdown(
    handle: Handle,
    #[cfg(target_os = "linux")] capture: Option<TcpCaptureTrack>,
) {
    tokio::signal::ctrl_c()
        .await
        .expect("Ctrl+C signal hanlde error");

    info!("Ctrl+C signal received: starting graceful shutdown");

    #[cfg(target_os = "linux")]
    if let Some(capture) = capture {
        capture.shutdown();
    }

    // Signal the server to shutdown using Handle.
    handle.graceful_shutdown(Some(Duration::from_secs(1)));

    // Print alive connection count every second.
    loop {
        sleep(Duration::from_secs(1)).await;
        let connections = handle.connection_count();
        info!("Alive connections: {}", connections);

        // Exit the loop when all connections are closed
        if connections == 0 {
            info!("All connections closed, exiting gracefully");
            break;
        }
    }
}
