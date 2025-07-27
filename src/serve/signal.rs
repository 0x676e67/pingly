use std::time::Duration;

use axum_server::Handle;
use tokio::time::sleep;
use tracing::info;

pub(super) async fn graceful_shutdown(handle: Handle) {
    tokio::signal::ctrl_c()
        .await
        .expect("Ctrl+C signal hanlde error");

    info!("Ctrl+C signal received: starting graceful shutdown");

    // Signal the server to shutdown using Handle.
    handle.graceful_shutdown(Some(Duration::from_secs(1)));

    // Print alive connection count every second.
    loop {
        sleep(Duration::from_secs(1)).await;
        info!("Alive connections: {}", handle.connection_count());
    }
}
