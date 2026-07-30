//! WebSocket TLS analysis and bounded message echo sessions.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{
        ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension,
};
use futures_util::SinkExt;
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::spawn_blocking_analysis;
use crate::server::tracker::info::{ConnectionTrack, TlsTrackInfo};

const MAX_SESSIONS: usize = 64;
const READ_BUFFER_SIZE: usize = 16 * 1024;
const WRITE_BUFFER_SIZE: usize = 16 * 1024;
const MAX_WRITE_BUFFER_SIZE: usize = 512 * 1024;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;
const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Limits upgraded sessions independently from the request concurrency layer.
#[derive(Clone)]
pub(super) struct Sessions(Arc<Semaphore>);

impl Sessions {
    pub(super) fn new(concurrent_limit: usize) -> Self {
        Self(Arc::new(Semaphore::new(
            concurrent_limit.clamp(1, MAX_SESSIONS),
        )))
    }

    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.0.clone().try_acquire_owned().ok()
    }
}

/// Upgrades a request and analyzes the TLS connection used by that WebSocket.
pub(super) async fn analyze(
    ws: WebSocketUpgrade,
    Extension(ConnectInfo(address)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    Extension(sessions): Extension<Sessions>,
) -> Response {
    let Some(permit) = sessions.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket session limit reached",
        )
            .into_response();
    };

    // A fragmented message can span several frames. Bound both levels as recommended by
    // RFC 6455, Section 10.4:
    // <https://www.rfc-editor.org/rfc/rfc6455#section-10.4>
    ws.read_buffer_size(READ_BUFFER_SIZE)
        .write_buffer_size(WRITE_BUFFER_SIZE)
        .max_write_buffer_size(MAX_WRITE_BUFFER_SIZE)
        .max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_FRAME_SIZE)
        .on_upgrade(move |socket| run(socket, address, track, permit))
}

async fn run(
    mut socket: WebSocket,
    address: SocketAddr,
    track: ConnectionTrack,
    _permit: OwnedSemaphorePermit,
) {
    let tls = match spawn_blocking_analysis(move || track.into_tls_info()).await {
        Ok(tls) => tls,
        Err(error) => {
            tracing::debug!(%error, %address, "WebSocket TLS analysis task failed");
            close_with_internal_error(&mut socket).await;
            return;
        }
    };

    if !send_connection_info(&mut socket, address, tls).await {
        return;
    }

    while let Some(message) = socket.recv().await {
        match message {
            Ok(message @ (Message::Text(_) | Message::Binary(_))) => {
                if socket.send(message).await.is_err() {
                    tracing::debug!(%address, "WebSocket closed while echoing a message");
                    return;
                }
            }
            Ok(Message::Close(frame)) => {
                if let Some(frame) = frame.as_ref() {
                    tracing::debug!(
                        %address,
                        code = frame.code,
                        reason = frame.reason.as_str(),
                        "WebSocket peer started the closing handshake"
                    );
                }

                // Tungstenite queues the peer's Close reply while reading it. Flush that reply
                // before dropping the stream, as required by RFC 6455, Section 7.1.2:
                // <https://www.rfc-editor.org/rfc/rfc6455#section-7.1.2>
                if SinkExt::close(&mut socket).await.is_err() {
                    tracing::debug!(%address, "WebSocket closing handshake failed");
                }
                return;
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Err(error) => {
                tracing::debug!(%error, %address, "WebSocket receive failed");
                return;
            }
        }
    }
}

async fn send_connection_info(
    socket: &mut WebSocket,
    address: SocketAddr,
    tls: Option<TlsTrackInfo>,
) -> bool {
    let event = ServerEvent::Connected {
        address,
        max_message_size: MAX_MESSAGE_SIZE,
        tls,
    };
    let payload = match serde_json::to_string(&event) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::debug!(%error, %address, "failed to serialize WebSocket TLS analysis");
            close_with_internal_error(socket).await;
            return false;
        }
    };

    if socket.send(Message::Text(payload.into())).await.is_err() {
        tracing::debug!(%address, "WebSocket closed before TLS analysis delivery");
        return false;
    }

    true
}

async fn close_with_internal_error(socket: &mut WebSocket) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code::ERROR,
            reason: "TLS analysis failed".into(),
        })))
        .await;
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    /// Connection metadata sent before application messages are echoed.
    Connected {
        /// Remote address observed by the server.
        address: SocketAddr,

        /// Maximum reassembled message size accepted by this endpoint.
        max_message_size: usize,

        /// ClientHello analysis for the upgraded connection.
        tls: Option<TlsTrackInfo>,
    },
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use serde_json::json;

    use super::{ServerEvent, Sessions, MAX_MESSAGE_SIZE};

    #[test]
    fn connected_event_has_a_stable_json_shape() {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
        let event = ServerEvent::Connected {
            address,
            max_message_size: MAX_MESSAGE_SIZE,
            tls: None,
        };

        assert_eq!(
            serde_json::to_value(event).unwrap(),
            json!({
                "type": "connected",
                "address": "127.0.0.1:443",
                "max_message_size": 262_144,
                "tls": null
            })
        );
    }

    #[test]
    fn session_permit_is_released_when_the_session_ends() {
        let sessions = Sessions::new(1);
        let permit = sessions.try_acquire().unwrap();

        assert!(sessions.try_acquire().is_none());
        drop(permit);
        assert!(sessions.try_acquire().is_some());
    }
}
