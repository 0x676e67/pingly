//! WebSocket connection analysis and bounded message echo sessions.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{
        ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo,
    },
    http::{header, HeaderValue, StatusCode, Version},
    response::{IntoResponse, Response},
    Extension,
};
use futures_util::SinkExt;
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::spawn_blocking_analysis;
use crate::server::tracker::info::{ConnectionTrack, WebSocketTrackInfo};

const MAX_SESSIONS: usize = 64;
const READ_BUFFER_SIZE: usize = 16 * 1024;
const WRITE_BUFFER_SIZE: usize = 16 * 1024;
const MAX_WRITE_BUFFER_SIZE: usize = 512 * 1024;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;
const MAX_FRAME_SIZE: usize = 64 * 1024;
const PREPARE_RETRY_STATUS: StatusCode = StatusCode::CONFLICT;

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

/// Upgrades a request and analyzes its TLS connection and opening handshake.
pub(super) async fn analyze(
    version: Version,
    ws: WebSocketUpgrade,
    Extension(ConnectInfo(address)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    Extension(sessions): Extension<Sessions>,
) -> Response {
    if !matches!(version, Version::HTTP_11 | Version::HTTP_2) {
        return (
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "WebSocket requires HTTP/1.1 or HTTP/2",
        )
            .into_response();
    }

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
        .on_upgrade(move |socket| run(socket, address, version, track, permit))
}

/// Closes any reusable TCP protocol session before the browser starts an HTTP/1.1 WebSocket.
pub(super) async fn prepare_http1(version: Version) -> Response {
    let status = if version == Version::HTTP_3 {
        PREPARE_RETRY_STATUS
    } else {
        StatusCode::NO_CONTENT
    };
    preparation_response(status, true)
}

/// Leaves one HTTP/2 connection ready for an RFC 8441 extended CONNECT request.
pub(super) async fn prepare_http2(version: Version) -> Response {
    match version {
        Version::HTTP_2 => preparation_response(StatusCode::NO_CONTENT, false),
        Version::HTTP_3 => preparation_response(PREPARE_RETRY_STATUS, true),
        _ => preparation_response(StatusCode::HTTP_VERSION_NOT_SUPPORTED, true),
    }
}

fn preparation_response(status: StatusCode, clear_alt_svc: bool) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    if clear_alt_svc {
        // Clearing cached alternatives lets the next browser request return from HTTP/3 to TCP.
        // RFC 7838, Section 3:
        // <https://www.rfc-editor.org/rfc/rfc7838#section-3>
        response
            .headers_mut()
            .insert(header::ALT_SVC, HeaderValue::from_static("clear"));
    }

    response
}

async fn run(
    mut socket: WebSocket,
    address: SocketAddr,
    version: Version,
    track: ConnectionTrack,
    _permit: OwnedSemaphorePermit,
) {
    let analysis = match spawn_blocking_analysis(move || track.into_websocket_info()).await {
        Ok(analysis) => analysis,
        Err(error) => {
            tracing::debug!(%error, %address, "WebSocket connection analysis task failed");
            close_with_internal_error(&mut socket).await;
            return;
        }
    };

    if !send_connection_info(&mut socket, address, version, analysis).await {
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
    version: Version,
    analysis: WebSocketTrackInfo,
) -> bool {
    let event = ServerEvent::Connected {
        address,
        http_version: format!("{version:?}").into_boxed_str(),
        max_message_size: MAX_MESSAGE_SIZE,
        analysis,
    };
    let payload = match serde_json::to_string(&event) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::debug!(%error, %address, "failed to serialize WebSocket connection analysis");
            close_with_internal_error(socket).await;
            return false;
        }
    };

    if socket.send(Message::Text(payload.into())).await.is_err() {
        tracing::debug!(%address, "WebSocket closed before connection analysis delivery");
        return false;
    }

    true
}

async fn close_with_internal_error(socket: &mut WebSocket) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code::ERROR,
            reason: "Connection analysis failed".into(),
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

        /// HTTP version that carried the WebSocket handshake.
        http_version: Box<str>,

        /// Maximum reassembled message size accepted by this endpoint.
        max_message_size: usize,

        /// TLS and opening-handshake analysis for the upgraded connection.
        #[serde(flatten)]
        analysis: WebSocketTrackInfo,
    },
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use axum::http::Version;
    use serde_json::json;

    use super::{ServerEvent, Sessions, MAX_MESSAGE_SIZE};
    use crate::server::tracker::info::WebSocketTrackInfo;

    #[test]
    fn connected_event_has_a_stable_json_shape() {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
        let event = ServerEvent::Connected {
            address,
            http_version: format!("{:?}", Version::HTTP_2).into_boxed_str(),
            max_message_size: MAX_MESSAGE_SIZE,
            analysis: WebSocketTrackInfo {
                tls: None,
                headers: None,
            },
        };

        assert_eq!(
            serde_json::to_value(event).unwrap(),
            json!({
                "type": "connected",
                "address": "127.0.0.1:443",
                "http_version": "HTTP/2.0",
                "max_message_size": 262_144,
                "headers": null,
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
