//! WebSocket connection analysis and bounded message echo sessions.

use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

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
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use super::spawn_blocking_analysis;
use crate::server::tracker::info::{ConnectionTrack, WebSocketTrackInfo};

const MAX_SESSIONS: usize = 64;
const MAX_SESSIONS_PER_IP: usize = 8;
const READ_BUFFER_SIZE: usize = 16 * 1024;
const WRITE_BUFFER_SIZE: usize = 16 * 1024;
const MAX_WRITE_BUFFER_SIZE: usize = 512 * 1024;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PREPARE_RETRY_STATUS: StatusCode = StatusCode::CONFLICT;

/// Limits upgraded sessions independently from the request concurrency layer.
#[derive(Clone)]
pub(super) struct Sessions(Arc<SessionLimits>);

struct SessionLimits {
    /// Global permits for active WebSocket sessions.
    global: Arc<Semaphore>,

    /// Active session counts grouped by remote IP address.
    peers: Mutex<HashMap<IpAddr, usize>>,
}

struct SessionPermit {
    /// Releases one global session slot when this guard is dropped.
    _global: OwnedSemaphorePermit,

    /// Remote IP address charged for this session.
    peer: IpAddr,

    /// Shared counters updated when this guard is dropped.
    limits: Arc<SessionLimits>,
}

impl Sessions {
    pub(super) fn new(concurrent_limit: usize) -> Self {
        Self(Arc::new(SessionLimits {
            global: Arc::new(Semaphore::new(concurrent_limit.clamp(1, MAX_SESSIONS))),
            peers: Mutex::new(HashMap::new()),
        }))
    }

    fn try_acquire(&self, peer: IpAddr) -> Option<SessionPermit> {
        let global = self.0.global.clone().try_acquire_owned().ok()?;
        let mut peers = self
            .0
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active = peers.entry(peer).or_default();
        if *active >= MAX_SESSIONS_PER_IP {
            return None;
        }
        *active += 1;
        drop(peers);

        Some(SessionPermit {
            _global: global,
            peer,
            limits: self.0.clone(),
        })
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        let mut peers = self
            .limits
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Entry::Occupied(mut entry) = peers.entry(self.peer) {
            if *entry.get() > 1 {
                *entry.get_mut() -= 1;
            } else {
                entry.remove();
            }
        }
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

    let Some(permit) = sessions.try_acquire(address.ip()) else {
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
        .max_frame_size(MAX_MESSAGE_SIZE)
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
    _permit: SessionPermit,
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

    loop {
        let message = match timeout(SESSION_IDLE_TIMEOUT, socket.recv()).await {
            Ok(Some(message)) => message,
            Ok(None) => return,
            Err(_) => {
                tracing::debug!(%address, "WebSocket session reached its idle timeout");
                let _ = send_bounded(
                    &mut socket,
                    Message::Close(Some(CloseFrame {
                        code: close_code::AWAY,
                        reason: "Idle timeout".into(),
                    })),
                )
                .await;
                return;
            }
        };

        match message {
            Ok(message @ (Message::Text(_) | Message::Binary(_))) => {
                if !send_bounded(&mut socket, message).await {
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
                if !matches!(
                    timeout(SESSION_WRITE_TIMEOUT, SinkExt::close(&mut socket)).await,
                    Ok(Ok(()))
                ) {
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

    if !send_bounded(socket, Message::Text(payload.into())).await {
        tracing::debug!(%address, "WebSocket closed before connection analysis delivery");
        return false;
    }

    true
}

async fn send_bounded(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        timeout(SESSION_WRITE_TIMEOUT, socket.send(message)).await,
        Ok(Ok(()))
    )
}

async fn close_with_internal_error(socket: &mut WebSocket) {
    let _ = send_bounded(
        socket,
        Message::Close(Some(CloseFrame {
            code: close_code::ERROR,
            reason: "Connection analysis failed".into(),
        })),
    )
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

    use super::{ServerEvent, Sessions, MAX_MESSAGE_SIZE, MAX_SESSIONS_PER_IP};
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
        let peer = Ipv4Addr::LOCALHOST.into();
        let permit = sessions.try_acquire(peer).unwrap();

        assert!(sessions.try_acquire(peer).is_none());
        drop(permit);
        assert!(sessions.try_acquire(peer).is_some());
    }

    #[test]
    fn one_peer_cannot_exhaust_the_global_session_limit() {
        let sessions = Sessions::new(MAX_SESSIONS_PER_IP + 1);
        let peer = Ipv4Addr::LOCALHOST.into();
        let permits = (0..MAX_SESSIONS_PER_IP)
            .map(|_| sessions.try_acquire(peer).unwrap())
            .collect::<Vec<_>>();

        assert!(sessions.try_acquire(peer).is_none());
        assert!(sessions
            .try_acquire(Ipv4Addr::new(192, 0, 2, 1).into())
            .is_some());

        drop(permits);
        assert!(sessions.try_acquire(peer).is_some());
    }
}
