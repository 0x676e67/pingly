//! Request handlers for the protocol analysis endpoints.

#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use std::{net::SocketAddr, sync::LazyLock};

#[cfg(target_os = "linux")]
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
    Extension, Router,
};
use axum_extra::response::ErasedJson;
#[cfg(target_os = "linux")]
use futures_util::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::tracker::info::{ConnectionTrack, Track, TrackInfo};
#[cfg(target_os = "linux")]
use crate::tcp::{ProxyAnalysis, TcpAnalysis, TcpCapture};
use crate::{error::Error, Result};

const INDEX_PATH: &str = "/";
const ALL_PATH: &str = "/api/all";
const TLS_PATH: &str = "/api/tls";
const HTTP1_PATH: &str = "/api/http1";
const HTTP2_PATH: &str = "/api/http2";
const HTTP3_PATH: &str = "/api/http3";
const TCP_PATH: &str = "/api/tcp";
const LATENCY_PATH: &str = "/api/latency";

#[cfg(target_os = "linux")]
const LATENCY_PROBE_SAMPLES: u8 = 8;
#[cfg(target_os = "linux")]
const LATENCY_PROBE_INTERVAL: Duration = Duration::from_millis(25);
#[cfg(target_os = "linux")]
const LATENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

const UI_TEMPLATE: &str = include_str!("ui/index.html");
const UI_SCRIPT: &str = include_str!("ui/app.js");
const UI_SCRIPT_MARKER: &str = "<!-- PINGLY_SCRIPT -->";
const UI_ROUTES_MARKER: &str = "/* PINGLY_ROUTES */ []";
const ANY_METHOD: &str = "ANY";
const ALWAYS_AVAILABLE: &str = "Always";
const LINUX_CAPTURE_AVAILABLE: &str = "Linux + capture";

#[derive(Serialize)]
struct PublicRoute {
    /// HTTP method shown in the route directory.
    method: &'static str,

    /// Absolute path registered by the server.
    path: &'static str,

    /// Short description shown in the interface.
    purpose: &'static str,

    /// Runtime conditions required for the route.
    availability: &'static str,
}

const PUBLIC_ROUTES: &[PublicRoute] = &[
    PublicRoute {
        method: "GET",
        path: INDEX_PATH,
        purpose: "Protocol inspector",
        availability: ALWAYS_AVAILABLE,
    },
    PublicRoute {
        method: ANY_METHOD,
        path: ALL_PATH,
        purpose: "Complete analysis",
        availability: ALWAYS_AVAILABLE,
    },
    PublicRoute {
        method: ANY_METHOD,
        path: TLS_PATH,
        purpose: "TLS analysis",
        availability: ALWAYS_AVAILABLE,
    },
    PublicRoute {
        method: ANY_METHOD,
        path: HTTP1_PATH,
        purpose: "HTTP/1 analysis",
        availability: ALWAYS_AVAILABLE,
    },
    PublicRoute {
        method: ANY_METHOD,
        path: HTTP2_PATH,
        purpose: "HTTP/2 analysis",
        availability: ALWAYS_AVAILABLE,
    },
    PublicRoute {
        method: ANY_METHOD,
        path: HTTP3_PATH,
        purpose: "HTTP/3 and QUIC analysis",
        availability: ALWAYS_AVAILABLE,
    },
    PublicRoute {
        method: ANY_METHOD,
        path: TCP_PATH,
        purpose: "TCP packet capture",
        availability: LINUX_CAPTURE_AVAILABLE,
    },
    PublicRoute {
        method: "WS",
        path: LATENCY_PATH,
        purpose: "Cross-layer latency probe",
        availability: LINUX_CAPTURE_AVAILABLE,
    },
];

static UI_DOCUMENT: LazyLock<Box<str>> = LazyLock::new(build_ui_document);

// Compression can change the transfer bytes without changing the UI document, so the
// validator is weak across content codings.
// https://www.rfc-editor.org/rfc/rfc9110.html#name-entity-tag
static UI_ETAG_TEXT: LazyLock<Box<str>> = LazyLock::new(|| {
    let digest = Sha256::digest(UI_DOCUMENT.as_bytes());
    format!("W/\"{}\"", hex::encode(digest)).into_boxed_str()
});

static UI_ETAG_VALUE: LazyLock<HeaderValue> = LazyLock::new(|| {
    HeaderValue::from_str(UI_ETAG_TEXT.as_ref())
        .unwrap_or_else(|_| HeaderValue::from_static("W/\"pingly-ui\""))
});

/// Builds the public routes and enables optional platform routes.
pub(crate) fn router(#[cfg(target_os = "linux")] tcp_capture: Option<&TcpCapture>) -> Router {
    let router = Router::new()
        .route(INDEX_PATH, get(index))
        .route(ALL_PATH, any(track))
        .route(TLS_PATH, any(tls_track))
        .route(HTTP1_PATH, any(http1_track))
        .route(HTTP2_PATH, any(http2_track))
        .route(HTTP3_PATH, any(http3_track));

    #[cfg(target_os = "linux")]
    let router = if let Some(capture) = tcp_capture {
        router
            .route(TCP_PATH, any(tcp_track))
            .route(LATENCY_PATH, any(latency_probe))
            .layer(Extension(capture.clone()))
    } else {
        router
    };

    router
}

fn build_ui_document() -> Box<str> {
    let routes = serde_json::to_string(PUBLIC_ROUTES).unwrap_or_else(|_| "[]".to_owned());
    let Some((script_head, script_tail)) = UI_SCRIPT.split_once(UI_ROUTES_MARKER) else {
        return UI_TEMPLATE.into();
    };

    let mut script = String::with_capacity(UI_SCRIPT.len() + routes.len());
    script.push_str(script_head);
    script.push_str(&routes);
    script.push_str(script_tail);

    let Some((body, tail)) = UI_TEMPLATE.split_once(UI_SCRIPT_MARKER) else {
        return UI_TEMPLATE.into();
    };

    let mut document = String::with_capacity(UI_TEMPLATE.len() + script.len() + 17);
    document.push_str(body);
    document.push_str("<script>");
    document.push_str(&script);
    document.push_str("</script>");
    document.push_str(tail);
    document.into_boxed_str()
}

fn matches_ui_etag(headers: &HeaderMap) -> bool {
    for value in headers.get_all(header::IF_NONE_MATCH) {
        let Ok(value) = value.to_str() else {
            continue;
        };

        // GET and HEAD use weak comparison for If-None-Match validators.
        // https://www.rfc-editor.org/rfc/rfc9110.html#name-if-none-match
        if value.split(',').any(|candidate| {
            let candidate = candidate.trim();
            let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
            let current = UI_ETAG_TEXT
                .strip_prefix("W/")
                .unwrap_or(UI_ETAG_TEXT.as_ref());

            candidate == "*" || candidate == current
        }) {
            return true;
        }
    }

    false
}

/// Serves the protocol analysis interface as a single cache-revalidated document.
pub(crate) async fn index(request_headers: HeaderMap) -> Response {
    let mut response = if matches_ui_etag(&request_headers) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let document: &'static str = UI_DOCUMENT.as_ref();
        Html(document).into_response()
    };

    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    response_headers.insert(header::ETAG, UI_ETAG_VALUE.clone());
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );

    response
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::warn!(%self, "server track error");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

fn spawn_blocking_analysis<F, R>(analysis: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let span = tracing::Span::current();

    // Blocking tasks do not automatically inherit the request's current tracing span.
    tokio::task::spawn_blocking(move || span.in_scope(analysis))
}

#[inline]
pub(crate) async fn track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    #[cfg(target_os = "linux")] tcp_capture: Option<Extension<TcpCapture>>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    #[cfg(target_os = "linux")]
    let tcp_packets = if let Some(Extension(capture)) = tcp_capture {
        capture.connection_packets(addr)
    } else {
        Vec::new()
    };

    #[cfg(target_os = "linux")]
    {
        spawn_blocking_analysis(move || {
            TrackInfo::new_with_tcp(Track::All, addr, req, track, tcp_packets)
        })
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
    }

    #[cfg(not(target_os = "linux"))]
    {
        spawn_blocking_analysis(move || TrackInfo::new(Track::All, addr, req, track))
            .await
            .map(ErasedJson::pretty)
            .map_err(Error::from)
    }
}

#[inline]
pub(crate) async fn tls_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::Tls, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub(crate) async fn http1_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::HTTP1, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub(crate) async fn http2_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::HTTP2, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub(crate) async fn http3_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::HTTP3, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) async fn tcp_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(capture): Extension<TcpCapture>,
) -> Result<ErasedJson> {
    let analysis = TcpAnalysis::from_packets(capture.connection_packets(addr));
    Ok(ErasedJson::pretty(analysis))
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) async fn latency_probe(
    ws: WebSocketUpgrade,
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    Extension(capture): Extension<TcpCapture>,
) -> Response {
    let tls_handshake_duration = track.tls_handshake_duration();
    ws.max_message_size(1_024)
        .max_frame_size(1_024)
        .on_upgrade(move |socket| async move {
            run_latency_probe(socket, addr, capture, tls_handshake_duration).await;
        })
}

#[cfg(target_os = "linux")]
async fn run_latency_probe(
    mut socket: WebSocket,
    addr: SocketAddr,
    capture: TcpCapture,
    tls_handshake_duration: Option<Duration>,
) {
    let mut samples = Vec::with_capacity(usize::from(LATENCY_PROBE_SAMPLES));

    for sequence in 1..=LATENCY_PROBE_SAMPLES {
        let message = LatencySocketMessage::Probe {
            sequence,
            total: LATENCY_PROBE_SAMPLES,
        };
        let Ok(payload) = serde_json::to_string(&message) else {
            tracing::debug!(%addr, "failed to serialize latency probe message");
            return;
        };

        let started = Instant::now();
        if socket
            .send(Message::Text(payload.clone().into()))
            .await
            .is_err()
        {
            tracing::debug!(%addr, "latency probe WebSocket closed while sending");
            return;
        }
        if !wait_for_probe_echo(&mut socket, &payload).await {
            tracing::debug!(%addr, sequence, "latency probe echo timed out or disconnected");
            return;
        }
        samples.push(started.elapsed());

        if sequence < LATENCY_PROBE_SAMPLES {
            tokio::time::sleep(LATENCY_PROBE_INTERVAL).await;
        }
    }

    let packets = capture.connection_packets(addr);
    let analysis = ProxyAnalysis::from_connection(addr, &packets, tls_handshake_duration, samples);
    let message = LatencySocketMessage::Result {
        analysis: &analysis,
    };
    let Ok(payload) = serde_json::to_string(&message) else {
        tracing::debug!(%addr, "failed to serialize latency analysis");
        return;
    };

    if socket.send(Message::Text(payload.into())).await.is_err() {
        tracing::debug!(%addr, "latency probe WebSocket closed before result delivery");
        return;
    }
    let _ = socket.send(Message::Close(None)).await;
}

#[cfg(target_os = "linux")]
async fn wait_for_probe_echo(socket: &mut WebSocket, expected: &str) -> bool {
    let receive = async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Text(payload)) if payload.as_str() == expected => return true,
                Ok(Message::Close(_)) | Err(_) => return false,
                _ => {}
            }
        }
        false
    };

    tokio::time::timeout(LATENCY_PROBE_TIMEOUT, receive)
        .await
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LatencySocketMessage<'a> {
    Probe { sequence: u8, total: u8 },
    Result { analysis: &'a ProxyAnalysis },
}
