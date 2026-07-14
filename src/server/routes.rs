//! Request handlers for the protocol analysis endpoints.

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::time::Duration;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::IntoResponse,
    Extension,
};
use axum_extra::response::ErasedJson;

use super::tracker::info::{ConnectionTrack, Track, TrackInfo};
#[cfg(target_os = "linux")]
use crate::proto::tcp::TcpCaptureTrack;
use crate::{error::Error, Result};

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        tracing::warn!(%self, "server track error");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[inline]
pub(crate) async fn track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    #[cfg(target_os = "linux")] tcp_capture: Option<Extension<TcpCaptureTrack>>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    #[cfg(target_os = "linux")]
    let tcp_packets = if let Some(Extension(capture)) = tcp_capture {
        // Give libpcap a moment to publish packets from this connection before reading them.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_ip = addr.ip().to_string();
        let client_port = addr.port();
        let packets = capture.get_packets_for_client(&client_ip, client_port);
        capture.clear_packets_for_client(&client_ip, client_port);
        packets
    } else {
        Vec::new()
    };

    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || {
            TrackInfo::new_with_tcp(Track::All, addr, req, track, tcp_packets)
        })
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
    }

    #[cfg(not(target_os = "linux"))]
    {
        tokio::task::spawn_blocking(move || TrackInfo::new(Track::All, addr, req, track))
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
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::Tls, addr, req, track))
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
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::HTTP1, addr, req, track))
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
    tokio::task::spawn_blocking(move || TrackInfo::new(Track::HTTP2, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) async fn tcp_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(capture): Extension<TcpCaptureTrack>,
) -> Result<ErasedJson> {
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_ip = addr.ip().to_string();
    let client_port = addr.port();
    let packets = capture.get_packets_for_client(&client_ip, client_port);
    capture.clear_packets_for_client(&client_ip, client_port);

    Ok(ErasedJson::pretty(&packets))
}
