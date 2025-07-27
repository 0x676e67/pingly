use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::IntoResponse,
    Extension,
};
use axum_extra::response::ErasedJson;

use super::track::TrackInfo;
use crate::{error::Error, track::ConnectionTrack, Result};

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        tracing::warn!("server track error: {}", self);
        (StatusCode::INTERNAL_SERVER_ERROR).into_response()
    }
}

#[inline]
pub async fn track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let (tls, http1, http2) = tokio::task::spawn_blocking(move || track.into_track_info()).await?;
    let info = TrackInfo::new(addr, &req, tls, http1, http2);
    Ok(ErasedJson::pretty(info))
}

#[inline]
pub async fn tls_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let tls = tokio::task::spawn_blocking(move || track.into_tls_track_info()).await?;
    let info = TrackInfo::new_tls_track(addr, tls, &req);
    Ok(ErasedJson::pretty(info))
}

#[inline]
pub async fn http1_headers(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let http1 = tokio::task::spawn_blocking(move || track.into_http1_headers()).await?;
    let info = TrackInfo::new_http1_track(addr, http1, &req);
    Ok(ErasedJson::pretty(info))
}

#[inline]
pub async fn http2_frames(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    let http2 = tokio::task::spawn_blocking(move || track.into_http2_track_info()).await?;
    let info = TrackInfo::new_http2_track(addr, http2, &req);
    Ok(ErasedJson::pretty(info))
}
