use crate::track::{Http2TrackInfo, TlsTrackInfo};
use axum::{
    body::Body,
    http::{header::USER_AGENT, Request},
};
use serde::Serialize;
use std::net::SocketAddr;

const DONATE_URL: &str = "TLS/HTTP2 tracking server written in Rust, Developed by penumbra-x. https://github.com/penumbra-x/pingly";

#[derive(Serialize)]
pub struct TrackInfo<'a> {
    donate: &'static str,
    socket_addr: SocketAddr,
    http_version: String,
    method: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsTrackInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http2: Option<Http2TrackInfo>,
}

impl<'a> TrackInfo<'a> {
    #[inline]
    pub fn new(
        socket_addr: SocketAddr,
        tls: Option<TlsTrackInfo>,
        http2: Option<Http2TrackInfo>,
        req: &'a Request<Body>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http2,
            tls,
        }
    }

    #[inline]
    pub fn new_tls_track(
        socket_addr: SocketAddr,
        tls: Option<TlsTrackInfo>,
        req: &'a Request<Body>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http2: None,
            tls,
        }
    }

    #[inline]
    pub fn new_http2_track(
        socket_addr: SocketAddr,
        http2: Option<Http2TrackInfo>,
        req: &'a Request<Body>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http2,
            tls: None,
        }
    }
}
