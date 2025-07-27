use std::net::SocketAddr;

use axum::{
    body::Body,
    http::{header::USER_AGENT, Request},
};
use serde::Serialize;

use crate::track::info::{Http1TrackInfo, Http2TrackInfo, TlsTrackInfo};

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
    http1: Option<Http1TrackInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http2: Option<Http2TrackInfo>,
}

impl<'a> TrackInfo<'a> {
    #[inline]
    pub fn new(
        socket_addr: SocketAddr,
        req: &'a Request<Body>,
        tls: Option<TlsTrackInfo>,
        http1: Option<Http1TrackInfo>,
        http2: Option<Http2TrackInfo>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http1,
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
            http1: None,
            http2: None,
            tls,
        }
    }

    #[inline]
    pub fn new_http1_track(
        socket_addr: SocketAddr,
        http1: Option<Http1TrackInfo>,
        req: &'a Request<Body>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http1,
            http2: None,
            tls: None,
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
            http1: None,
            http2,
            tls: None,
        }
    }
}
