use std::net::SocketAddr;

use axum::{
    body::Body,
    http::{header::USER_AGENT, Request},
};
use serde::{Serialize, Serializer};

use super::{
    inspector::{ClientHello, Frame, Http1Headers},
    Http2Frame,
};

/// TLS handshake tracking information, wrapping the parsed ClientHello.
#[derive(Serialize)]
pub struct TlsTrackInfo(ClientHello);

/// HTTP/1.x request header tracking information.
pub struct Http1TrackInfo(Http1Headers);

/// HTTP/2 tracking information, including Akamai fingerprint and sent frames.
#[derive(Serialize)]
pub struct Http2TrackInfo {
    akamai_fingerprint: String,
    akamai_fingerprint_hash: String,

    #[serde(serialize_with = "serialize_sent_frames")]
    sent_frames: Http2Frame,
}

/// Aggregated tracking information for a connection, including TLS, HTTP/1, and HTTP/2 details.
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

// ==== impl Http1TrackInfo ====

impl TlsTrackInfo {
    /// Create a new [`TlsTrackInfo`] instance.
    pub fn new(client_hello: ClientHello) -> TlsTrackInfo {
        TlsTrackInfo(client_hello)
    }
}

// ==== impl Http1TrackInfo ====

impl Http1TrackInfo {
    /// Create a new [`Http1TrackInfo`] instance.
    pub fn new(headers: Http1Headers) -> Http1TrackInfo {
        Http1TrackInfo(headers)
    }
}

impl Serialize for Http1TrackInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.count()))?;
        for (_, (name, value)) in self.0.iter() {
            let s = format!(
                "{}: {}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(value)
            );
            seq.serialize_element(&s)?;
        }
        seq.end()
    }
}

// ==== impl Http2TrackInfo ====

impl Http2TrackInfo {
    /// Create a new [`Http2TrackInfo`] instance.
    pub fn new(sent_frames: Http2Frame) -> Option<Http2TrackInfo> {
        if sent_frames.is_empty() {
            return None;
        }

        let akamai_fingerprint = compute_akamai_fingerprint(&sent_frames);
        let akamai_fingerprint_hash = compute_akamai_fingerprint_hash(&akamai_fingerprint);

        Some(Self {
            akamai_fingerprint,
            akamai_fingerprint_hash,
            sent_frames,
        })
    }
}

/// Compute the Akamai fingerprint hash from the Akamai fingerprint
fn compute_akamai_fingerprint_hash(akamai_fingerprint: &str) -> String {
    let hash = md5::compute(akamai_fingerprint);
    hex::encode(hash.as_slice())
}

/// Compute the Akamai fingerprint from the sent frames
///
/// The Akamai fingerprint is a string of 16 bytes that is computed from the sent frames.
/// It is used to identify the client and the server.
fn compute_akamai_fingerprint(sent_frames: &Http2Frame) -> String {
    let mut setting_group = Vec::new();
    let mut window_update_group = None;
    let mut priority_group = None;
    let mut headers_group = Vec::with_capacity(4);

    for (_, frame) in sent_frames.iter() {
        match frame {
            Frame::Settings(frame) => {
                for setting in &frame.settings {
                    let (id, value) = setting.value();
                    setting_group.push(format!("{id}:{value}"));
                }
            }
            Frame::WindowUpdate(frame) => {
                window_update_group = Some(frame.increment);
            }
            Frame::Priority(frame) => {
                let priority_group = priority_group.get_or_insert_with(Vec::new);
                priority_group.push(format!(
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    frame.priority.exclusive as u8,
                    frame.priority.depends_on,
                    frame.priority.weight as u16 + 1
                ));
            }
            Frame::Headers(frame) => {
                headers_group.push(format!("{}", frame.stream_id));
                headers_group.push(
                    frame
                        .pseudo_headers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                headers_group.push(format!("{}", frame.flags.0));
                if let Some(ref priority) = frame.priority {
                    headers_group.push(format!(
                        "{}:{}:{}",
                        priority.exclusive, priority.depends_on, priority.weight
                    ));
                }
            }
            Frame::Unknown(v) => {
                tracing::trace!("Unknown http2 frame: {:?}", v);
            }
        }
    }

    let mut akamai_fingerprint = Vec::with_capacity(3);

    akamai_fingerprint.push(setting_group.join(";"));

    if let Some(window_update_group) = window_update_group {
        akamai_fingerprint.push(window_update_group.to_string());
    }

    if let Some(priority_group) = priority_group {
        akamai_fingerprint.push(priority_group.join(","));
    }

    akamai_fingerprint.push(headers_group.join(";"));

    akamai_fingerprint.join("|")
}

fn serialize_sent_frames<S>(sent_frames: &Http2Frame, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let vec = sent_frames
        .iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    vec.serialize(serializer)
}

// ==== impl TrackInfo ====

impl<'a> TrackInfo<'a> {
    const DONATE_URL: &'static str = "Analysis server for TLS and HTTP/1/2/3, developed by 0x676e67: https://github.com/0x676e67/pingly";

    /// Create a new [`TrackInfo`] instance.
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
            donate: Self::DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http1,
            http2,
            tls,
        }
    }

    /// Create a new [`TrackInfo`] instance for TLS tracking.
    #[inline]
    pub fn new_tls_track(
        socket_addr: SocketAddr,
        req: &'a Request<Body>,
        tls: Option<TlsTrackInfo>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: Self::DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http1: None,
            http2: None,
            tls,
        }
    }

    /// Create a new [`TrackInfo`] instance for HTTP/1 tracking.
    #[inline]
    pub fn new_http1_track(
        socket_addr: SocketAddr,
        req: &'a Request<Body>,
        http1: Option<Http1TrackInfo>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: Self::DONATE_URL,
            socket_addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().as_str(),
            user_agent: headers.get(USER_AGENT).and_then(|v| v.to_str().ok()),
            http1,
            http2: None,
            tls: None,
        }
    }

    /// Create a new [`TrackInfo`] instance for HTTP/2 tracking.
    #[inline]
    pub fn new_http2_track(
        socket_addr: SocketAddr,
        req: &'a Request<Body>,
        http2: Option<Http2TrackInfo>,
    ) -> TrackInfo<'a> {
        let headers = req.headers();
        Self {
            donate: Self::DONATE_URL,
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
