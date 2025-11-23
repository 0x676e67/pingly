use std::net::SocketAddr;

use axum::{
    body::Body,
    http::{header::USER_AGENT, HeaderValue, Method, Request},
};
use serde::{Serialize, Serializer};
use tokio_rustls::rustls::ProtocolVersion;

use super::inspector::{ClientHello, Frame, Http1Headers, Http2Frame, LazyClientHello};

#[cfg(target_os = "linux")]
use super::capture::CapturedPacket;

/// TLS handshake tracking information, which includes the client hello payload.
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

/// Collects TLS, HTTP/1, and HTTP/2 handshake info for tracking.
#[derive(Clone, Default)]
pub struct ConnectionTrack {
    /// The TLS protocol version that was negotiated for this connection, if any.
    tls_version_negotiated: Option<ProtocolVersion>,
    client_hello: Option<LazyClientHello>,
    http1_headers: Option<Http1Headers>,
    http2_frames: Option<Http2Frame>,
}

/// TrackInfo aggregates tracking details for a single connection,
/// including TLS handshake info, HTTP/1 headers, and HTTP/2 frames.
/// Useful for logging, analysis, or debugging connection
#[derive(Serialize)]
pub struct TrackInfo {
    donate: &'static str,
    address: SocketAddr,
    http_version: String,

    #[serde(serialize_with = "serialize_method")]
    method: Method,

    #[serde(serialize_with = "serialize_user_agent")]
    user_agent: Option<HeaderValue>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsTrackInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http1: Option<Http1TrackInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http2: Option<Http2TrackInfo>,

    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tcp: Vec<CapturedPacket>,
}

/// Track enum to specify which tracking information to collect.
#[repr(u8)]
pub enum Track {
    All,
    Tls,
    HTTP1,
    HTTP2,
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
                    frame.priority.exclusive,
                    frame.priority.depends_on,
                    frame.priority.weight + 1
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

// ==== impl ConnectionTrack ====

impl ConnectionTrack {
    /// Set TLS version negotiated during the handshake.
    #[inline]
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.tls_version_negotiated = version;
    }

    /// Set TLS client hello
    #[inline]
    pub fn set_client_hello(&mut self, client_hello: Option<LazyClientHello>) {
        self.client_hello = client_hello;
    }

    /// Set HTTP/1 headers
    #[inline]
    pub fn set_http1_headers(&mut self, headers: Http1Headers) {
        self.http1_headers = Some(headers);
    }

    /// Set HTTP/2 frames
    #[inline]
    pub fn set_http2_frames(&mut self, frames: Http2Frame) {
        self.http2_frames = Some(frames);
    }
}

// ==== impl TrackInfo ====

impl TrackInfo {
    const DONATE_URL: &'static str = "Analysis server for TLS and HTTP/1/2/3, developed by 0x676e67: https://github.com/0x676e67/pingly";

    /// Create a new [`TrackInfo`] instance.
    #[inline]
    pub fn new(
        track: Track,
        addr: SocketAddr,
        req: Request<Body>,
        connection_track: ConnectionTrack,
    ) -> TrackInfo {
        #[cfg(target_os = "linux")]
        return Self::new_with_tcp(track, addr, req, connection_track, Vec::new());

        #[cfg(not(target_os = "linux"))]
        {
            let mut tls = connection_track
                .client_hello
                .and_then(LazyClientHello::parse)
                .map(TlsTrackInfo::new);

            if let Some(tls) = tls.as_mut() {
                tls.0
                    .set_tls_version_negotiated(connection_track.tls_version_negotiated);
            }

            let track_info = TrackInfo {
                donate: Self::DONATE_URL,
                address: addr,
                http_version: format!("{:?}", req.version()),
                method: req.method().clone(),
                user_agent: req.headers().get(USER_AGENT).cloned(),
                tls,
                http1: connection_track.http1_headers.map(Http1TrackInfo::new),
                http2: connection_track.http2_frames.and_then(Http2TrackInfo::new),
            };

            match track {
                Track::All => track_info,
                Track::Tls => TrackInfo {
                    http1: None,
                    http2: None,
                    ..track_info
                },
                Track::HTTP1 => TrackInfo {
                    tls: None,
                    http2: None,
                    ..track_info
                },
                Track::HTTP2 => TrackInfo {
                    tls: None,
                    http1: None,
                    ..track_info
                },
            }
        }
    }

    /// Create a new [`TrackInfo`] instance with TCP data.
    #[inline]
    #[cfg(target_os = "linux")]
    pub fn new_with_tcp(
        track: Track,
        addr: SocketAddr,
        req: Request<Body>,
        connection_track: ConnectionTrack,
        tcp_packets: Vec<CapturedPacket>,
    ) -> TrackInfo {
        let mut tls = connection_track
            .client_hello
            .and_then(LazyClientHello::parse)
            .map(TlsTrackInfo::new);

        if let Some(tls) = tls.as_mut() {
            tls.0
                .set_tls_version_negotiated(connection_track.tls_version_negotiated);
        }

        let track_info = TrackInfo {
            donate: Self::DONATE_URL,
            address: addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().clone(),
            user_agent: req.headers().get(USER_AGENT).cloned(),
            tls,
            http1: connection_track.http1_headers.map(Http1TrackInfo::new),
            http2: connection_track.http2_frames.and_then(Http2TrackInfo::new),
            #[cfg(target_os = "linux")]
            tcp: tcp_packets,
        };

        match track {
            Track::All => track_info,
            Track::Tls => TrackInfo {
                http1: None,
                http2: None,
                #[cfg(target_os = "linux")]
                tcp: Vec::new(),
                ..track_info
            },
            Track::HTTP1 => TrackInfo {
                tls: None,
                http2: None,
                #[cfg(target_os = "linux")]
                tcp: Vec::new(),
                ..track_info
            },
            Track::HTTP2 => TrackInfo {
                tls: None,
                http1: None,
                #[cfg(target_os = "linux")]
                tcp: Vec::new(),
                ..track_info
            },
        }
    }
}

fn serialize_user_agent<S>(value: &Option<HeaderValue>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => value
            .to_str()
            .map_err(serde::ser::Error::custom)
            .and_then(|s| serializer.serialize_str(s)),
        None => serializer.serialize_none(),
    }
}

fn serialize_method<S>(method: &Method, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(method.as_str())
}
