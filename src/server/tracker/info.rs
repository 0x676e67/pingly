use std::net::SocketAddr;

use axum::{
    body::Body,
    http::{header::USER_AGENT, HeaderValue, Method, Request},
};
use serde::{Serialize, Serializer};
use tokio_rustls::rustls::ProtocolVersion;

use crate::http2::AkamaiFingerprint;

#[cfg(target_os = "linux")]
use crate::tcp::CapturedPacket;

use super::inspector::{ClientHello, Http1Headers, Http2Frame, LazyClientHello};

/// TLS handshake tracking information, which includes the client hello payload.
#[derive(Serialize)]
pub struct TlsTrackInfo {
    ja3: String,
    ja3_hash: String,
    #[serde(rename = "ja4")]
    ja4_fingerprint: String,
    #[serde(rename = "ja4_r")]
    ja4_raw: String,
    #[serde(flatten)]
    client_hello: ClientHello,
}

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
        let (ja3, ja3_hash) = client_hello.ja3_fingerprint();
        let (ja4_fingerprint, ja4_raw) = client_hello.ja4_fingerprint();

        TlsTrackInfo {
            ja3,
            ja3_hash,
            ja4_fingerprint,
            ja4_raw,
            client_hello,
        }
    }

    /// Set TLS version negotiated during the handshake.
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.client_hello.set_tls_version_negotiated(version);
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
        let akamai = AkamaiFingerprint::from_frames(&sent_frames)?;

        Some(Self {
            akamai_fingerprint: akamai.fingerprint,
            akamai_fingerprint_hash: akamai.hash,
            sent_frames,
        })
    }
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
                tls.set_tls_version_negotiated(connection_track.tls_version_negotiated);
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
            tls.set_tls_version_negotiated(connection_track.tls_version_negotiated);
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
