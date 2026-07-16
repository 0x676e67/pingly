use std::{borrow::Cow, net::SocketAddr};

use axum::{
    body::Body,
    http::{header::USER_AGENT, HeaderValue, Method, Request},
};
use serde::{Serialize, Serializer};
use tokio_rustls::rustls::ProtocolVersion;

use super::inspector::{ClientHello, ClientHelloBuffer, Http1Headers, Http2Frame};
use crate::proto::{http2::AkamaiFingerprint, tls::TlsVersion};
#[cfg(target_os = "linux")]
use crate::tcp::CapturedPacket;

/// A captured HTTP header field, preserving the original order.
#[derive(Serialize)]
pub struct HeaderField<'a> {
    /// Header name rendered as UTF-8 text, replacing invalid byte sequences.
    name: Cow<'a, str>,

    /// Header value rendered as UTF-8 text, replacing invalid byte sequences.
    value: Cow<'a, str>,
}

/// TLS handshake tracking information, which includes the client hello payload.
#[derive(Serialize)]
pub struct TlsTrackInfo {
    /// The unhashed JA3 string built from the ClientHello.
    ja3: Box<str>,

    /// The lowercase MD5 digest of the JA3 string.
    ja3_hash: Box<str>,

    /// The JA4 fingerprint derived from the ClientHello.
    #[serde(rename = "ja4")]
    ja4_fingerprint: Box<str>,

    /// The unhashed JA4_r representation used to inspect its input values.
    #[serde(rename = "ja4_r")]
    ja4_raw: Box<str>,

    /// Parsed ClientHello fields flattened into the TLS response object.
    #[serde(flatten)]
    client_hello: ClientHello,
}

/// HTTP/1.x request header tracking information.
pub struct Http1TrackInfo(Http1Headers);

/// HTTP/2 tracking information, including Akamai fingerprint and sent frames.
#[derive(Serialize)]
pub struct Http2TrackInfo {
    /// The unhashed Akamai fingerprint derived from the captured client frames.
    akamai_fingerprint: Box<str>,

    /// The lowercase MD5 digest of the Akamai fingerprint.
    akamai_fingerprint_hash: Box<str>,

    /// Client HTTP/2 frames retained in their original wire order.
    #[serde(serialize_with = "serialize_sent_frames")]
    sent_frames: Http2Frame,
}

/// Collects TLS, HTTP/1, and HTTP/2 handshake info for tracking.
#[derive(Clone, Default)]
pub struct ConnectionTrack {
    /// The TLS protocol version that was negotiated for this connection, if any.
    tls_version_negotiated: Option<ProtocolVersion>,

    /// Raw TLS records retained until the ClientHello can be analyzed.
    client_hello: Option<ClientHelloBuffer>,

    /// HTTP/1 request headers retained in their received order.
    http1_headers: Option<Http1Headers>,

    /// HTTP/2 client frames retained in their received order.
    http2_frames: Option<Http2Frame>,
}

/// Tracking details collected for a single connection.
///
/// Includes the TLS, HTTP/1, and HTTP/2 analysis selected for the response.
#[derive(Serialize)]
pub struct TrackInfo {
    /// Project information included in every analysis response.
    donate: &'static str,

    /// Remote peer address associated with the request.
    address: SocketAddr,

    /// HTTP version used by the request.
    http_version: String,

    /// HTTP request method.
    #[serde(serialize_with = "serialize_method")]
    method: Method,

    /// User-Agent request header, when present.
    #[serde(serialize_with = "serialize_user_agent")]
    user_agent: Option<HeaderValue>,

    /// TLS analysis requested for this response, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsTrackInfo>,

    /// HTTP/1 header analysis requested for this response, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    http1: Option<Http1TrackInfo>,

    /// HTTP/2 frame analysis requested for this response, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    http2: Option<Http2TrackInfo>,

    /// Captured TCP packets included by the Linux `/api/all` endpoint.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tcp: Vec<CapturedPacket>,
}

/// Track enum to specify which tracking information to collect.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Track {
    All,
    Tls,
    HTTP1,
    HTTP2,
}

impl Track {
    const fn includes_tls(self) -> bool {
        matches!(self, Track::All | Track::Tls)
    }

    const fn includes_http1(self) -> bool {
        matches!(self, Track::All | Track::HTTP1)
    }

    const fn includes_http2(self) -> bool {
        matches!(self, Track::All | Track::HTTP2)
    }
}

struct ProtocolTrackInfo {
    tls: Option<TlsTrackInfo>,

    http1: Option<Http1TrackInfo>,

    http2: Option<Http2TrackInfo>,
}

// ==== impl Http1TrackInfo ====

impl TlsTrackInfo {
    /// Create a new [`TlsTrackInfo`] instance.
    pub fn new(client_hello: ClientHello) -> TlsTrackInfo {
        let ja3 = client_hello.ja3();
        let ja4 = client_hello.ja4();

        TlsTrackInfo {
            ja3: ja3.raw,
            ja3_hash: ja3.hash,
            ja4_fingerprint: ja4.fingerprint,
            ja4_raw: ja4.raw,
            client_hello,
        }
    }

    /// Set TLS version negotiated during the handshake.
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.client_hello
            .set_tls_version_negotiated(version.map(u16::from).map(TlsVersion::from));
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
            seq.serialize_element(&HeaderField {
                name: String::from_utf8_lossy(name),
                value: String::from_utf8_lossy(value),
            })?;
        }
        seq.end()
    }
}

// ==== impl Http2TrackInfo ====

impl Http2TrackInfo {
    /// Create a new [`Http2TrackInfo`] instance.
    pub fn new(sent_frames: Http2Frame) -> Option<Http2TrackInfo> {
        let akamai = AkamaiFingerprint::from_frames(sent_frames.iter().map(|(_, frame)| frame))?;

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
    pub fn set_client_hello(&mut self, client_hello: Option<ClientHelloBuffer>) {
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

fn protocol_track_info(track: Track, connection_track: ConnectionTrack) -> ProtocolTrackInfo {
    let ConnectionTrack {
        tls_version_negotiated,
        client_hello,
        http1_headers,
        http2_frames,
    } = connection_track;

    let mut tls = if track.includes_tls() {
        client_hello
            .and_then(|client_hello| client_hello.parse().ok())
            .map(TlsTrackInfo::new)
    } else {
        None
    };

    if let Some(tls) = tls.as_mut() {
        tls.set_tls_version_negotiated(tls_version_negotiated);
    }

    let http1 = if track.includes_http1() {
        http1_headers.map(Http1TrackInfo::new)
    } else {
        None
    };
    let http2 = if track.includes_http2() {
        http2_frames.and_then(Http2TrackInfo::new)
    } else {
        None
    };

    ProtocolTrackInfo { tls, http1, http2 }
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
            let ProtocolTrackInfo { tls, http1, http2 } =
                protocol_track_info(track, connection_track);

            TrackInfo {
                donate: Self::DONATE_URL,
                address: addr,
                http_version: format!("{:?}", req.version()),
                method: req.method().clone(),
                user_agent: req.headers().get(USER_AGENT).cloned(),
                tls,
                http1,
                http2,
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
        let ProtocolTrackInfo { tls, http1, http2 } = protocol_track_info(track, connection_track);

        TrackInfo {
            donate: Self::DONATE_URL,
            address: addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().clone(),
            user_agent: req.headers().get(USER_AGENT).cloned(),
            tls,
            http1,
            http2,
            #[cfg(target_os = "linux")]
            tcp: if matches!(track, Track::All) {
                tcp_packets
            } else {
                Vec::new()
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use serde_json::json;

    use super::{Http1TrackInfo, Track};

    #[test]
    fn http1_headers_serialize_name_and_value_separately() {
        let headers = Arc::new(boxcar::Vec::new());
        headers.push((
            Bytes::from_static(b"user-agent"),
            Bytes::from_static(b"curl"),
        ));

        assert_eq!(
            serde_json::to_value(Http1TrackInfo::new(headers)).unwrap(),
            json!([{"name": "user-agent", "value": "curl"}])
        );
    }

    #[test]
    fn track_only_includes_requested_protocol_analysis() {
        assert!(Track::All.includes_tls());
        assert!(Track::All.includes_http1());
        assert!(Track::All.includes_http2());
        assert!(Track::Tls.includes_tls());
        assert!(Track::HTTP1.includes_http1());
        assert!(Track::HTTP2.includes_http2());
        assert!(!Track::HTTP1.includes_tls());
        assert!(!Track::HTTP2.includes_tls());
        assert!(!Track::Tls.includes_http1());
        assert!(!Track::Tls.includes_http2());
    }
}
