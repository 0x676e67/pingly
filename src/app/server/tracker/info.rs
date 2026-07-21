use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use axum::{
    body::Body,
    http::{header::USER_AGENT, HeaderValue, Method, Request},
};
use pingly::{
    h1::{Http1Head, RequestHead},
    h2::AkamaiFingerprint,
    h3::Http3Fingerprint,
    tls::{ClientHelloHandshakeBuffer, ClientHelloParseError, TlsVersion},
};
use serde::{Serialize, Serializer};
use tokio_rustls::rustls::ProtocolVersion;

use super::inspector::{ClientHello, ClientHelloBuffer, Http1RequestCapture, Http2Frame};
use crate::server::quic::inspect::{HeadersCapture, SettingsCapture};
#[cfg(target_os = "linux")]
use crate::tcp::CapturedPacket;

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
pub struct Http1TrackInfo {
    /// Request parsed from its raw capture during response analysis.
    request: RequestHead,
}

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

/// HTTP/3 tracking information from the client's control and request streams.
#[derive(Serialize)]
pub struct Http3TrackInfo {
    /// Fingerprint derived from the client SETTINGS frame.
    #[serde(flatten)]
    fingerprint: Http3Fingerprint,

    /// Client SETTINGS frame captured from the HTTP/3 control stream.
    #[serde(serialize_with = "serialize_settings_capture")]
    settings: SettingsCapture,

    /// First HEADERS frame captured from this request stream.
    #[serde(serialize_with = "serialize_headers_capture")]
    headers: HeadersCapture,
}

#[derive(Clone)]
enum ClientHelloCapture {
    /// ClientHello retained with its TLS record framing on a TCP connection.
    Records(ClientHelloBuffer),

    /// ClientHello retained directly from QUIC CRYPTO handshake bytes.
    Handshake(Arc<OnceLock<ClientHelloHandshakeBuffer>>),
}

impl ClientHelloCapture {
    fn parse(self) -> Option<Result<ClientHello, ClientHelloParseError>> {
        match self {
            Self::Records(buffer) => Some(buffer.parse()),
            Self::Handshake(capture) => capture.get().map(ClientHelloHandshakeBuffer::parse),
        }
    }
}

#[derive(Clone)]
struct Http3RequestCapture {
    /// SETTINGS shared by all requests on one HTTP/3 connection.
    settings: SettingsCapture,

    /// HEADERS belonging to the current HTTP/3 request stream.
    headers: HeadersCapture,
}

/// Collects TLS, HTTP/1, HTTP/2, and HTTP/3 handshake info for tracking.
#[derive(Clone, Default)]
pub struct ConnectionTrack {
    /// The TLS protocol version that was negotiated for this connection, if any.
    tls_version_negotiated: Option<ProtocolVersion>,

    /// Raw TLS records retained until the ClientHello can be analyzed.
    client_hello: Option<ClientHelloCapture>,

    /// Raw HTTP/1 request head shared with the stream inspector for delayed parsing.
    http1_capture: Option<Http1RequestCapture>,

    /// HTTP/2 client frames retained in their received order.
    http2_frames: Option<Http2Frame>,

    /// HTTP/3 control-stream SETTINGS and request-stream HEADERS captures.
    http3_capture: Option<Http3RequestCapture>,
}

/// Tracking details collected for a single connection.
///
/// Includes the TLS, HTTP/1, HTTP/2, and HTTP/3 analysis selected for the response.
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

    /// HTTP/3 and QUIC analysis requested for this response, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    http3: Option<Http3TrackInfo>,

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
    HTTP3,
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

    const fn includes_http3(self) -> bool {
        matches!(self, Track::All | Track::HTTP3)
    }
}

struct ProtocolTrackInfo {
    tls: Option<TlsTrackInfo>,
    http1: Option<Http1TrackInfo>,
    http2: Option<Http2TrackInfo>,
    http3: Option<Http3TrackInfo>,
}

// ==== impl TlsTrackInfo ====

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
    pub fn new(request: RequestHead) -> Http1TrackInfo {
        Http1TrackInfo { request }
    }
}

impl Serialize for Http1TrackInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.request.headers.serialize(serializer)
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

// ==== impl Http3TrackInfo ====

impl Http3TrackInfo {
    /// Builds HTTP/3 analysis only after both client frames have been captured.
    fn new(capture: Http3RequestCapture) -> Option<Self> {
        let settings = capture.settings.get()?;
        let headers = capture.headers.get()?;
        let fingerprint = Http3Fingerprint::from_frames(settings, headers);

        Some(Self {
            fingerprint,
            settings: capture.settings,
            headers: capture.headers,
        })
    }
}

fn serialize_settings_capture<S>(
    capture: &SettingsCapture,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match capture.get() {
        Some(frame) => frame.serialize(serializer),
        None => Err(serde::ser::Error::custom(
            "HTTP/3 SETTINGS capture is not complete",
        )),
    }
}

fn serialize_headers_capture<S>(capture: &HeadersCapture, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match capture.get() {
        Some(frame) => frame.serialize(serializer),
        None => Err(serde::ser::Error::custom(
            "HTTP/3 HEADERS capture is not complete",
        )),
    }
}

// ==== impl ConnectionTrack ====

impl ConnectionTrack {
    /// Set TLS version negotiated during the handshake.
    #[inline]
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.tls_version_negotiated = version;
    }

    /// Sets a ClientHello captured with TLS record framing.
    #[inline]
    pub fn set_client_hello(&mut self, client_hello: Option<ClientHelloBuffer>) {
        self.client_hello = client_hello.map(ClientHelloCapture::Records);
    }

    /// Sets a ClientHello captured from QUIC CRYPTO handshake bytes.
    #[inline]
    pub fn set_client_hello_handshake(
        &mut self,
        client_hello: Arc<OnceLock<ClientHelloHandshakeBuffer>>,
    ) {
        self.client_hello = Some(ClientHelloCapture::Handshake(client_hello));
    }

    /// Sets the raw HTTP/1 request head shared with delayed analysis.
    #[inline]
    pub fn set_http1_request_capture(&mut self, capture: Http1RequestCapture) {
        self.http1_capture = Some(capture);
    }

    /// Sets captured HTTP/2 frames.
    #[inline]
    pub fn set_http2_frames(&mut self, frames: Http2Frame) {
        self.http2_frames = Some(frames);
    }

    /// Sets HTTP/3 control-stream SETTINGS and request-stream HEADERS captures.
    #[inline]
    pub(in crate::server) fn set_http3_capture(
        &mut self,
        settings: SettingsCapture,
        headers: HeadersCapture,
    ) {
        self.http3_capture = Some(Http3RequestCapture { settings, headers });
    }
}

fn protocol_track_info(track: Track, connection_track: ConnectionTrack) -> ProtocolTrackInfo {
    let ConnectionTrack {
        tls_version_negotiated,
        client_hello,
        http1_capture,
        http2_frames,
        http3_capture,
    } = connection_track;

    let mut client_hello = if track.includes_tls() {
        client_hello.and_then(|capture| match capture.parse() {
            Some(Ok(client_hello)) => Some(client_hello),
            Some(Err(error)) => {
                tracing::debug!(?error, "failed to parse captured ClientHello");
                None
            }
            None => {
                tracing::debug!("ClientHello capture was not complete before analysis");
                None
            }
        })
    } else {
        None
    };

    let http3 = if track.includes_http3() {
        http3_capture.and_then(|capture| {
            let info = Http3TrackInfo::new(capture);
            if info.is_none() {
                tracing::debug!("HTTP/3 SETTINGS or HEADERS capture was not complete");
            }
            info
        })
    } else {
        None
    };

    let mut tls = track
        .includes_tls()
        .then(|| client_hello.take())
        .flatten()
        .map(TlsTrackInfo::new);
    if let Some(tls) = tls.as_mut() {
        tls.set_tls_version_negotiated(tls_version_negotiated);
    }

    let http1 = if track.includes_http1() {
        http1_capture.and_then(|capture| {
            let buffer = capture.get()?;
            match buffer.parse() {
                Ok(Http1Head::Request(request)) => Some(Http1TrackInfo::new(request)),
                Ok(Http1Head::Response(_)) => {
                    tracing::debug!("request capture unexpectedly contained an HTTP/1 response");
                    None
                }
                Err(error) => {
                    tracing::debug!(?error, "failed to parse captured HTTP/1 request head");
                    None
                }
            }
        })
    } else {
        None
    };
    let http2 = if track.includes_http2() {
        http2_frames.and_then(Http2TrackInfo::new)
    } else {
        None
    };

    ProtocolTrackInfo {
        tls,
        http1,
        http2,
        http3,
    }
}

// ==== impl TrackInfo ====

impl TrackInfo {
    const DONATE_MESSAGE: &'static str = "Please consider supporting Pingly to keep this API running. Visit https://github.com/0x676e67/pingly";

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
            let ProtocolTrackInfo {
                tls,
                http1,
                http2,
                http3,
            } = protocol_track_info(track, connection_track);

            TrackInfo {
                donate: Self::DONATE_MESSAGE,
                address: addr,
                http_version: format!("{:?}", req.version()),
                method: req.method().clone(),
                user_agent: req.headers().get(USER_AGENT).cloned(),
                tls,
                http1,
                http2,
                http3,
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
        let ProtocolTrackInfo {
            tls,
            http1,
            http2,
            http3,
        } = protocol_track_info(track, connection_track);

        TrackInfo {
            donate: Self::DONATE_MESSAGE,
            address: addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().clone(),
            user_agent: req.headers().get(USER_AGENT).cloned(),
            tls,
            http1,
            http2,
            http3,
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
    use std::sync::{Arc, OnceLock};

    use pingly::{
        h1::Http1HeadBuffer,
        h3::{FrameType, HeaderField, HeadersFrame, Setting, SettingsFrame},
        tls::ClientHelloHandshakeBuffer,
    };
    use serde_json::json;

    use super::{protocol_track_info, ConnectionTrack, Track};
    use crate::server::quic::inspect::SettingsCapture;

    fn quic_client_hello() -> ClientHelloHandshakeBuffer {
        let transport_parameters = [0x00, 0x39, 0x00, 0x03, 0x04, 0x01, 0x20];
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        let extensions_len = u16::try_from(transport_parameters.len()).unwrap();
        body.extend_from_slice(&extensions_len.to_be_bytes());
        body.extend_from_slice(&transport_parameters);

        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut handshake = vec![1, length[1], length[2], length[3]];
        handshake.extend_from_slice(&body);
        ClientHelloHandshakeBuffer::from_bytes(handshake)
    }

    #[test]
    fn http1_capture_is_parsed_when_analysis_is_built() {
        let wire = b"GET / HTTP/1.1\r\nuSeR-aGeNt: curl\r\n\r\n";
        let mut buffer = Http1HeadBuffer::request();
        assert_eq!(buffer.extend(wire), wire.len());

        let capture = Arc::new(OnceLock::new());
        capture.set(buffer).unwrap();

        let mut connection = ConnectionTrack::default();
        connection.set_http1_request_capture(capture);
        let http1 = protocol_track_info(Track::HTTP1, connection).http1.unwrap();

        assert_eq!(
            serde_json::to_value(http1).unwrap(),
            json!([{"name": "uSeR-aGeNt", "value": "curl"}])
        );
    }

    #[test]
    fn http3_capture_is_fingerprinted_when_analysis_is_built() {
        let settings = SettingsCapture::new();
        settings.set(SettingsFrame {
            frame_type: FrameType::Settings,
            length: 5,
            settings: vec![Setting::try_from_wire(1, 65_536).unwrap()],
        });

        let headers = Arc::new(OnceLock::new());
        headers
            .set(HeadersFrame {
                frame_type: FrameType::Headers,
                length: 16,
                headers: vec![
                    HeaderField {
                        name: b":method".as_slice().into(),
                        value: b"GET".as_slice().into(),
                    },
                    HeaderField {
                        name: b":path".as_slice().into(),
                        value: b"/api/http3".as_slice().into(),
                    },
                ],
            })
            .unwrap();

        let client_hello = Arc::new(OnceLock::new());
        client_hello.set(quic_client_hello()).unwrap();

        let mut connection = ConnectionTrack::default();
        connection.set_client_hello_handshake(client_hello);
        connection.set_http3_capture(settings, headers);
        let analysis = protocol_track_info(Track::All, connection);
        let tls = serde_json::to_value(analysis.tls.unwrap()).unwrap();
        let http3 = analysis.http3.unwrap();
        let value = serde_json::to_value(http3).unwrap();

        assert_eq!(value["h3_text"], "1:65536|m,p");
        assert_eq!(value["h3_text_hash"], "7b9ae05c41a8dab63ad54ead553ed227");
        assert_eq!(
            value["settings"]["settings"][0]["name"],
            "QpackMaxTableCapacity"
        );
        assert_eq!(value["headers"]["headers"][1]["name"], ":path");
        assert_eq!(
            tls["extensions"][0]["quic_transport_parameters"]["data"],
            json!([{"id": 4, "name": "initial_max_data", "value": 32}])
        );
        assert!(tls["ja4"].as_str().is_some_and(|ja4| ja4.starts_with('q')));
        assert!(tls["ja4_r"]
            .as_str()
            .is_some_and(|ja4_r| ja4_r.starts_with('q')));
        assert!(value.get("fingerprint").is_none());
        assert!(value.get("normalized_fingerprint").is_none());
        assert!(value.get("normalized_h3_text").is_none());
        assert!(value.get("normalized_h3_text_hash").is_none());
        assert!(value.get("quic_transport_parameters").is_none());
    }

    #[test]
    fn track_only_includes_requested_protocol_analysis() {
        assert!(Track::All.includes_tls());
        assert!(Track::All.includes_http1());
        assert!(Track::All.includes_http2());
        assert!(Track::All.includes_http3());
        assert!(Track::Tls.includes_tls());
        assert!(Track::HTTP1.includes_http1());
        assert!(Track::HTTP2.includes_http2());
        assert!(Track::HTTP3.includes_http3());
        assert!(!Track::HTTP1.includes_tls());
        assert!(!Track::HTTP2.includes_tls());
        assert!(!Track::HTTP3.includes_tls());
        assert!(!Track::Tls.includes_http1());
        assert!(!Track::Tls.includes_http2());
        assert!(!Track::Tls.includes_http3());
    }
}
