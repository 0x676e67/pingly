//! Response models assembled from connection captures after a request reaches its endpoint.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    body::Body,
    http::{header::USER_AGENT, HeaderValue, Method, Request},
};
use pingly::{
    h1::{Http1Head, RequestHead},
    h2::{
        frame::{HeadersFlagName, StreamDependency},
        AkamaiFingerprint, Frame,
    },
    h3::Http3Fingerprint,
    tls::{ClientHelloHandshakeBuffer, ClientHelloParseError, TlsVersion},
};
use serde::{
    ser::{SerializeSeq, SerializeStruct},
    Serialize, Serializer,
};
use tokio_rustls::rustls::ProtocolVersion;

use super::inspector::{
    ClientHello, ClientHelloBuffer, Http1RequestCapture, Http2Capture, Http2FrameDirection,
};
use crate::server::quic::inspect::{HeadersCapture, SettingsCapture};
#[cfg(target_os = "linux")]
use crate::tcp::{CapturedPacket, TcpAnalysis};

const HTTP2_FRAME_HEADER_LENGTH: u64 = 9;

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

/// TLS and opening-handshake fields collected for a WebSocket connection.
#[derive(Serialize)]
pub(in crate::server) struct WebSocketTrackInfo {
    /// ClientHello analysis for the upgraded connection.
    pub(in crate::server) tls: Option<TlsTrackInfo>,

    /// Request fields that opened the WebSocket connection.
    pub(in crate::server) headers: Option<WebSocketHeaders>,
}

/// Ordered WebSocket opening-handshake fields from HTTP/1 or HTTP/2.
pub(in crate::server) enum WebSocketHeaders {
    /// HTTP/1.1 Upgrade request fields.
    Http1(Http1TrackInfo),

    /// HTTP/2 Extended CONNECT fields retained in the captured frame list.
    Http2 {
        /// Shared HTTP/2 frame-event capture.
        capture: Http2Capture,

        /// Index of the Extended CONNECT HEADERS frame.
        event_index: usize,
    },
}

/// HTTP/1.x request header tracking information.
pub struct Http1TrackInfo {
    /// Request parsed from its raw capture during response analysis.
    request: RequestHead,
}

/// HTTP/2 tracking information, including fingerprints and a per-stream timeline.
pub struct Http2TrackInfo {
    /// The unhashed Akamai fingerprint derived from the captured client frames.
    akamai_fingerprint: Box<str>,

    /// The lowercase MD5 digest of the Akamai fingerprint.
    akamai_fingerprint_hash: Box<str>,

    /// Shared bidirectional frame capture used by all serialized HTTP/2 views.
    capture: Http2Capture,

    /// Number of events visible when response analysis began.
    event_count: usize,
}

/// Delayed summary of one HTTP/2 request or push stream.
#[derive(Serialize)]
struct Http2StreamInfo {
    /// Stream identifier scoped to this connection.
    stream_id: u32,

    /// Request method decoded from the opening client HEADERS frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<Box<str>>,

    /// Request target decoded from the opening client HEADERS frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Box<str>>,

    /// Priority signals associated with this stream.
    #[serde(skip_serializing_if = "Http2PriorityInfo::is_empty")]
    priority: Http2PriorityInfo,

    /// Positions of this stream's frames in the connection-level `events` array.
    event_indices: Vec<usize>,

    /// Client-to-server bytes carried directly on this stream, including frame headers.
    client_wire_bytes: u64,

    /// Server-to-client bytes carried directly on this stream, including frame headers.
    server_wire_bytes: u64,

    /// Whether an endpoint reset the stream.
    reset: bool,

    /// Whether the client sent END_STREAM or the stream was reset.
    client_ended: bool,

    /// Whether the server sent END_STREAM or the stream was reset.
    server_ended: bool,
}

impl Http2StreamInfo {
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            method: None,
            path: None,
            priority: Http2PriorityInfo::default(),
            event_indices: Vec::new(),
            client_wire_bytes: 0,
            server_wire_bytes: 0,
            reset: false,
            client_ended: false,
            server_ended: false,
        }
    }
}

/// Priority signals observed for one HTTP/2 stream.
#[derive(Default, Serialize)]
struct Http2PriorityInfo {
    /// Initial RFC 9218 Priority request field.
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Box<str>>,

    /// Latest deprecated RFC 7540 dependency signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy: Option<Http2LegacyPriority>,

    /// RFC 9218 reprioritization signals in arrival order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    updates: Vec<Http2PriorityUpdate>,
}

impl Http2PriorityInfo {
    fn is_empty(&self) -> bool {
        self.header.is_none() && self.legacy.is_none() && self.updates.is_empty()
    }
}

/// Deprecated HTTP/2 dependency fields copied into a stream summary.
#[derive(Serialize)]
struct Http2LegacyPriority {
    /// Effective stream weight in the inclusive range 1 through 256.
    weight: u16,

    /// Parent stream in the dependency tree.
    depends_on: u32,

    /// Whether the dependency was marked exclusive.
    exclusive: u8,
}

impl From<&StreamDependency> for Http2LegacyPriority {
    fn from(priority: &StreamDependency) -> Self {
        Self {
            weight: priority.weight,
            depends_on: priority.depends_on,
            exclusive: priority.exclusive,
        }
    }
}

/// One RFC 9218 priority update associated with a target stream.
#[derive(Serialize)]
struct Http2PriorityUpdate {
    /// Time since HTTP/2 inspection began.
    elapsed_us: u64,

    /// Complete replacement Priority Field Value.
    value: Box<str>,
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

    /// Wall-clock time spent completing the TLS handshake after TCP accept.
    tls_handshake_duration: Option<Duration>,

    /// Raw TLS records retained until the ClientHello can be analyzed.
    client_hello: Option<ClientHelloCapture>,

    /// Raw HTTP/1 request head shared with the stream inspector for delayed parsing.
    http1_capture: Option<Http1RequestCapture>,

    /// Bidirectional HTTP/2 frame events retained in observed order.
    http2_capture: Option<Http2Capture>,

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

    /// Captured TCP packets and passive fingerprint for Linux `/api/all` responses.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<TcpAnalysis>,
}

/// Protocol analysis selected by an API endpoint.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Track {
    /// Include every available protocol layer.
    All,

    /// Include TLS ClientHello analysis.
    Tls,

    /// Include ordered HTTP/1 fields.
    HTTP1,

    /// Include HTTP/2 frames and the Akamai fingerprint.
    HTTP2,

    /// Include HTTP/3 frames, fingerprint, and QUIC data.
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
    /// Parsed TLS analysis, when requested and available.
    tls: Option<TlsTrackInfo>,

    /// Parsed HTTP/1 analysis, when requested and available.
    http1: Option<Http1TrackInfo>,

    /// HTTP/2 analysis, when requested and available.
    http2: Option<Http2TrackInfo>,

    /// HTTP/3 analysis, when requested and available.
    http3: Option<Http3TrackInfo>,
}

impl TlsTrackInfo {
    /// Computes TLS fingerprints from a parsed ClientHello.
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

    /// Records the TLS version negotiated during the handshake.
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.client_hello
            .set_tls_version_negotiated(version.map(u16::from).map(TlsVersion::from));
    }
}

impl Http1TrackInfo {
    /// Wraps a parsed HTTP/1 request for response serialization.
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

impl WebSocketHeaders {
    fn from_http2(capture: Http2Capture) -> Option<Self> {
        let event_index = capture
            .iter()
            .filter_map(|(index, event)| match (&event.direction, &event.frame) {
                (Http2FrameDirection::ClientToServer, Frame::Headers(headers))
                    if headers.is_extended_connect(b"websocket") =>
                {
                    Some(index)
                }
                _ => None,
            })
            .last()?;

        Some(Self::Http2 {
            capture,
            event_index,
        })
    }
}

impl Serialize for WebSocketHeaders {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Http1(info) => info.serialize(serializer),
            Self::Http2 {
                capture,
                event_index,
            } => match capture.get(*event_index).map(|event| &event.frame) {
                Some(Frame::Headers(frame)) => frame.headers.serialize(serializer),
                _ => Err(serde::ser::Error::custom(
                    "HTTP/2 WebSocket HEADERS frame is no longer available",
                )),
            },
        }
    }
}

impl Http2TrackInfo {
    /// Builds HTTP/2 analysis when the captured frames contain fingerprint input.
    pub fn new(capture: Http2Capture) -> Option<Http2TrackInfo> {
        let event_count = capture.count();
        let akamai = AkamaiFingerprint::from_frames(initial_client_frames(&capture, event_count))?;

        Some(Self {
            akamai_fingerprint: akamai.fingerprint,
            akamai_fingerprint_hash: akamai.hash,
            capture,
            event_count,
        })
    }
}

impl Serialize for Http2TrackInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let streams = summarize_http2_streams(&self.capture, self.event_count);
        let mut state = serializer.serialize_struct("Http2TrackInfo", 5)?;
        state.serialize_field("akamai_fingerprint", &self.akamai_fingerprint)?;
        state.serialize_field("akamai_fingerprint_hash", &self.akamai_fingerprint_hash)?;
        state.serialize_field(
            "sent_frames",
            &ClientFrameSequence {
                capture: &self.capture,
                event_count: self.event_count,
            },
        )?;
        state.serialize_field(
            "events",
            &Http2EventSequence {
                capture: &self.capture,
                event_count: self.event_count,
            },
        )?;
        state.serialize_field("streams", &streams)?;
        state.end()
    }
}

/// Existing client-frame JSON view retained for API compatibility.
struct ClientFrameSequence<'a> {
    capture: &'a Http2Capture,
    event_count: usize,
}

impl Serialize for ClientFrameSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let count = legacy_client_frames(self.capture, self.event_count).count();
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for frame in legacy_client_frames(self.capture, self.event_count) {
            sequence.serialize_element(frame)?;
        }
        sequence.end()
    }
}

/// Returns the initial client frame sequence through the opening request HEADERS frame.
fn initial_client_frames(
    capture: &Http2Capture,
    event_count: usize,
) -> impl Iterator<Item = &Frame> {
    capture
        .iter()
        .take(event_count)
        .scan(false, |stopped, (_, event)| {
            if *stopped {
                return None;
            }
            if event.direction != Http2FrameDirection::ClientToServer {
                return Some(None);
            }

            *stopped = matches!(event.frame, Frame::Headers(_));
            Some(Some(&event.frame))
        })
        .flatten()
}

/// Recreates the bounded client sequence exposed before full-connection capture was added.
fn legacy_client_frames(
    capture: &Http2Capture,
    event_count: usize,
) -> impl Iterator<Item = &Frame> {
    capture
        .iter()
        .take(event_count)
        .scan((0usize, false), |(header_blocks, stopped), (_, event)| {
            if *stopped {
                return None;
            }
            if event.direction != Http2FrameDirection::ClientToServer {
                return Some(None);
            }

            if let Frame::Headers(headers) = &event.frame {
                *header_blocks = header_blocks.saturating_add(1);
                *stopped = headers.is_extended_connect(b"websocket") || *header_blocks >= 2;
            }
            Some(Some(&event.frame))
        })
        .flatten()
}

/// Bidirectional connection timeline serialized in observation order.
struct Http2EventSequence<'a> {
    capture: &'a Http2Capture,
    event_count: usize,
}

impl Serialize for Http2EventSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.event_count))?;
        for (_, event) in self.capture.iter().take(self.event_count) {
            sequence.serialize_element(event)?;
        }
        sequence.end()
    }
}

fn summarize_http2_streams(capture: &Http2Capture, event_count: usize) -> Vec<Http2StreamInfo> {
    let mut streams = BTreeMap::<u32, Http2StreamInfo>::new();

    for (event_index, event) in capture.iter().take(event_count) {
        let stream_id = http2_event_stream_id(&event.frame);
        if stream_id == 0 {
            continue;
        }

        let stream = streams
            .entry(stream_id)
            .or_insert_with(|| Http2StreamInfo::new(stream_id));
        stream.event_indices.push(event_index);

        let wire_bytes = if event.frame.stream_id() == stream_id {
            http2_frame_wire_bytes(&event.frame)
        } else {
            0
        };
        let ended = http2_frame_ends_direction(&event.frame);
        match event.direction {
            Http2FrameDirection::ClientToServer => {
                stream.client_wire_bytes = stream.client_wire_bytes.saturating_add(wire_bytes);
                stream.client_ended |= ended;
                update_http2_request_summary(stream, event);
            }
            Http2FrameDirection::ServerToClient => {
                stream.server_wire_bytes = stream.server_wire_bytes.saturating_add(wire_bytes);
                stream.server_ended |= ended;
            }
        }
        if http2_frame_resets_stream(&event.frame) {
            stream.reset = true;
            stream.client_ended = true;
            stream.server_ended = true;
        }
    }

    streams.into_values().collect()
}

fn http2_frame_wire_bytes(frame: &Frame) -> u64 {
    let base = u64::try_from(frame.payload_len())
        .unwrap_or(u64::MAX)
        .saturating_add(HTTP2_FRAME_HEADER_LENGTH);
    let Frame::Headers(headers) = frame else {
        return base;
    };

    headers
        .continuations
        .iter()
        .fold(base, |total, continuation| {
            total.saturating_add(
                u64::try_from(continuation.length)
                    .unwrap_or(u64::MAX)
                    .saturating_add(HTTP2_FRAME_HEADER_LENGTH),
            )
        })
}

fn update_http2_request_summary(
    stream: &mut Http2StreamInfo,
    event: &super::inspector::Http2FrameEvent,
) {
    match &event.frame {
        Frame::Headers(headers) => {
            stream.method.get_or_insert_with(|| {
                http2_header_text(headers, b":method").unwrap_or_else(|| "Unknown".into())
            });
            if stream.path.is_none() {
                stream.path = http2_header_text(headers, b":path");
            }
            if stream.priority.header.is_none() {
                stream.priority.header = http2_header_text(headers, b"priority");
            }
            if let Some(priority) = headers.priority.as_ref() {
                stream.priority.legacy = Some(priority.into());
            }
        }
        Frame::Priority(frame) => {
            stream.priority.legacy = Some((&frame.priority).into());
        }
        Frame::PriorityUpdate(frame) => {
            stream.priority.updates.push(Http2PriorityUpdate {
                elapsed_us: event.elapsed_us,
                value: frame.priority.clone(),
            });
        }
        _ => {}
    }
}

fn http2_header_text(headers: &pingly::h2::frame::HeadersFrame, name: &[u8]) -> Option<Box<str>> {
    headers
        .headers
        .iter()
        .find(|field| field.name.as_ref() == name)
        .map(|field| {
            String::from_utf8_lossy(&field.value)
                .into_owned()
                .into_boxed_str()
        })
}

fn http2_event_stream_id(frame: &Frame) -> u32 {
    match frame {
        Frame::PriorityUpdate(frame) => frame.prioritized_stream_id,
        _ => frame.stream_id(),
    }
}

fn http2_frame_ends_direction(frame: &Frame) -> bool {
    match frame {
        Frame::Data(frame) => frame.is_end_stream(),
        Frame::Headers(frame) => frame.flags.contains(HeadersFlagName::EndStream),
        _ => false,
    }
}

fn http2_frame_resets_stream(frame: &Frame) -> bool {
    matches!(frame, Frame::Unknown(frame) if frame.type_id == 0x03 && frame.length == 4)
}

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

impl ConnectionTrack {
    /// Consumes this capture and builds WebSocket TLS and opening-handshake analysis.
    pub(in crate::server) fn into_websocket_info(self) -> WebSocketTrackInfo {
        let Self {
            tls_version_negotiated,
            tls_handshake_duration: _,
            client_hello,
            http1_capture,
            http2_capture,
            http3_capture: _,
        } = self;

        let headers = http1_capture
            .and_then(http1_track_info)
            .map(WebSocketHeaders::Http1)
            .or_else(|| http2_capture.and_then(WebSocketHeaders::from_http2));

        WebSocketTrackInfo {
            tls: tls_track_info(client_hello, tls_version_negotiated),
            headers,
        }
    }

    /// Records the TLS version negotiated during the handshake.
    #[inline]
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.tls_version_negotiated = version;
    }

    /// Records the server-observed duration of the TLS handshake.
    #[inline]
    pub fn set_tls_handshake_duration(&mut self, duration: Duration) {
        self.tls_handshake_duration = Some(duration);
    }

    /// Returns the server-observed TLS handshake duration.
    #[inline]
    #[cfg(target_os = "linux")]
    pub fn tls_handshake_duration(&self) -> Option<Duration> {
        self.tls_handshake_duration
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

    /// Sets captured HTTP/2 frame events.
    #[inline]
    pub fn set_http2_capture(&mut self, capture: Http2Capture) {
        self.http2_capture = Some(capture);
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
        tls_handshake_duration: _,
        client_hello,
        http1_capture,
        http2_capture,
        http3_capture,
    } = connection_track;

    let tls = if track.includes_tls() {
        tls_track_info(client_hello, tls_version_negotiated)
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

    let http1 = if track.includes_http1() {
        http1_capture.and_then(http1_track_info)
    } else {
        None
    };
    let http2 = if track.includes_http2() {
        http2_capture.and_then(Http2TrackInfo::new)
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

fn tls_track_info(
    client_hello: Option<ClientHelloCapture>,
    tls_version_negotiated: Option<ProtocolVersion>,
) -> Option<TlsTrackInfo> {
    let client_hello = match client_hello?.parse() {
        Some(client_hello) => client_hello,
        None => {
            tracing::debug!("ClientHello capture was not complete before analysis");
            return None;
        }
    };
    let mut tls = match client_hello {
        Ok(client_hello) => TlsTrackInfo::new(client_hello),
        Err(error) => {
            tracing::debug!(?error, "failed to parse captured ClientHello");
            return None;
        }
    };
    tls.set_tls_version_negotiated(tls_version_negotiated);
    Some(tls)
}

fn http1_track_info(capture: Http1RequestCapture) -> Option<Http1TrackInfo> {
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
}

impl TrackInfo {
    const DONATE_MESSAGE: &'static str = "Please consider supporting Pingly to keep this API running. Visit https://github.com/0x676e67/pingly";

    /// Builds the endpoint response from request and connection metadata.
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

    /// Builds the endpoint response with packets captured for this TCP connection.
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
            tcp: matches!(track, Track::All)
                .then(|| TcpAnalysis::from_packets(tcp_packets))
                .filter(|analysis| !analysis.is_empty()),
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
        h2::{
            frame::{
                DataFrame, HeaderField as Http2HeaderField, HeadersFlags,
                HeadersFrame as Http2HeadersFrame, PriorityUpdateFrame,
                SettingsFrame as Http2SettingsFrame, StreamDependency,
                UnknownFrame as Http2UnknownFrame,
            },
            Frame as Http2Frame, FrameType as Http2FrameType,
        },
        h3::{FrameType, HeaderField, HeadersFrame, Setting, SettingsFrame},
        tls::ClientHelloHandshakeBuffer,
    };
    use serde_json::json;

    use super::{protocol_track_info, ConnectionTrack, Http2TrackInfo, Track};
    use crate::server::{
        quic::inspect::SettingsCapture,
        tracker::inspector::{Http2FrameDirection, Http2FrameEvent},
    };

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
    fn http2_capture_serializes_compatible_frames_and_stream_timeline() {
        let capture = Arc::new(boxcar::Vec::new());
        let settings =
            Http2SettingsFrame::try_from((0, 0, &[0x00, 0x01, 0x00, 0x01, 0x00, 0x00][..]))
                .unwrap();
        capture.push(Http2FrameEvent {
            elapsed_us: 5,
            direction: Http2FrameDirection::ClientToServer,
            frame: Http2Frame::Settings(settings),
        });
        capture.push(Http2FrameEvent {
            elapsed_us: 10,
            direction: Http2FrameDirection::ClientToServer,
            frame: Http2Frame::Headers(Http2HeadersFrame {
                frame_type: Http2FrameType::Headers,
                stream_id: 3,
                length: 7,
                headers: vec![
                    Http2HeaderField {
                        name: b":method".as_slice().into(),
                        value: b"GET".as_slice().into(),
                    },
                    Http2HeaderField {
                        name: b":path".as_slice().into(),
                        value: b"/api/http2".as_slice().into(),
                    },
                    Http2HeaderField {
                        name: b"priority".as_slice().into(),
                        value: b"u=1, i".as_slice().into(),
                    },
                ],
                flags: HeadersFlags::from(0x25),
                priority: Some(StreamDependency {
                    weight: 220,
                    depends_on: 0,
                    exclusive: 0,
                }),
                continuations: Vec::new(),
            }),
        });
        capture.push(Http2FrameEvent {
            elapsed_us: 20,
            direction: Http2FrameDirection::ClientToServer,
            frame: Http2Frame::PriorityUpdate(
                PriorityUpdateFrame::try_from((0, 0, &[0, 0, 0, 3, b'u', b'=', b'0'][..])).unwrap(),
            ),
        });
        capture.push(Http2FrameEvent {
            elapsed_us: 30,
            direction: Http2FrameDirection::ServerToClient,
            frame: Http2Frame::Data(DataFrame::try_from((0x01, 3, b"ok".as_slice())).unwrap()),
        });
        capture.push(Http2FrameEvent {
            elapsed_us: 40,
            direction: Http2FrameDirection::ServerToClient,
            frame: Http2Frame::Unknown(Http2UnknownFrame {
                frame_type: Http2FrameType::Unknown,
                type_id: 0x03,
                stream_id: 5,
                length: 4,
                flags: 0,
                payload: vec![0; 4],
            }),
        });
        capture.push(Http2FrameEvent {
            elapsed_us: 50,
            direction: Http2FrameDirection::ClientToServer,
            frame: Http2Frame::Headers(Http2HeadersFrame {
                frame_type: Http2FrameType::Headers,
                stream_id: 7,
                length: 2,
                headers: vec![
                    Http2HeaderField {
                        name: b":path".as_slice().into(),
                        value: b"/later".as_slice().into(),
                    },
                    Http2HeaderField {
                        name: b":method".as_slice().into(),
                        value: b"GET".as_slice().into(),
                    },
                ],
                flags: HeadersFlags::from(0x05),
                priority: None,
                continuations: Vec::new(),
            }),
        });

        let info = Http2TrackInfo::new(capture.clone()).unwrap();
        capture.push(Http2FrameEvent {
            elapsed_us: 60,
            direction: Http2FrameDirection::ClientToServer,
            frame: Http2Frame::Data(DataFrame::try_from((0x01, 7, b"late".as_slice())).unwrap()),
        });

        let value = serde_json::to_value(info).unwrap();
        let stream = &value["streams"][0];
        let reset_stream = &value["streams"][1];

        assert_eq!(value["akamai_fingerprint"], "1:65536|00|0|m,p");
        assert_eq!(value["sent_frames"].as_array().unwrap().len(), 4);
        assert_eq!(value["events"].as_array().unwrap().len(), 6);
        assert_eq!(value["events"][3]["direction"], "ServerToClient");
        assert_eq!(stream["stream_id"], 3);
        assert_eq!(stream["method"], "GET");
        assert_eq!(stream["path"], "/api/http2");
        assert_eq!(stream["event_indices"], json!([1, 2, 3]));
        assert_eq!(stream["client_wire_bytes"], 16);
        assert_eq!(stream["server_wire_bytes"], 11);
        assert_eq!(stream["client_ended"], true);
        assert_eq!(stream["server_ended"], true);
        assert_eq!(stream["priority"]["header"], "u=1, i");
        assert_eq!(
            stream["priority"]["legacy"],
            json!({"weight": 220, "depends_on": 0, "exclusive": 0})
        );
        assert_eq!(
            stream["priority"]["updates"],
            json!([{"elapsed_us": 20, "value": "u=0"}])
        );
        assert_eq!(reset_stream["stream_id"], 5);
        assert_eq!(reset_stream["event_indices"], json!([4]));
        assert_eq!(reset_stream["reset"], true);
        assert_eq!(reset_stream["client_ended"], true);
        assert_eq!(reset_stream["server_ended"], true);
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
