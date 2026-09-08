//! Stateful HTTP/2 frame and HPACK field-block decoding.

mod altsvc;
mod data;
mod error;
mod goaway;
mod headers;
mod origin;
mod ping;
mod priority;
mod priority_update;
mod push_promise;
mod rst_stream;
mod settings;
mod window_update;

pub use altsvc::AltSvcFrame;
pub use data::{DataFlag, DataFlagName, DataFlags, DataFrame};
pub use error::FrameError;
pub use goaway::GoAwayFrame;
use headers::PendingHeaders;
pub use headers::{
    ContinuationFlag, ContinuationFlagName, ContinuationFlags, ContinuationFrame, HeaderField,
    HeadersFlag, HeadersFlagName, HeadersFlags, HeadersFrame,
};
use httlib_hpack::Decoder;
pub use origin::{OriginEntry, OriginFrame};
pub use ping::PingFrame;
pub use priority::{PriorityFrame, StreamDependency};
pub use priority_update::PriorityUpdateFrame;
use push_promise::PendingPushPromise;
pub use push_promise::PushPromiseFrame;
pub use rst_stream::{ErrorCode, ErrorCodeName, RstStreamFrame};
use serde::{de, Deserialize, Deserializer, Serialize};
pub use settings::{Setting, SettingValue, SettingsFrame};
pub use window_update::WindowUpdateFrame;

const FRAME_HEADER_LEN: usize = 9;
const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;

/// A field section awaiting completion in this parser's HPACK direction.
#[derive(Debug)]
enum PendingFieldSection {
    /// Request, response, or trailer fields.
    Headers(PendingHeaders),

    /// Request fields promised by the server.
    PushPromise(PendingPushPromise),
}

impl PendingFieldSection {
    fn is_complete(&self) -> bool {
        match self {
            Self::Headers(frame) => frame.is_complete(),
            Self::PushPromise(frame) => frame.is_complete(),
        }
    }

    fn push_continuation(
        &mut self,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<bool, FrameError> {
        match self {
            Self::Headers(frame) => frame.push_continuation(flags, stream_id, payload),
            Self::PushPromise(frame) => frame.push_continuation(flags, stream_id, payload),
        }
    }

    fn finish(self, decoder: &mut Decoder<'_>) -> Result<Frame, FrameError> {
        match self {
            Self::Headers(frame) => frame.finish(decoder).map(Frame::Headers),
            Self::PushPromise(frame) => frame.finish(decoder).map(Frame::PushPromise),
        }
    }
}

/// Stateful parser for HTTP/2 frames and fragmented field blocks.
///
/// [`FrameParser::parse`] accepts bytes beginning at an HTTP/2 frame header. It
/// does not consume the client connection preface. Use
/// [`crate::h2::Http2Parser`] when bytes arrive as arbitrary TCP
/// chunks or still contain the preface.
#[derive(Debug)]
pub struct FrameParser {
    // HEADERS and PUSH_PROMISE both require uninterrupted CONTINUATION sequences.
    pending_field_section: Option<PendingFieldSection>,

    // HPACK's dynamic table is a connection-level decoding context. See RFC 7541, Section 2.2:
    // <https://www.rfc-editor.org/rfc/rfc7541#section-2.2>
    hpack_decoder: Decoder<'static>,

    // SETTINGS_HEADER_TABLE_SIZE advertised by the decoder's endpoint.
    hpack_max_dynamic_size: u32,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self {
            pending_field_section: None,
            hpack_decoder: Decoder::with_dynamic_size(DEFAULT_HEADER_TABLE_SIZE),
            hpack_max_dynamic_size: DEFAULT_HEADER_TABLE_SIZE,
        }
    }
}

/// The result of parsing bytes that begin at an HTTP/2 frame boundary.
#[derive(Debug)]
#[must_use]
pub enum FrameParseOutcome {
    /// More bytes are required to complete the frame header or payload.
    Incomplete,

    /// A complete wire frame was consumed.
    ///
    /// `frame` is `None` only while a HEADERS or PUSH_PROMISE block is waiting for, or
    /// consuming, a CONTINUATION frame.
    Consumed {
        /// Number of bytes consumed from the supplied slice.
        bytes: usize,

        /// A decoded frame when the logical frame is complete.
        frame: Option<Frame>,
    },
}

impl FrameParseOutcome {
    /// Returns the number of bytes that can be removed from the input buffer.
    #[inline]
    pub const fn consumed(&self) -> usize {
        match self {
            Self::Incomplete => 0,
            Self::Consumed { bytes, .. } => *bytes,
        }
    }

    /// Returns the decoded frame, if this outcome completed one.
    #[inline]
    pub fn into_frame(self) -> Option<Frame> {
        match self {
            Self::Incomplete => None,
            Self::Consumed { frame, .. } => frame,
        }
    }
}

/// A malformed complete HTTP/2 frame and its recoverable input position.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse the HTTP/2 frame after {consumed} bytes: {source}")]
pub struct FrameParseError {
    /// Number of bytes occupied by the malformed frame.
    pub consumed: usize,

    /// The protocol-level reason the frame was rejected.
    #[source]
    pub source: FrameError,
}

impl FrameParser {
    /// Parses one wire frame from the beginning of `data`.
    ///
    /// Incomplete input is reported as [`FrameParseOutcome::Incomplete`], not
    /// as an error, so callers can append the next TCP chunk and retry. A
    /// complete malformed frame returns [`FrameParseError`], whose `consumed`
    /// field allows a capture tool to skip that frame and continue.
    ///
    /// HPACK decoding errors reset the connection-level compression state before
    /// the error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`FrameParseError`] when a complete frame violates its type-specific rules, a
    /// CONTINUATION sequence is invalid, or HPACK decoding fails.
    pub fn parse(&mut self, data: &[u8]) -> Result<FrameParseOutcome, FrameParseError> {
        if data.len() < FRAME_HEADER_LEN {
            return Ok(FrameParseOutcome::Incomplete);
        }

        let header = &data[..FRAME_HEADER_LEN];
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let ty = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
        let Some(frame_len) = FRAME_HEADER_LEN.checked_add(length) else {
            return Err(FrameParseError {
                consumed: data.len(),
                source: FrameError::BadFrameSize,
            });
        };
        if data.len() < frame_len {
            return Ok(FrameParseOutcome::Incomplete);
        }

        let payload = &data[FRAME_HEADER_LEN..frame_len];
        match self.parse_payload(ty, flags, stream_id, payload) {
            Ok(frame) => Ok(FrameParseOutcome::Consumed {
                bytes: frame_len,
                frame,
            }),
            Err(source) => {
                self.pending_field_section = None;
                // httlib-hpack updates its dynamic table one field at a time. A later decoding
                // failure can therefore leave partial state, but RFC 9113, Section 4.3 requires
                // the connection to terminate after COMPRESSION_ERROR:
                // <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>
                if matches!(&source, FrameError::CompressionError) {
                    self.reset_hpack_decoder();
                }

                Err(FrameParseError {
                    consumed: frame_len,
                    source,
                })
            }
        }
    }

    /// Clears any incomplete field section and resets this direction's HPACK table.
    #[inline]
    pub fn reset(&mut self) {
        self.pending_field_section = None;
        self.reset_hpack_decoder();
    }

    /// Applies the peer's `SETTINGS_HEADER_TABLE_SIZE` to subsequent field sections.
    ///
    /// The setting limits the encoder used by the endpoint that receives it, so a bidirectional
    /// capture applies each direction's value to the opposite HPACK decoder. See
    /// [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    pub fn set_max_header_table_size(&mut self, size: u32) {
        self.hpack_max_dynamic_size = size;
        self.hpack_decoder.set_max_dynamic_size(size);
    }

    /// Returns whether the next frame must be a CONTINUATION frame.
    #[inline]
    pub const fn is_waiting_for_continuation(&self) -> bool {
        self.pending_field_section.is_some()
    }

    fn reset_hpack_decoder(&mut self) {
        self.hpack_decoder = Decoder::with_dynamic_size(self.hpack_max_dynamic_size);
    }

    fn parse_payload(
        &mut self,
        ty: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<Option<Frame>, FrameError> {
        // RFC 9113, Section 6.10 requires CONTINUATION frames to be consecutive and on the same
        // stream until END_HEADERS is received:
        // <https://www.rfc-editor.org/rfc/rfc9113#section-6.10>
        if let Some(pending) = self.pending_field_section.as_mut() {
            if ty != 0x9 {
                return Err(FrameError::ExpectedContinuation);
            }

            if !pending.push_continuation(flags, stream_id, payload)? {
                return Ok(None);
            }

            let Some(pending) = self.pending_field_section.take() else {
                return Err(FrameError::MalformedMessage);
            };
            return pending.finish(&mut self.hpack_decoder).map(Some);
        }

        let pending = match FrameType::from(ty) {
            FrameType::Headers => {
                PendingFieldSection::Headers(PendingHeaders::try_from((flags, stream_id, payload))?)
            }
            FrameType::PushPromise => PendingFieldSection::PushPromise(
                PendingPushPromise::try_from((flags, stream_id, payload))?,
            ),
            FrameType::Continuation => return Err(FrameError::UnexpectedContinuation),
            _ => return Frame::try_from((ty, flags, stream_id, payload)).map(Some),
        };
        if pending.is_complete() {
            pending.finish(&mut self.hpack_decoder).map(Some)
        } else {
            self.pending_field_section = Some(pending);
            Ok(None)
        }
    }
}

/// A decoded HTTP/2 frame supported by the analyzer.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Frame {
    /// A DATA frame.
    Data(DataFrame),
    /// A SETTINGS frame.
    Settings(SettingsFrame),
    /// A WINDOW_UPDATE frame.
    WindowUpdate(WindowUpdateFrame),
    /// A legacy PRIORITY frame.
    Priority(PriorityFrame),
    /// An RST_STREAM frame.
    RstStream(RstStreamFrame),
    /// A PUSH_PROMISE frame, including any CONTINUATION metadata.
    PushPromise(PushPromiseFrame),
    /// A connection-level PING probe or acknowledgement.
    Ping(PingFrame),
    /// A connection-level GOAWAY notification.
    GoAway(GoAwayFrame),
    /// An alternative-service advertisement.
    AltSvc(AltSvcFrame),
    /// An origin advertisement.
    Origin(OriginFrame),
    /// An extensible PRIORITY_UPDATE frame.
    PriorityUpdate(PriorityUpdateFrame),
    /// A HEADERS frame, including any CONTINUATION metadata.
    Headers(HeadersFrame),
    /// A frame whose payload is retained without type-specific decoding.
    Unknown(UnknownFrame),
}

/// Intermediate deserialization shape used to validate a saved frame against its frame type.
#[derive(Deserialize)]
#[serde(untagged)]
enum FrameRepr {
    /// A candidate DATA frame representation.
    Data(DataFrame),

    /// A candidate SETTINGS frame representation.
    Settings(SettingsFrame),

    /// A candidate WINDOW_UPDATE frame representation.
    WindowUpdate(WindowUpdateFrame),

    // HEADERS can include priority data, so it must be attempted before PRIORITY.
    /// A candidate HEADERS frame representation.
    Headers(HeadersFrame),

    /// A candidate PRIORITY frame representation.
    Priority(PriorityFrame),

    /// A candidate RST_STREAM frame representation.
    RstStream(RstStreamFrame),

    /// A candidate promised request.
    PushPromise(PushPromiseFrame),

    /// A candidate PING frame.
    Ping(PingFrame),

    /// A candidate GOAWAY frame.
    GoAway(GoAwayFrame),

    /// A candidate ALTSVC frame.
    AltSvc(AltSvcFrame),

    /// A candidate ORIGIN frame.
    Origin(OriginFrame),

    /// A candidate PRIORITY_UPDATE frame representation.
    PriorityUpdate(PriorityUpdateFrame),

    /// A legacy control frame saved before it had a dedicated model.
    LegacyControl(LegacyControlFrame),

    /// A candidate frame representation without type-specific payload decoding.
    Unknown(UnknownFrame),
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let frame = match FrameRepr::deserialize(deserializer)? {
            FrameRepr::Data(frame) if frame.frame_type == FrameType::Data => Self::Data(frame),
            FrameRepr::Settings(frame) if frame.frame_type == FrameType::Settings => {
                Self::Settings(frame)
            }
            FrameRepr::WindowUpdate(frame) if frame.frame_type == FrameType::WindowUpdate => {
                Self::WindowUpdate(frame)
            }
            FrameRepr::Headers(frame) if frame.frame_type == FrameType::Headers => {
                Self::Headers(frame)
            }
            FrameRepr::Priority(frame) if frame.frame_type == FrameType::Priority => {
                Self::Priority(frame)
            }
            FrameRepr::RstStream(frame) if frame.frame_type == FrameType::RstStream => {
                Self::RstStream(frame)
            }
            FrameRepr::PushPromise(frame) => Self::PushPromise(frame),
            FrameRepr::Ping(frame) => Self::Ping(frame),
            FrameRepr::GoAway(frame) => Self::GoAway(frame),
            FrameRepr::AltSvc(frame) => Self::AltSvc(frame),
            FrameRepr::Origin(frame) => Self::Origin(frame),
            FrameRepr::PriorityUpdate(frame) if frame.frame_type == FrameType::PriorityUpdate => {
                Self::PriorityUpdate(frame)
            }
            FrameRepr::LegacyControl(frame) => frame.0,
            FrameRepr::Unknown(frame) if frame.frame_type == FrameType::Unknown => {
                Self::Unknown(frame)
            }
            _ => {
                return Err(de::Error::custom(
                    "frame_type does not match HTTP/2 frame payload",
                ));
            }
        };

        Ok(frame)
    }
}

impl Frame {
    /// Returns the decoded frame category.
    #[inline]
    pub const fn frame_type(&self) -> FrameType {
        match self {
            Self::Data(_) => FrameType::Data,
            Self::Settings(_) => FrameType::Settings,
            Self::WindowUpdate(_) => FrameType::WindowUpdate,
            Self::Priority(_) => FrameType::Priority,
            Self::RstStream(_) => FrameType::RstStream,
            Self::PushPromise(_) => FrameType::PushPromise,
            Self::Ping(_) => FrameType::Ping,
            Self::GoAway(_) => FrameType::GoAway,
            Self::AltSvc(_) => FrameType::AltSvc,
            Self::Origin(_) => FrameType::Origin,
            Self::PriorityUpdate(_) => FrameType::PriorityUpdate,
            Self::Headers(_) => FrameType::Headers,
            Self::Unknown(_) => FrameType::Unknown,
        }
    }

    /// Returns the stream identifier from the wire frame header.
    #[inline]
    pub const fn stream_id(&self) -> u32 {
        match self {
            Self::Data(frame) => frame.stream_id,
            Self::Settings(frame) => frame.stream_id,
            Self::WindowUpdate(frame) => frame.stream_id,
            Self::Priority(frame) => frame.stream_id,
            Self::RstStream(frame) => frame.stream_id,
            Self::PushPromise(frame) => frame.stream_id,
            Self::Ping(frame) => frame.stream_id,
            Self::GoAway(frame) => frame.stream_id,
            Self::AltSvc(frame) => frame.stream_id,
            Self::Origin(frame) => frame.stream_id,
            Self::PriorityUpdate(frame) => frame.stream_id,
            Self::Headers(frame) => frame.stream_id,
            Self::Unknown(frame) => frame.stream_id,
        }
    }

    /// Returns the payload length, excluding the 9-byte frame header.
    #[inline]
    pub const fn payload_len(&self) -> usize {
        match self {
            Self::Data(frame) => frame.length,
            Self::Settings(frame) => frame.length,
            Self::WindowUpdate(frame) => frame.length,
            Self::Priority(frame) => frame.length,
            Self::RstStream(frame) => frame.length,
            Self::PushPromise(frame) => frame.length,
            Self::Ping(frame) => frame.length,
            Self::GoAway(frame) => frame.length,
            Self::AltSvc(frame) => frame.length,
            Self::Origin(frame) => frame.length,
            Self::PriorityUpdate(frame) => frame.length,
            Self::Headers(frame) => frame.length,
            Self::Unknown(frame) => frame.length,
        }
    }
}

registry_enum! {
    /// HTTP/2 frame types in the [IANA registry](https://www.iana.org/assignments/http2-parameters#frame-type).
    pub enum FrameType: u8 {
        /// DATA (`0x00`, RFC 9113 Section 6.1).
        Data => 0x00,
        /// HEADERS (`0x01`, RFC 9113 Section 6.2).
        Headers => 0x01,
        /// PRIORITY (`0x02`, RFC 9113 Section 6.3).
        Priority => 0x02,
        /// RST_STREAM (`0x03`, RFC 9113 Section 6.4).
        RstStream => 0x03,
        /// SETTINGS (`0x04`, RFC 9113 Section 6.5).
        Settings => 0x04,
        /// PUSH_PROMISE (`0x05`, RFC 9113 Section 6.6).
        PushPromise => 0x05,
        /// PING (`0x06`, RFC 9113 Section 6.7).
        Ping => 0x06,
        /// GOAWAY (`0x07`, RFC 9113 Section 6.8).
        GoAway => 0x07,
        /// WINDOW_UPDATE (`0x08`, RFC 9113 Section 6.9).
        WindowUpdate => 0x08,
        /// CONTINUATION (`0x09`, RFC 9113 Section 6.10).
        Continuation => 0x09,
        /// ALTSVC (`0x0a`, RFC 7838 Section 4).
        AltSvc => 0x0a,
        /// ORIGIN (`0x0c`, RFC 8336 Section 2).
        Origin => 0x0c,
        /// PRIORITY_UPDATE (`0x10`, RFC 9218 Section 7.1).
        PriorityUpdate => 0x10,
    }

    fallback(_id) {
        /// An unassigned or private frame type; its ID remains in [`UnknownFrame::type_id`].
        Unknown,
    } => Self::Unknown;
}

/// A frame retained without type-specific payload decoding.
///
/// RFC 9113 requires unknown frame types to be ignored. Analysis tools still
/// need their original metadata, so this model retains the complete header and
/// payload information. See
/// [RFC 9113, Section 4.1](https://www.rfc-editor.org/rfc/rfc9113#section-4.1).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UnknownFrameRepr")]
pub struct UnknownFrame {
    /// The model category, always [`FrameType::Unknown`].
    pub frame_type: FrameType,

    /// The original 8-bit frame type from the wire header.
    pub type_id: u8,

    /// The stream identifier from the wire header.
    pub stream_id: u32,

    /// The payload length, excluding the 9-byte frame header.
    pub length: usize,

    /// The original frame flag byte.
    pub flags: u8,

    /// The payload retained verbatim.
    pub payload: Vec<u8>,
}

/// Converts saved control frames that do not need a connection's compression context.
#[derive(Deserialize)]
#[serde(try_from = "UnknownFrameRepr")]
struct LegacyControlFrame(Frame);

/// Deserialization shape used to validate a frame retained as unknown.
#[derive(Deserialize)]
struct UnknownFrameRepr {
    /// Saved model category.
    frame_type: FrameType,

    /// Original 8-bit frame type.
    type_id: u8,

    /// Original 31-bit stream identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Original flag byte.
    flags: u8,

    /// Original payload bytes.
    payload: Vec<u8>,
}

impl TryFrom<UnknownFrameRepr> for UnknownFrame {
    type Error = &'static str;

    fn try_from(repr: UnknownFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Unknown {
            return Err("unknown frame_type must be Unknown");
        }
        // Keep older captures of newly supported types readable. Legacy PUSH_PROMISE
        // payloads cannot be decoded without their connection's HPACK context.
        if matches!(repr.type_id, 0x0 | 0x1 | 0x2 | 0x3 | 0x4 | 0x8 | 0x9 | 0x10) {
            return Err("a supported HTTP/2 frame type cannot use UnknownFrame");
        }
        if repr.stream_id > 0x7fff_ffff {
            return Err("unknown frame stream_id must be a 31-bit value");
        }
        if repr.length > 0x00ff_ffff {
            return Err("unknown frame payload length exceeds the HTTP/2 frame limit");
        }
        if repr.length != repr.payload.len() {
            return Err("unknown frame length does not match its payload");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            type_id: repr.type_id,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            payload: repr.payload,
        })
    }
}

impl TryFrom<UnknownFrameRepr> for LegacyControlFrame {
    type Error = &'static str;

    fn try_from(repr: UnknownFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Unknown
            || !matches!(repr.type_id, 0x03 | 0x06 | 0x07 | 0x0a | 0x0c)
        {
            return Err("not a legacy HTTP/2 control frame");
        }
        if repr.length != repr.payload.len() {
            return Err("legacy frame length does not match its payload");
        }

        Frame::try_from((
            repr.type_id,
            repr.flags,
            repr.stream_id,
            repr.payload.as_slice(),
        ))
        .map(Self)
        .map_err(|_| "legacy control frame fields are invalid")
    }
}

impl TryFrom<(u8, u8, u32, &[u8])> for Frame {
    type Error = FrameError;

    fn try_from(
        (ty, flags, stream_id, payload): (u8, u8, u32, &[u8]),
    ) -> Result<Self, Self::Error> {
        match FrameType::from(ty) {
            FrameType::Data => DataFrame::try_from((flags, stream_id, payload)).map(Frame::Data),
            FrameType::Headers => {
                HeadersFrame::try_from((flags, stream_id, payload)).map(Frame::Headers)
            }
            FrameType::Priority => {
                PriorityFrame::try_from((stream_id, payload)).map(Frame::Priority)
            }
            FrameType::RstStream => {
                RstStreamFrame::try_from((flags, stream_id, payload)).map(Frame::RstStream)
            }
            FrameType::Settings => {
                SettingsFrame::try_from((flags, stream_id, payload)).map(Frame::Settings)
            }
            FrameType::PushPromise => {
                PushPromiseFrame::try_from((flags, stream_id, payload)).map(Frame::PushPromise)
            }
            FrameType::Ping => PingFrame::try_from((flags, stream_id, payload)).map(Frame::Ping),
            FrameType::GoAway => {
                GoAwayFrame::try_from((flags, stream_id, payload)).map(Frame::GoAway)
            }
            FrameType::AltSvc => {
                AltSvcFrame::try_from((flags, stream_id, payload)).map(Frame::AltSvc)
            }
            FrameType::Origin => {
                OriginFrame::try_from((flags, stream_id, payload)).map(Frame::Origin)
            }
            FrameType::WindowUpdate => {
                WindowUpdateFrame::try_from((stream_id, payload)).map(Frame::WindowUpdate)
            }
            FrameType::PriorityUpdate => PriorityUpdateFrame::try_from((flags, stream_id, payload))
                .map(Frame::PriorityUpdate),
            FrameType::Continuation => Err(FrameError::UnexpectedContinuation),
            FrameType::Unknown => {
                let frame = UnknownFrame {
                    frame_type: FrameType::Unknown,
                    type_id: ty,
                    stream_id,
                    length: payload.len(),
                    flags,
                    payload: payload.to_vec(),
                };
                Ok(Frame::Unknown(frame))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameError, FrameParseOutcome, FrameParser, HeadersFrame, UnknownFrame};

    #[test]
    fn headers_are_decoded_after_continuation_completes_the_block() {
        let mut parser = FrameParser::default();
        let headers = [0, 0, 1, 0x1, 0x1, 0, 0, 0, 1, 0x82];
        let continuation = [0, 0, 1, 0x9, 0x4, 0, 0, 0, 1, 0x84];

        let parsed = parser.parse(&headers).unwrap();
        assert_eq!(parsed.consumed(), headers.len());
        assert!(parsed.into_frame().is_none());

        let parsed = parser.parse(&continuation).unwrap();
        assert_eq!(parsed.consumed(), continuation.len());
        let Some(Frame::Headers(frame)) = parsed.into_frame() else {
            panic!("expected the completed HEADERS frame");
        };

        assert_eq!(&*frame.headers[0].name, b":method");
        assert_eq!(&*frame.headers[0].value, b"GET");
        assert_eq!(&*frame.headers[1].name, b":path");
        assert_eq!(&*frame.headers[1].value, b"/");
        assert_eq!(frame.continuations.len(), 1);

        let json = serde_json::to_vec(&frame).unwrap();
        let restored: HeadersFrame = serde_json::from_slice(&json).unwrap();
        assert_eq!(restored, frame);
    }

    #[test]
    fn incomplete_frame_is_not_an_error() {
        let parsed = FrameParser::default().parse(&[0, 0, 1]).unwrap();

        assert!(matches!(parsed, FrameParseOutcome::Incomplete));
        assert_eq!(parsed.consumed(), 0);
    }

    #[test]
    fn continuation_must_use_the_open_field_block_stream() {
        let mut parser = FrameParser::default();
        let headers = [0, 0, 1, 0x1, 0, 0, 0, 0, 1, 0x82];
        let wrong_stream = [0, 0, 1, 0x9, 0x4, 0, 0, 0, 3, 0x84];

        assert_eq!(parser.parse(&headers).unwrap().consumed(), headers.len());
        let error = parser.parse(&wrong_stream).unwrap_err();

        assert_eq!(error.consumed, wrong_stream.len());
        assert_eq!(error.source, FrameError::UnexpectedContinuation);
        assert!(!parser.is_waiting_for_continuation());
    }

    #[test]
    fn unknown_frames_retain_wire_metadata() {
        let bytes = [0, 0, 2, 0x0b, 0xa5, 0, 0, 0, 7, 1, 2];
        let parsed = FrameParser::default().parse(&bytes).unwrap();
        let Some(Frame::Unknown(frame)) = parsed.into_frame() else {
            panic!("expected an unknown frame");
        };

        assert_eq!(frame.type_id, 0x0b);
        assert_eq!(frame.flags, 0xa5);
        assert_eq!(frame.stream_id, 7);
        assert_eq!(frame.payload, [1, 2]);

        let json = serde_json::to_vec(&frame).unwrap();
        let restored: UnknownFrame = serde_json::from_slice(&json).unwrap();
        assert_eq!(restored, frame);
    }

    #[test]
    fn hpack_dynamic_table_is_shared_across_field_sections() {
        let mut parser = FrameParser::default();
        let first = [
            0, 0, 9, 0x1, 0x4, 0, 0, 0, 1, 0x40, 3, b'f', b'o', b'o', 3, b'b', b'a', b'r',
        ];
        let second = [0, 0, 1, 0x1, 0x4, 0, 0, 0, 3, 0xbe];

        let Some(Frame::Headers(first)) = parser.parse(&first).unwrap().into_frame() else {
            panic!("expected the first HEADERS frame");
        };
        let Some(Frame::Headers(second)) = parser.parse(&second).unwrap().into_frame() else {
            panic!("expected the second HEADERS frame");
        };

        assert_eq!(first.headers, second.headers);
        assert_eq!(&*second.headers[0].name, b"foo");
        assert_eq!(&*second.headers[0].value, b"bar");
    }

    #[test]
    fn hpack_decode_error_discards_partial_dynamic_table_updates() {
        let mut parser = FrameParser::default();
        let malformed = [0, 0, 6, 0x1, 0x4, 0, 0, 0, 1, 0x40, 1, b'x', 1, b'y', 0x80];
        let dynamic_reference = [0, 0, 1, 0x1, 0x4, 0, 0, 0, 3, 0xbe];

        let error = parser.parse(&malformed).unwrap_err();
        assert_eq!(error.source, FrameError::CompressionError);

        let error = parser.parse(&dynamic_reference).unwrap_err();
        assert_eq!(error.source, FrameError::CompressionError);
    }

    #[test]
    fn unknown_frame_deserialization_rejects_supported_types_and_accepts_legacy_rst_stream() {
        let supported_type = r#"{
            "frame_type":"Unknown",
            "type_id":1,
            "stream_id":1,
            "length":1,
            "flags":0,
            "payload":[0]
        }"#;
        let bad_length = r#"{
            "frame_type":"Unknown",
            "type_id":10,
            "stream_id":1,
            "length":2,
            "flags":0,
            "payload":[0]
        }"#;
        let legacy_rst_stream = r#"{
            "frame_type":"Unknown",
            "type_id":3,
            "stream_id":5,
            "length":4,
            "flags":0,
            "payload":[0,0,0,8]
        }"#;

        assert!(serde_json::from_str::<UnknownFrame>(supported_type).is_err());
        assert!(serde_json::from_str::<UnknownFrame>(bad_length).is_err());
        assert!(matches!(
            serde_json::from_str::<Frame>(legacy_rst_stream).unwrap(),
            Frame::RstStream(frame) if frame.error_code.id == 8
        ));
    }
}
