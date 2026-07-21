mod error;
mod headers;
mod priority;
mod settings;
mod window_update;

pub use error::FrameError;
use headers::PendingHeaders;
pub use headers::{
    ContinuationFlag, ContinuationFlagName, ContinuationFlags, ContinuationFrame, HeaderField,
    HeadersFlag, HeadersFlagName, HeadersFlags, HeadersFrame,
};
use httlib_hpack::Decoder;
pub use priority::{PriorityFrame, StreamDependency};
use serde::{de, Deserialize, Deserializer, Serialize};
pub use settings::{Setting, SettingValue, SettingsFrame};
pub use window_update::WindowUpdateFrame;

const FRAME_HEADER_LEN: usize = 9;

/// Stateful parser for HTTP/2 frames and fragmented field blocks.
///
/// [`FrameParser::parse`] accepts bytes beginning at an HTTP/2 frame header. It
/// does not consume the client connection preface. Use
/// [`crate::h2::Http2Parser`] when bytes arrive as arbitrary TCP
/// chunks or still contain the preface.
#[derive(Debug, Default)]
pub struct FrameParser {
    pending_headers: Option<PendingHeaders>,

    // HPACK's dynamic table is a connection-level decoding context. See RFC 7541 Section 2.2:
    // <https://www.rfc-editor.org/rfc/rfc7541#section-2.2>
    hpack_decoder: Decoder<'static>,
}

/// The result of parsing bytes that begin at an HTTP/2 frame boundary.
#[derive(Debug)]
#[must_use]
pub enum FrameParseOutcome {
    /// More bytes are required to complete the frame header or payload.
    Incomplete,

    /// A complete wire frame was consumed.
    ///
    /// `frame` is `None` only while a HEADERS field block is waiting for, or
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
                self.pending_headers = None;
                // httlib-hpack updates its dynamic table one field at a time. A later decoding
                // failure can therefore leave partial state, but RFC 9113 requires the connection
                // to terminate after COMPRESSION_ERROR:
                // <https://www.rfc-editor.org/rfc/rfc9113#section-4.3>
                if matches!(&source, FrameError::CompressionError) {
                    self.hpack_decoder = Decoder::default();
                }

                Err(FrameParseError {
                    consumed: frame_len,
                    source,
                })
            }
        }
    }

    /// Clears any partially decoded HEADERS field block.
    #[inline]
    pub fn reset(&mut self) {
        self.pending_headers = None;
        self.hpack_decoder = Decoder::default();
    }

    /// Returns whether the next frame must be a CONTINUATION frame.
    #[inline]
    pub const fn is_waiting_for_continuation(&self) -> bool {
        self.pending_headers.is_some()
    }

    fn parse_payload(
        &mut self,
        ty: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<Option<Frame>, FrameError> {
        // RFC 9113 requires CONTINUATION frames to be consecutive and on the
        // same stream until END_HEADERS is received.
        // See: <https://www.rfc-editor.org/rfc/rfc9113#section-6.10>
        if let Some(pending) = self.pending_headers.as_mut() {
            if ty != 0x9 {
                return Err(FrameError::ExpectedContinuation);
            }

            if !pending.push_continuation(flags, stream_id, payload)? {
                return Ok(None);
            }

            let Some(pending) = self.pending_headers.take() else {
                return Err(FrameError::MalformedMessage);
            };
            return pending
                .finish(&mut self.hpack_decoder)
                .map(Frame::Headers)
                .map(Some);
        }

        match ty {
            0x1 => {
                let pending = PendingHeaders::try_from((flags, stream_id, payload))?;
                if pending.is_complete() {
                    pending
                        .finish(&mut self.hpack_decoder)
                        .map(Frame::Headers)
                        .map(Some)
                } else {
                    self.pending_headers = Some(pending);
                    Ok(None)
                }
            }
            0x9 => Err(FrameError::UnexpectedContinuation),
            _ => Frame::try_from((ty, flags, stream_id, payload)).map(Some),
        }
    }
}

/// A decoded HTTP/2 frame supported by the analyzer.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Frame {
    /// A SETTINGS frame.
    Settings(SettingsFrame),
    /// A WINDOW_UPDATE frame.
    WindowUpdate(WindowUpdateFrame),
    /// A legacy PRIORITY frame.
    Priority(PriorityFrame),
    /// A HEADERS frame, including any CONTINUATION metadata.
    Headers(HeadersFrame),
    /// A frame whose payload is retained without type-specific decoding.
    Unknown(UnknownFrame),
}

/// Intermediate deserialization shape used to validate a saved frame against its frame type.
#[derive(Deserialize)]
#[serde(untagged)]
enum FrameRepr {
    /// A candidate SETTINGS frame representation.
    Settings(SettingsFrame),

    /// A candidate WINDOW_UPDATE frame representation.
    WindowUpdate(WindowUpdateFrame),

    // HEADERS can include priority data, so it must be attempted before PRIORITY.
    /// A candidate HEADERS frame representation.
    Headers(HeadersFrame),

    /// A candidate PRIORITY frame representation.
    Priority(PriorityFrame),

    /// A candidate frame representation without type-specific payload decoding.
    Unknown(UnknownFrame),
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let frame = match FrameRepr::deserialize(deserializer)? {
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
            Self::Settings(_) => FrameType::Settings,
            Self::WindowUpdate(_) => FrameType::WindowUpdate,
            Self::Priority(_) => FrameType::Priority,
            Self::Headers(_) => FrameType::Headers,
            Self::Unknown(_) => FrameType::Unknown,
        }
    }

    /// Returns the stream identifier from the wire frame header.
    #[inline]
    pub const fn stream_id(&self) -> u32 {
        match self {
            Self::Settings(frame) => frame.stream_id,
            Self::WindowUpdate(frame) => frame.stream_id,
            Self::Priority(frame) => frame.stream_id,
            Self::Headers(frame) => frame.stream_id,
            Self::Unknown(frame) => frame.stream_id,
        }
    }

    /// Returns the payload length, excluding the 9-byte frame header.
    #[inline]
    pub const fn payload_len(&self) -> usize {
        match self {
            Self::Settings(frame) => frame.length,
            Self::WindowUpdate(frame) => frame.length,
            Self::Priority(frame) => frame.length,
            Self::Headers(frame) => frame.length,
            Self::Unknown(frame) => frame.length,
        }
    }
}

/// Frame categories represented by [`Frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    /// SETTINGS (`0x04`).
    Settings,

    /// WINDOW_UPDATE (`0x08`).
    WindowUpdate,

    /// HEADERS (`0x01`).
    Headers,

    /// CONTINUATION (`0x09`).
    Continuation,

    /// PRIORITY (`0x02`).
    Priority,

    /// A frame retained without type-specific decoding.
    Unknown,
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
        if matches!(repr.type_id, 0x1 | 0x2 | 0x4 | 0x8 | 0x9) {
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

impl TryFrom<(u8, u8, u32, &[u8])> for Frame {
    type Error = FrameError;

    fn try_from(
        (ty, flags, stream_id, payload): (u8, u8, u32, &[u8]),
    ) -> Result<Self, Self::Error> {
        match ty {
            0x1 => HeadersFrame::try_from((flags, stream_id, payload)).map(Frame::Headers),
            0x2 => PriorityFrame::try_from((stream_id, payload)).map(Frame::Priority),
            0x4 => SettingsFrame::try_from((flags, stream_id, payload)).map(Frame::Settings),
            0x8 => WindowUpdateFrame::try_from((stream_id, payload)).map(Frame::WindowUpdate),
            0x9 => Err(FrameError::UnexpectedContinuation),
            _ => {
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
        assert!(parser.pending_headers.is_none());
    }

    #[test]
    fn unknown_frames_retain_wire_metadata() {
        let bytes = [0, 0, 2, 0x0a, 0xa5, 0, 0, 0, 7, 1, 2];
        let parsed = FrameParser::default().parse(&bytes).unwrap();
        let Some(Frame::Unknown(frame)) = parsed.into_frame() else {
            panic!("expected an unknown frame");
        };

        assert_eq!(frame.type_id, 0x0a);
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
    fn unknown_frame_deserialization_rejects_supported_types_and_bad_lengths() {
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

        assert!(serde_json::from_str::<UnknownFrame>(supported_type).is_err());
        assert!(serde_json::from_str::<UnknownFrame>(bad_length).is_err());
    }
}
