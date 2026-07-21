use bytes::{Buf, BytesMut};

use super::frame::{
    parse_headers, parse_settings, Frame, FrameType, Http3FrameError, OpaqueFrame, StreamType,
    StreamTypeName,
};
use crate::{quic::varint, tls::HexBytes};

const DEFAULT_BUFFER_CAPACITY: usize = 2048;
const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 1024 * 1024;

/// Errors returned while parsing one decrypted HTTP/3 stream.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Http3ParseError {
    /// A finite input ended inside a stream type, frame header, or payload.
    #[error("incomplete HTTP/3 stream input")]
    IncompleteInput {
        /// Bytes retained for a future parser call.
        buffered_bytes: usize,

        /// Whether a unidirectional stream type is still incomplete.
        waiting_for_stream_type: bool,
    },

    /// A declared frame length exceeds the parser's configured bound.
    #[error("HTTP/3 frame length {length} exceeds the configured limit {limit}")]
    FrameTooLarge {
        /// Declared frame payload length.
        length: u64,

        /// Maximum accepted frame payload length.
        limit: usize,
    },

    /// A frame length could not be represented by this platform.
    #[error("HTTP/3 frame length exceeds the platform limit")]
    LengthOverflow,

    /// The first control-stream frame was not SETTINGS.
    #[error("the HTTP/3 control stream must begin with SETTINGS")]
    ExpectedSettings,

    /// A control stream contained more than one SETTINGS frame.
    #[error("the HTTP/3 control stream contains a second SETTINGS frame")]
    DuplicateSettingsFrame,

    /// The first request-stream frame was not HEADERS.
    #[error("an HTTP/3 request stream must begin with HEADERS")]
    ExpectedHeaders,

    /// A server-only unidirectional stream type was opened by the client.
    ///
    /// See [RFC 9114, Section 6.2.2](https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2).
    #[error("HTTP/3 stream type {type_id} is not valid for a client-initiated stream")]
    UnexpectedStreamType {
        /// Numeric unidirectional stream type found on the wire.
        type_id: u64,
    },
    /// A known frame appeared on a stream where RFC 9114 forbids it.
    #[error("HTTP/3 frame type {type_id} is not valid on this stream")]
    UnexpectedFrame {
        /// Numeric frame type found on the wrong stream.
        type_id: u64,
    },

    /// A complete frame payload was malformed.
    #[error(transparent)]
    Frame(#[from] Http3FrameError),
}

/// An incremental HTTP/3 error together with frames completed before it.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct Http3PushError {
    /// Frames completed before malformed input stopped parsing.
    completed_frames: Vec<Frame>,

    /// Protocol error that stopped parsing.
    #[source]
    error: Http3ParseError,
}

impl Http3PushError {
    /// Returns frames completed before parsing stopped.
    pub fn completed_frames(&self) -> &[Frame] {
        &self.completed_frames
    }

    /// Returns the protocol error that stopped parsing.
    pub const fn error(&self) -> &Http3ParseError {
        &self.error
    }

    /// Consumes this error and returns its completed frames and protocol error.
    pub fn into_parts(self) -> (Vec<Frame>, Http3ParseError) {
        (self.completed_frames, self.error)
    }

    fn into_error(self) -> Http3ParseError {
        self.error
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    Request,

    Unidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestState {
    Initial,

    Body,

    Trailers,
}

/// Incrementally parses frames from one decrypted HTTP/3 QUIC stream.
///
/// Use [`Self::request`] for a client bidirectional request stream and
/// [`Self::unidirectional`] when the input begins with a unidirectional stream-type varint.
/// QPACK encoder and decoder streams are identified and ignored because they do not contain
/// HTTP/3 frames.
#[derive(Debug)]
pub struct Http3Parser {
    /// Bytes retained until a stream type or complete frame is available.
    buffer: BytesMut,

    /// Whether this parser handles a request or unidirectional stream.
    kind: StreamKind,

    /// Decoded type of a unidirectional stream.
    stream_type: Option<StreamType>,

    /// Whether a non-control unidirectional stream has been identified.
    ignored: bool,

    /// Number of complete HTTP/3 frames consumed from this stream.
    frame_count: usize,

    /// Current HTTP message section on a client request stream.
    request_state: RequestState,

    /// Maximum accepted frame payload size.
    max_frame_size: usize,

    /// Maximum decoded QPACK field-section size.
    max_field_section_size: u64,
}

impl Http3Parser {
    /// Creates a parser for a client bidirectional request stream.
    pub fn request() -> Self {
        Self::request_with_capacity(DEFAULT_BUFFER_CAPACITY)
    }

    /// Creates a request-stream parser with the requested initial allocation.
    pub fn request_with_capacity(capacity: usize) -> Self {
        Self::request_with_capacity_and_limits(
            capacity,
            DEFAULT_MAX_FRAME_SIZE,
            DEFAULT_MAX_FIELD_SECTION_SIZE,
        )
    }

    /// Creates a request-stream parser with custom frame and field-section limits.
    pub fn request_with_limits(max_frame_size: usize, max_field_section_size: u64) -> Self {
        Self::request_with_capacity_and_limits(
            DEFAULT_BUFFER_CAPACITY.min(max_frame_size),
            max_frame_size,
            max_field_section_size,
        )
    }

    /// Creates a request-stream parser with explicit allocation and resource limits.
    pub fn request_with_capacity_and_limits(
        capacity: usize,
        max_frame_size: usize,
        max_field_section_size: u64,
    ) -> Self {
        Self::with_capacity_and_limits(
            StreamKind::Request,
            capacity,
            max_frame_size,
            max_field_section_size,
        )
    }

    /// Creates a parser for a client-initiated unidirectional stream.
    pub fn unidirectional() -> Self {
        Self::unidirectional_with_capacity(DEFAULT_BUFFER_CAPACITY)
    }

    /// Creates a unidirectional-stream parser with the requested initial allocation.
    pub fn unidirectional_with_capacity(capacity: usize) -> Self {
        Self::unidirectional_with_capacity_and_limits(
            capacity,
            DEFAULT_MAX_FRAME_SIZE,
            DEFAULT_MAX_FIELD_SECTION_SIZE,
        )
    }

    /// Creates a unidirectional-stream parser with custom frame and field-section limits.
    pub fn unidirectional_with_limits(max_frame_size: usize, max_field_section_size: u64) -> Self {
        Self::unidirectional_with_capacity_and_limits(
            DEFAULT_BUFFER_CAPACITY.min(max_frame_size),
            max_frame_size,
            max_field_section_size,
        )
    }

    /// Creates a unidirectional-stream parser with explicit allocation and resource limits.
    pub fn unidirectional_with_capacity_and_limits(
        capacity: usize,
        max_frame_size: usize,
        max_field_section_size: u64,
    ) -> Self {
        Self::with_capacity_and_limits(
            StreamKind::Unidirectional,
            capacity,
            max_frame_size,
            max_field_section_size,
        )
    }

    fn with_capacity_and_limits(
        kind: StreamKind,
        capacity: usize,
        max_frame_size: usize,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
            kind,
            stream_type: None,
            ignored: false,
            frame_count: 0,
            request_state: RequestState::Initial,
            max_frame_size,
            max_field_section_size,
        }
    }

    /// Returns the current allocation capacity.
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Returns the configured maximum encoded frame payload size.
    pub const fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Returns the configured maximum decoded QPACK field-section size.
    pub const fn max_field_section_size(&self) -> u64 {
        self.max_field_section_size
    }

    /// Appends a chunk and returns every frame completed by it.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Frame>, Http3PushError> {
        let mut frames = Vec::new();
        if let Err(error) = self.push_into(data, &mut frames) {
            return Err(Http3PushError {
                completed_frames: frames,
                error,
            });
        }
        Ok(frames)
    }

    /// Appends a chunk and writes completed frames into `output`.
    pub fn push_into(
        &mut self,
        data: &[u8],
        output: &mut Vec<Frame>,
    ) -> Result<usize, Http3ParseError> {
        let initial_len = output.len();
        if self.ignored {
            return Ok(0);
        }
        self.buffer.extend_from_slice(data);

        if self.kind == StreamKind::Unidirectional && self.stream_type.is_none() {
            let Some((type_id, consumed)) = varint::decode(&self.buffer) else {
                return Ok(0);
            };
            self.buffer.advance(consumed);
            let stream_type = StreamType::from_id(type_id);
            self.stream_type = Some(stream_type);
            if stream_type.name == StreamTypeName::Push {
                self.buffer.clear();
                return Err(Http3ParseError::UnexpectedStreamType { type_id });
            }
            self.ignored = stream_type.name != StreamTypeName::Control;
            if self.ignored {
                self.buffer.clear();
                return Ok(0);
            }
        }

        while let Some((type_id, type_len)) = varint::decode(&self.buffer) {
            let Some((length, length_len)) = varint::decode(&self.buffer[type_len..]) else {
                break;
            };
            if length > self.max_frame_size as u64 {
                self.buffer.clear();
                return Err(Http3ParseError::FrameTooLarge {
                    length,
                    limit: self.max_frame_size,
                });
            }
            let length = usize::try_from(length).map_err(|_| Http3ParseError::LengthOverflow)?;
            let header_len = type_len
                .checked_add(length_len)
                .ok_or(Http3ParseError::LengthOverflow)?;
            let frame_len = header_len
                .checked_add(length)
                .ok_or(Http3ParseError::LengthOverflow)?;
            let Some(payload) = self.buffer.get(header_len..frame_len) else {
                break;
            };

            let frame = match self.parse_frame(type_id, payload) {
                Ok(frame) => frame,
                Err(error) => {
                    self.buffer.advance(frame_len);
                    return Err(error);
                }
            };
            self.buffer.advance(frame_len);
            self.record_frame(type_id);
            self.frame_count = self.frame_count.saturating_add(1);
            output.push(frame);
        }

        Ok(output.len() - initial_len)
    }

    /// Returns the decoded unidirectional stream type, if available.
    pub const fn stream_type(&self) -> Option<StreamType> {
        self.stream_type
    }

    /// Returns whether this is a non-control unidirectional stream with no HTTP/3 frames.
    pub const fn is_ignored(&self) -> bool {
        self.ignored
    }

    /// Returns bytes retained for a future parser call.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether no partial stream type, frame header, or payload remains.
    pub fn is_idle(&self) -> bool {
        if self.ignored {
            return true;
        }
        let stream_type_complete = self.kind == StreamKind::Request || self.stream_type.is_some();
        stream_type_complete && self.buffer.is_empty()
    }

    /// Verifies that finite input has a complete and valid stream prefix.
    pub fn finish(&self) -> Result<(), Http3ParseError> {
        if !self.is_idle() {
            return Err(Http3ParseError::IncompleteInput {
                buffered_bytes: self.buffer.len(),
                waiting_for_stream_type: self.kind == StreamKind::Unidirectional
                    && self.stream_type.is_none(),
            });
        }

        if self.ignored {
            return Ok(());
        }

        match self.kind {
            StreamKind::Request if self.request_state == RequestState::Initial => {
                Err(Http3ParseError::ExpectedHeaders)
            }
            StreamKind::Unidirectional => match self.stream_type {
                Some(stream_type) if stream_type.name == StreamTypeName::Push => {
                    Err(Http3ParseError::UnexpectedStreamType {
                        type_id: stream_type.id,
                    })
                }
                Some(stream_type)
                    if stream_type.name == StreamTypeName::Control && self.frame_count == 0 =>
                {
                    Err(Http3ParseError::ExpectedSettings)
                }
                _ => Ok(()),
            },
            StreamKind::Request => Ok(()),
        }
    }

    /// Drops buffered input and resets this parser for another stream of the same kind.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.stream_type = None;
        self.ignored = false;
        self.frame_count = 0;
        self.request_state = RequestState::Initial;
    }

    fn parse_frame(&self, type_id: u64, payload: &[u8]) -> Result<Frame, Http3ParseError> {
        let frame_type = FrameType::from_id(type_id);
        if frame_type.is_http2_reserved() {
            return Err(Http3ParseError::UnexpectedFrame { type_id });
        }

        match self.kind {
            StreamKind::Unidirectional => {
                if self.frame_count == 0 && type_id != 0x04 {
                    return Err(Http3ParseError::ExpectedSettings);
                }
                if type_id == 0x04 && self.frame_count > 0 {
                    return Err(Http3ParseError::DuplicateSettingsFrame);
                }
                // DATA, HEADERS, and PUSH_PROMISE are forbidden on a control stream.
                // https://www.rfc-editor.org/rfc/rfc9114#section-7.2
                if matches!(type_id, 0x00 | 0x01 | 0x05) {
                    return Err(Http3ParseError::UnexpectedFrame { type_id });
                }
            }
            StreamKind::Request => {
                // Connection-level frames are forbidden on request streams. PUSH_PROMISE is
                // server-originated, while this parser models a client request stream. ORIGIN
                // and PRIORITY_UPDATE are also control-stream extensions.
                // https://www.rfc-editor.org/rfc/rfc9114#section-7.2
                // https://www.rfc-editor.org/rfc/rfc9412#section-2
                // https://www.rfc-editor.org/rfc/rfc9218#section-7.1
                if matches!(
                    type_id,
                    0x03 | 0x04 | 0x05 | 0x07 | 0x0c | 0x0d | 0x0f_0700 | 0x0f_0701
                ) {
                    return Err(Http3ParseError::UnexpectedFrame { type_id });
                }
                if self.request_state == RequestState::Initial && type_id == 0x00 {
                    return Err(Http3ParseError::ExpectedHeaders);
                }
                if self.request_state == RequestState::Trailers && matches!(type_id, 0x00 | 0x01) {
                    return Err(Http3ParseError::UnexpectedFrame { type_id });
                }
            }
        }

        match type_id {
            0x01 => parse_headers(payload, self.max_field_section_size)
                .map(Frame::Headers)
                .map_err(Into::into),
            0x04 => parse_settings(payload)
                .map(Frame::Settings)
                .map_err(Into::into),
            _ => Ok(Frame::Opaque(OpaqueFrame {
                frame_type,
                type_id,
                length: payload.len(),
                payload: HexBytes::from(payload),
            })),
        }
    }

    fn record_frame(&mut self, type_id: u64) {
        if self.kind != StreamKind::Request || type_id != 0x01 {
            return;
        }

        self.request_state = match self.request_state {
            RequestState::Initial => RequestState::Body,
            RequestState::Body | RequestState::Trailers => RequestState::Trailers,
        };
    }
}

impl Default for Http3Parser {
    fn default() -> Self {
        Self::request()
    }
}

/// Parses a complete decrypted HTTP/3 request stream.
///
/// The stream must contain its initial HEADERS frame as required by [RFC 9114, Section 4.1](https://www.rfc-editor.org/rfc/rfc9114#section-4.1).
pub fn parse_request_stream(data: &[u8]) -> Result<Vec<Frame>, Http3ParseError> {
    parse_complete(Http3Parser::request(), data)
}

/// Parses a complete client-initiated unidirectional stream, including its stream-type varint.
///
/// Control streams must start with SETTINGS, and the server-only Push stream type is rejected.
/// See [RFC 9114, Section 6.2](https://www.rfc-editor.org/rfc/rfc9114#section-6.2).
pub fn parse_unidirectional_stream(data: &[u8]) -> Result<Vec<Frame>, Http3ParseError> {
    parse_complete(Http3Parser::unidirectional(), data)
}

fn parse_complete(mut parser: Http3Parser, data: &[u8]) -> Result<Vec<Frame>, Http3ParseError> {
    let frames = parser.push(data).map_err(Http3PushError::into_error)?;
    parser.finish()?;
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{parse_request_stream, parse_unidirectional_stream, Http3ParseError, Http3Parser};
    use crate::{
        h3::{Frame, FrameType, Http3FrameError, SettingValue},
        quic::varint,
    };

    #[test]
    fn configured_constructors_apply_limits_before_input() {
        let mut frame_limited = Http3Parser::request_with_limits(2, 64);
        assert!(frame_limited.capacity() >= 2);
        assert_eq!(frame_limited.max_frame_size(), 2);
        assert_eq!(frame_limited.max_field_section_size(), 64);

        let error = frame_limited.push(&[0x01, 0x03]).unwrap_err();
        assert_eq!(
            error.error(),
            &Http3ParseError::FrameTooLarge {
                length: 3,
                limit: 2,
            }
        );

        let parser = Http3Parser::unidirectional_with_capacity_and_limits(4096, 32, 16);
        assert!(parser.capacity() >= 4096);
        assert_eq!(parser.max_frame_size(), 32);
        assert_eq!(parser.max_field_section_size(), 16);
    }

    #[test]
    fn configured_field_section_limit_reaches_qpack_decoder() {
        let headers = [0x01, 0x03, 0x00, 0x00, 0xd1];
        let mut parser = Http3Parser::request_with_limits(64, 1);

        let error = parser.push(&headers).unwrap_err();
        assert_eq!(
            error.error(),
            &Http3ParseError::Frame(Http3FrameError::QpackDecompression)
        );

        let mut parser = Http3Parser::request_with_limits(64, 64);
        assert!(matches!(
            parser.push(&headers).unwrap().as_slice(),
            [Frame::Headers(_)]
        ));
    }

    #[test]
    fn control_stream_settings_accept_arbitrary_chunks() {
        let mut input = vec![0x00, 0x04, 0x05, 0x01];
        input.extend_from_slice(&[0x80, 0x01, 0x00, 0x00]);
        let mut parser = Http3Parser::unidirectional();
        let mut frames = Vec::new();

        for chunk in input.chunks(2) {
            parser.push_into(chunk, &mut frames).unwrap();
        }

        parser.finish().unwrap();
        let Frame::Settings(frame) = &frames[0] else {
            panic!("expected SETTINGS");
        };
        assert_eq!(frame.settings[0].value, SettingValue::Number(65_536));
    }

    #[test]
    fn request_headers_are_qpack_decoded_in_wire_order() {
        let mut block = BytesMut::from(&[0x00, 0x00, 0xd1, 0x51, 0x0a][..]);
        block.extend_from_slice(b"/api/http3");
        block.extend_from_slice(&[0x5f, 0x50, 0x0b]);
        block.extend_from_slice(b"pingly-test");

        let mut input = Vec::new();
        varint::encode(1, &mut input).unwrap();
        varint::encode(block.len() as u64, &mut input).unwrap();
        input.extend_from_slice(&block);

        let frames = parse_request_stream(&input).unwrap();
        let Frame::Headers(frame) = &frames[0] else {
            panic!("expected HEADERS");
        };

        assert_eq!(&*frame.headers[0].name, b":method");
        assert_eq!(&*frame.headers[1].name, b":path");
        assert_eq!(&*frame.headers[2].value, b"pingly-test");
    }

    #[test]
    fn request_stream_allows_extension_frames_before_headers() {
        let input = [0x21, 0x00, 0x01, 0x03, 0x00, 0x00, 0xd1];

        let frames = parse_request_stream(&input).unwrap();

        assert!(matches!(
            &frames[0],
            Frame::Opaque(frame) if frame.type_id == 0x21 && frame.frame_type == FrameType::Grease
        ));
        assert!(matches!(&frames[1], Frame::Headers(_)));
    }

    #[test]
    fn registered_frames_obey_client_stream_locations() {
        let control_with_data = [0x00, 0x04, 0x00, 0x00, 0x00];
        assert_eq!(
            parse_unidirectional_stream(&control_with_data).unwrap_err(),
            Http3ParseError::UnexpectedFrame { type_id: 0 }
        );

        for type_id in [0x03, 0x04, 0x05, 0x07, 0x0c, 0x0d, 0x0f_0700, 0x0f_0701] {
            let mut input = Vec::new();
            varint::encode(type_id, &mut input).unwrap();
            input.push(0x00);
            assert_eq!(
                parse_request_stream(&input).unwrap_err(),
                Http3ParseError::UnexpectedFrame { type_id }
            );
        }
        for type_id in [0x02, 0x06, 0x08, 0x09] {
            let input = [type_id as u8, 0x00];
            assert_eq!(
                parse_request_stream(&input).unwrap_err(),
                Http3ParseError::UnexpectedFrame { type_id }
            );
        }

        let data_after_trailers = [
            0x01, 0x03, 0x00, 0x00, 0xd1, 0x01, 0x03, 0x00, 0x00, 0xd1, 0x00, 0x00,
        ];
        assert_eq!(
            parse_request_stream(&data_after_trailers).unwrap_err(),
            Http3ParseError::UnexpectedFrame { type_id: 0 }
        );
    }

    #[test]
    fn non_control_unidirectional_streams_are_identified_and_ignored() {
        let frames = parse_unidirectional_stream(&[0x02, 0xff, 0xff]).unwrap();
        assert!(frames.is_empty());
        let frames = parse_unidirectional_stream(&[0x04, 0xff, 0xff]).unwrap();
        assert!(frames.is_empty());

        let mut parser = Http3Parser::unidirectional();
        parser.push(&[0x02]).unwrap();
        assert!(parser.is_ignored());
        assert_eq!(parser.stream_type().unwrap().id, 2);
    }
    #[test]
    fn client_push_streams_are_rejected_explicitly() {
        assert_eq!(
            parse_unidirectional_stream(&[0x01, 0x00]).unwrap_err(),
            Http3ParseError::UnexpectedStreamType { type_id: 0x01 }
        );
    }

    #[test]
    fn complete_streams_require_their_mandatory_initial_frame() {
        assert_eq!(
            parse_request_stream(&[]).unwrap_err(),
            Http3ParseError::ExpectedHeaders
        );
        assert_eq!(
            parse_request_stream(&[0x21, 0x00]).unwrap_err(),
            Http3ParseError::ExpectedHeaders
        );
        assert_eq!(
            parse_unidirectional_stream(&[0x00]).unwrap_err(),
            Http3ParseError::ExpectedSettings
        );
    }

    #[test]
    fn stream_sequence_and_partial_input_are_rejected() {
        assert_eq!(
            parse_unidirectional_stream(&[0x00, 0x00, 0x00]).unwrap_err(),
            Http3ParseError::ExpectedSettings
        );
        assert!(matches!(
            parse_request_stream(&[0x01, 0x04, 0x00]),
            Err(Http3ParseError::IncompleteInput { .. })
        ));
    }
}
