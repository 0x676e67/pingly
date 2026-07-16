use bytes::{Buf, BytesMut};

use super::frame::{Frame, FrameParseError, FrameParseOutcome, FrameParser};

/// The HTTP/2 client connection preface defined by RFC 9113.
///
/// See [RFC 9113, Section 3.4](https://www.rfc-editor.org/rfc/rfc9113#section-3.4).
pub const HTTP2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Errors returned while parsing an HTTP/2 byte stream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Http2ParseError {
    /// The stream does not begin with the HTTP/2 client connection preface.
    #[error("invalid HTTP/2 client connection preface")]
    InvalidPreface,

    /// The supplied complete input ends in a partial frame or field block.
    #[error("incomplete HTTP/2 input")]
    IncompleteInput {
        /// Bytes retained because they do not yet form a complete frame.
        buffered_bytes: usize,

        /// Whether the parser still needs the rest of the client preface.
        waiting_for_preface: bool,

        /// Whether a HEADERS field block still needs a CONTINUATION frame.
        waiting_for_continuation: bool,
    },

    /// A complete frame violated its HTTP/2 wire format.
    #[error(transparent)]
    Frame(#[from] FrameParseError),
}

/// Incrementally parses HTTP/2 frames from arbitrary byte chunks.
///
/// The default parser expects the HTTP/2 client connection preface. This is
/// the convenient choice for bytes captured from the start of a TCP stream.
/// Use [`Self::without_preface`] when the input already starts at a frame
/// header.
#[derive(Debug)]
pub struct Http2Parser {
    /// Bytes retained until they form a complete preface or frame.
    buffer: BytesMut,

    /// Connection-level frame and HPACK decoding state.
    frame_parser: FrameParser,

    /// Whether this parser expects a client connection preface.
    requires_preface: bool,

    /// Whether the expected client connection preface has been consumed.
    preface_complete: bool,
}

impl Http2Parser {
    /// Creates a parser that expects the HTTP/2 client connection preface.
    #[inline]
    pub fn new() -> Self {
        Self::with_preface(true)
    }

    /// Creates a parser whose input begins directly at an HTTP/2 frame header.
    #[inline]
    pub fn without_preface() -> Self {
        Self::with_preface(false)
    }

    fn with_preface(requires_preface: bool) -> Self {
        Self {
            buffer: BytesMut::new(),
            frame_parser: FrameParser::default(),
            requires_preface,
            preface_complete: !requires_preface,
        }
    }

    /// Appends one byte chunk and returns every logical frame completed by it.
    ///
    /// The chunk may stop anywhere, including inside the connection preface,
    /// frame header, payload, or HPACK field block. Use [`Self::push_into`] to
    /// reuse an existing output vector in allocation-sensitive code.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Frame>, Http2ParseError> {
        let mut frames = Vec::new();
        self.push_into(data, &mut frames)?;
        Ok(frames)
    }

    /// Appends one byte chunk and writes completed frames into `output`.
    ///
    /// Returns the number of frames appended. If a complete malformed frame is
    /// encountered, that frame is removed from the internal buffer before the
    /// error is returned; calling this method again can continue with trailing
    /// bytes already buffered after it.
    pub fn push_into(
        &mut self,
        data: &[u8],
        output: &mut Vec<Frame>,
    ) -> Result<usize, Http2ParseError> {
        let initial_len = output.len();
        self.buffer.extend_from_slice(data);

        if !self.preface_complete {
            let prefix_len = self.buffer.len().min(HTTP2_CLIENT_PREFACE.len());
            if self.buffer[..prefix_len] != HTTP2_CLIENT_PREFACE[..prefix_len] {
                self.clear();
                return Err(Http2ParseError::InvalidPreface);
            }
            if prefix_len < HTTP2_CLIENT_PREFACE.len() {
                return Ok(0);
            }

            self.buffer.advance(HTTP2_CLIENT_PREFACE.len());
            self.preface_complete = true;
        }

        loop {
            match self.frame_parser.parse(&self.buffer) {
                Ok(FrameParseOutcome::Incomplete) => break,
                Ok(FrameParseOutcome::Consumed { bytes, frame }) => {
                    self.buffer.advance(bytes);
                    if let Some(frame) = frame {
                        output.push(frame);
                    }
                }
                Err(error) => {
                    let consumed = error.consumed.min(self.buffer.len());
                    self.buffer.advance(consumed);
                    return Err(error.into());
                }
            }
        }

        Ok(output.len() - initial_len)
    }

    /// Returns the number of bytes retained for a future call to [`Self::push`].
    #[inline]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether no partial preface, frame, or field block remains.
    #[inline]
    pub fn is_idle(&self) -> bool {
        self.preface_complete
            && self.buffer.is_empty()
            && !self.frame_parser.is_waiting_for_continuation()
    }

    /// Verifies that a finite input ended on a complete logical frame.
    pub fn finish(&self) -> Result<(), Http2ParseError> {
        if self.is_idle() {
            return Ok(());
        }

        Err(Http2ParseError::IncompleteInput {
            buffered_bytes: self.buffer.len(),
            waiting_for_preface: !self.preface_complete,
            waiting_for_continuation: self.frame_parser.is_waiting_for_continuation(),
        })
    }

    /// Drops buffered input and partial field-block state so the parser can be reused.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.frame_parser.reset();
        self.preface_complete = !self.requires_preface;
    }
}

impl Default for Http2Parser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses a complete HTTP/2 client byte stream, including its connection preface.
///
/// Use [`Http2Parser`] directly when bytes arrive incrementally.
pub fn parse_connection(data: &[u8]) -> Result<Vec<Frame>, Http2ParseError> {
    parse_complete(Http2Parser::new(), data)
}

/// Parses complete HTTP/2 wire frames without a connection preface.
///
/// This is useful for a captured frame sequence or a protocol test vector.
pub fn parse_frames(data: &[u8]) -> Result<Vec<Frame>, Http2ParseError> {
    parse_complete(Http2Parser::without_preface(), data)
}

fn parse_complete(mut parser: Http2Parser, data: &[u8]) -> Result<Vec<Frame>, Http2ParseError> {
    let frames = parser.push(data)?;
    parser.finish()?;
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        parse_connection, parse_frames, Http2ParseError, Http2Parser, HTTP2_CLIENT_PREFACE,
    };
    use crate::proto::http2::frame::Frame;

    const SETTINGS_FRAME: &[u8] = &[0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x10, 0];

    #[test]
    fn stream_parser_accepts_arbitrary_tcp_chunks() {
        let mut input = HTTP2_CLIENT_PREFACE.to_vec();
        input.extend_from_slice(SETTINGS_FRAME);
        let mut parser = Http2Parser::new();
        let mut frames = Vec::new();

        for chunk in input.chunks(5) {
            parser.push_into(chunk, &mut frames).unwrap();
        }

        parser.finish().unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], Frame::Settings(_)));
    }

    #[test]
    fn complete_helpers_distinguish_prefaced_and_frame_only_data() {
        let mut connection = HTTP2_CLIENT_PREFACE.to_vec();
        connection.extend_from_slice(SETTINGS_FRAME);

        assert_eq!(parse_connection(&connection).unwrap().len(), 1);
        assert_eq!(parse_frames(SETTINGS_FRAME).unwrap().len(), 1);
        assert!(matches!(
            parse_connection(SETTINGS_FRAME),
            Err(Http2ParseError::InvalidPreface)
        ));
    }

    #[test]
    fn complete_helper_rejects_trailing_partial_frame() {
        let error = parse_frames(&SETTINGS_FRAME[..10]).unwrap_err();

        assert!(matches!(
            error,
            Http2ParseError::IncompleteInput {
                buffered_bytes: 10,
                waiting_for_preface: false,
                waiting_for_continuation: false,
            }
        ));
    }

    #[test]
    fn parsed_frames_roundtrip_through_json() {
        let frames = parse_frames(SETTINGS_FRAME).unwrap();
        let json = serde_json::to_value(&frames).unwrap();
        let restored: Vec<Frame> = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(restored, frames);
        assert!(matches!(json, Value::Array(_)));
    }
}
