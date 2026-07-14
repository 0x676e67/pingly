mod error;
mod headers;
mod priority;
mod settings;
mod window_update;

use headers::{HeadersFrame, PendingHeaders};
use priority::PriorityFrame;
use serde::Serialize;
use settings::SettingsFrame;
use window_update::WindowUpdateFrame;

/// Stateful parser for HTTP/2 frames and fragmented field blocks.
#[derive(Default)]
pub(crate) struct FrameParser {
    pending_headers: Option<PendingHeaders>,
}

impl FrameParser {
    pub(crate) fn parse(&mut self, data: &[u8]) -> (usize, Option<Frame>) {
        const FRAME_HEADER_LEN: usize = 9;

        if data.len() < FRAME_HEADER_LEN {
            return (0, None);
        }
        let header = &data[..FRAME_HEADER_LEN];
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let ty = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
        let payload = &data[FRAME_HEADER_LEN..];
        if payload.len() < length {
            return (0, None);
        }

        let frame_len = FRAME_HEADER_LEN + length;
        match self.parse_payload(ty, flags, stream_id, &payload[..length]) {
            Ok(frame) => (frame_len, frame),
            Err(error) => {
                self.pending_headers = None;
                tracing::debug!(?error, "failed to parse HTTP/2 frame");
                (frame_len, None)
            }
        }
    }

    fn parse_payload(
        &mut self,
        ty: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<Option<Frame>, error::Error> {
        // RFC 9113 requires CONTINUATION frames to be consecutive and on the
        // same stream until END_HEADERS is received.
        // See: <https://www.rfc-editor.org/rfc/rfc9113#section-6.10>
        if let Some(pending) = self.pending_headers.as_mut() {
            if ty != 0x9 {
                return Err(error::Error::ExpectedContinuation);
            }

            if !pending.push_continuation(flags, stream_id, payload)? {
                return Ok(None);
            }

            let Some(pending) = self.pending_headers.take() else {
                return Err(error::Error::MalformedMessage);
            };
            return pending.finish().map(Frame::Headers).map(Some);
        }

        match ty {
            0x1 => {
                let pending = PendingHeaders::try_from((flags, stream_id, payload))?;
                if pending.is_complete() {
                    pending.finish().map(Frame::Headers).map(Some)
                } else {
                    self.pending_headers = Some(pending);
                    Ok(None)
                }
            }
            0x9 => Err(error::Error::UnexpectedContinuation),
            _ => Frame::try_from((ty, flags, stream_id, payload)).map(Some),
        }
    }
}

/// Represents HTTP/2 frame.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Frame {
    Settings(SettingsFrame),
    WindowUpdate(WindowUpdateFrame),
    Priority(PriorityFrame),
    Headers(HeadersFrame),
    Unknown(UnknownFrame),
}

/// Represents frame types for serialization.
#[derive(Debug, Serialize)]
pub enum FrameType {
    Settings,
    WindowUpdate,
    Headers,
    Continuation,
    Priority,
    Unknown,
}

/// Represents an unknown frame.
#[derive(Debug, Serialize)]
pub struct UnknownFrame {
    pub frame_type: FrameType,
    pub length: usize,
    pub payload: Vec<u8>,
}

impl TryFrom<(u8, u8, u32, &[u8])> for Frame {
    type Error = error::Error;

    fn try_from(
        (ty, flags, stream_id, payload): (u8, u8, u32, &[u8]),
    ) -> Result<Self, Self::Error> {
        match ty {
            0x1 => HeadersFrame::try_from((flags, stream_id, payload)).map(Frame::Headers),
            0x2 => PriorityFrame::try_from((stream_id, payload)).map(Frame::Priority),
            0x4 => SettingsFrame::try_from((flags, stream_id, payload)).map(Frame::Settings),
            0x8 => WindowUpdateFrame::try_from(payload).map(Frame::WindowUpdate),
            0x9 => Err(error::Error::UnexpectedContinuation),
            _ => {
                // If the frame type is unknown, we create an UnknownFrame
                let frame = UnknownFrame {
                    frame_type: FrameType::Unknown,
                    length: payload.len(),
                    payload: payload.to_vec(),
                };
                Ok(Frame::Unknown(frame))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameParser};

    #[test]
    fn headers_are_decoded_after_continuation_completes_the_block() {
        let mut parser = FrameParser::default();
        let headers = [0, 0, 1, 0x1, 0x1, 0, 0, 0, 1, 0x82];
        let continuation = [0, 0, 1, 0x9, 0x4, 0, 0, 0, 1, 0x84];

        let (consumed, frame) = parser.parse(&headers);
        assert_eq!(consumed, headers.len());
        assert!(frame.is_none());

        let (consumed, frame) = parser.parse(&continuation);
        assert_eq!(consumed, continuation.len());
        let Some(Frame::Headers(frame)) = frame else {
            panic!("expected the completed HEADERS frame");
        };

        assert_eq!(frame.pseudo_headers, ['m', 'p']);
        assert_eq!(&*frame.headers[0].name, ":method");
        assert_eq!(&*frame.headers[0].value, "GET");
        assert_eq!(&*frame.headers[1].name, ":path");
        assert_eq!(&*frame.headers[1].value, "/");
        assert_eq!(frame.continuations.len(), 1);
    }

    #[test]
    fn continuation_must_use_the_open_field_block_stream() {
        let mut parser = FrameParser::default();
        let headers = [0, 0, 1, 0x1, 0, 0, 0, 0, 1, 0x82];
        let wrong_stream = [0, 0, 1, 0x9, 0x4, 0, 0, 0, 3, 0x84];

        assert_eq!(parser.parse(&headers).0, headers.len());
        assert_eq!(parser.parse(&wrong_stream).0, wrong_stream.len());
        assert!(parser.pending_headers.is_none());
    }
}
