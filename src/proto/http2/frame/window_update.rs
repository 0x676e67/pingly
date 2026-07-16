use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// Represents an HTTP/2 WINDOW_UPDATE frame.
///
/// See [RFC 9113, Section 6.9](https://www.rfc-editor.org/rfc/rfc9113#section-6.9).
/// This frame is used for flow control, indicating how many additional bytes the sender is
/// permitted to transmit.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WindowUpdateFrameRepr")]
pub struct WindowUpdateFrame {
    /// The type of this frame (should always be `FrameType::WindowUpdate`)
    pub frame_type: FrameType,

    /// The affected stream, or zero for the connection flow-control window.
    pub stream_id: u32,

    /// The length of the frame payload (should always be 4 for WINDOW_UPDATE)
    pub length: usize,

    /// The window size increment (31 bits, most significant bit is reserved and must be zero).
    /// This value specifies the number of bytes that can be sent.
    pub increment: u32,
}

/// Deserialization shape used to validate a saved WINDOW_UPDATE frame.
#[derive(Deserialize)]
struct WindowUpdateFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Affected stream identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Saved flow-control increment.
    increment: u32,
}

impl TryFrom<WindowUpdateFrameRepr> for WindowUpdateFrame {
    type Error = &'static str;

    fn try_from(repr: WindowUpdateFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::WindowUpdate {
            return Err("WINDOW_UPDATE frame_type must be WindowUpdate");
        }
        if repr.stream_id > 0x7fff_ffff {
            return Err("WINDOW_UPDATE stream_id must be a 31-bit value");
        }
        if repr.length != 4 {
            return Err("WINDOW_UPDATE payload length must be four");
        }
        if !(1..=0x7fff_ffff).contains(&repr.increment) {
            return Err("WINDOW_UPDATE increment must be a nonzero 31-bit value");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            increment: repr.increment,
        })
    }
}

impl TryFrom<(u32, &[u8])> for WindowUpdateFrame {
    type Error = FrameError;

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, Self::Error> {
        if payload.len() != 4 {
            tracing::debug!("Invalid WINDOW_UPDATE frame size: {}", payload.len());
            return Err(FrameError::BadFrameSize);
        }

        let window_size_increment =
            u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        if window_size_increment == 0 {
            return Err(FrameError::InvalidWindowIncrement);
        }

        Ok(WindowUpdateFrame {
            frame_type: FrameType::WindowUpdate,
            stream_id,
            length: payload.len(),
            increment: window_size_increment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::WindowUpdateFrame;
    use crate::proto::http2::frame::FrameError;

    #[test]
    fn window_update_rejects_zero_increment() {
        assert_eq!(
            WindowUpdateFrame::try_from((0, &[0; 4][..])).unwrap_err(),
            FrameError::InvalidWindowIncrement
        );
    }

    #[test]
    fn window_update_retains_stream_and_ignores_reserved_bit() {
        let frame = WindowUpdateFrame::try_from((7, &[0x80, 0, 0, 1][..])).unwrap();

        assert_eq!(frame.stream_id, 7);
        assert_eq!(frame.increment, 1);
    }

    #[test]
    fn window_update_deserialization_rejects_invalid_metadata() {
        let zero_increment =
            r#"{"frame_type":"WindowUpdate","stream_id":0,"length":4,"increment":0}"#;
        let bad_length = r#"{"frame_type":"WindowUpdate","stream_id":0,"length":3,"increment":1}"#;

        assert!(serde_json::from_str::<WindowUpdateFrame>(zero_increment).is_err());
        assert!(serde_json::from_str::<WindowUpdateFrame>(bad_length).is_err());
    }
}
