use serde::Serialize;

use super::{error::Error, FrameType};

/// Represents an HTTP/2 WINDOW_UPDATE frame.
///
/// See [RFC 9113, Section 6.9](https://www.rfc-editor.org/rfc/rfc9113#section-6.9).
/// This frame is used for flow control, indicating how many additional bytes the sender is
/// permitted to transmit.
#[derive(Debug, Serialize)]
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

impl TryFrom<(u32, &[u8])> for WindowUpdateFrame {
    type Error = Error;

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, Self::Error> {
        if payload.len() != 4 {
            tracing::debug!("Invalid WINDOW_UPDATE frame size: {}", payload.len());
            return Err(Error::BadFrameSize);
        }

        let window_size_increment =
            u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        if window_size_increment == 0 {
            return Err(Error::InvalidWindowIncrement);
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
    use crate::proto::http2::frame::error::Error;

    #[test]
    fn window_update_rejects_zero_increment() {
        assert_eq!(
            WindowUpdateFrame::try_from((0, &[0; 4][..])).unwrap_err(),
            Error::InvalidWindowIncrement
        );
    }

    #[test]
    fn window_update_retains_stream_and_ignores_reserved_bit() {
        let frame = WindowUpdateFrame::try_from((7, &[0x80, 0, 0, 1][..])).unwrap();

        assert_eq!(frame.stream_id, 7);
        assert_eq!(frame.increment, 1);
    }
}
