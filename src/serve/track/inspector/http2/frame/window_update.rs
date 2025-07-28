use serde::Serialize;

use super::{error::Error, FrameType};

/// Represents an HTTP/2 WINDOW_UPDATE frame.
///
/// See RFC 7540, Section 6.9: <https://datatracker.ietf.org/doc/html/rfc7540#section-6.9>
/// This frame is used for flow control, indicating how many additional bytes the sender is
/// permitted to transmit.
#[derive(Debug, Serialize)]
pub struct WindowUpdateFrame {
    /// The type of this frame (should always be `FrameType::WindowUpdate`)
    pub frame_type: FrameType,

    /// The length of the frame payload (should always be 4 for WINDOW_UPDATE)
    pub length: usize,

    /// The window size increment (31 bits, most significant bit is reserved and must be zero).
    /// This value specifies the number of bytes that can be sent.
    pub increment: u32,
}

impl TryFrom<&[u8]> for WindowUpdateFrame {
    type Error = Error;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.len() != 4 {
            return Err(Error::BadFrameSize);
        }

        let window_size_increment =
            u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        Ok(WindowUpdateFrame {
            frame_type: FrameType::WindowUpdate,
            length: payload.len(),
            increment: window_size_increment,
        })
    }
}
