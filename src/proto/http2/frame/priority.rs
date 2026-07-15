use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// A decoded HTTP/2 PRIORITY frame.
///
/// This frame is deprecated but its wire format remains defined by
/// [RFC 9113, Section 6.3](https://www.rfc-editor.org/rfc/rfc9113#section-6.3).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityFrame {
    /// The type of the frame, which is always `FrameType::Priority`.
    pub frame_type: FrameType,

    /// The stream identifier this frame applies to.
    pub stream_id: u32,

    /// The length of the frame payload, excluding the 9-byte header.
    pub length: usize,

    /// The priority information contained in this frames.
    pub priority: StreamDependency,
}

/// Represents a stream dependency in HTTP/2 priority frames.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDependency {
    /// The effective stream weight after decoding the wire value (range 1..=256).
    /// RFC 7540 Section 5.3.2 encodes weights as one less than their effective value:
    /// <https://www.rfc-editor.org/rfc/rfc7540#section-5.3.2>
    pub weight: u16,

    /// The stream identifier this stream depends on.
    pub depends_on: u32,

    /// Whether this dependency is exclusive (1 for exclusive, 0 for non-exclusive).
    pub exclusive: u8,
}

// ==== impl PriorityFrame ====

impl TryFrom<(u32, &[u8])> for PriorityFrame {
    type Error = FrameError;

    fn try_from((stream_id, buf): (u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id == 0 {
            return Err(FrameError::InvalidStreamId);
        }

        let priority = StreamDependency::try_from(buf)?;

        if stream_id == priority.depends_on {
            return Err(FrameError::InvalidStreamDependency);
        }

        Ok(PriorityFrame {
            frame_type: FrameType::Priority,
            stream_id,
            length: buf.len(),
            priority,
        })
    }
}

// ==== impl StreamDependency ====

impl TryFrom<&[u8]> for StreamDependency {
    type Error = FrameError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() != 5 {
            tracing::debug!("Invalid PRIORITY frame size: {}", buf.len());
            return Err(FrameError::BadFrameSize);
        }

        let (weight, depends_on, exclusive) = {
            const STREAM_ID_MASK: u32 = 1 << 31;

            let mut ubuf = [0; 4];
            ubuf.copy_from_slice(&buf[0..4]);
            let unpacked = u32::from_be_bytes(ubuf);
            let exclusive = unpacked & STREAM_ID_MASK == STREAM_ID_MASK;

            // Now clear the most significant bit, as that is reserved and MUST be
            // ignored when received.
            (buf[4], unpacked & !STREAM_ID_MASK, exclusive)
        };

        Ok(StreamDependency {
            weight: weight as u16 + 1,
            depends_on,
            exclusive: exclusive as u8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PriorityFrame, StreamDependency};
    use crate::proto::http2::frame::FrameError;

    #[test]
    fn priority_requires_a_nonzero_distinct_stream_dependency() {
        assert_eq!(
            PriorityFrame::try_from((0, &[0; 5][..])).unwrap_err(),
            FrameError::InvalidStreamId
        );
        assert_eq!(
            PriorityFrame::try_from((3, &[0, 0, 0, 3, 0][..])).unwrap_err(),
            FrameError::InvalidStreamDependency
        );
    }

    #[test]
    fn priority_weight_is_one_more_than_the_wire_value() {
        let priority = StreamDependency::try_from(&[0, 0, 0, 0, 0xff][..]).unwrap();

        assert_eq!(priority.weight, 256);
    }
}
