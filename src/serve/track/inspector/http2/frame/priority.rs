use serde::Serialize;

use super::{error::Error, FrameType};

/// The PRIORITY frame (type=0x2) specifies the sender-advised priority
/// of a stream [Section 5.3].  It can be sent in any stream state,
/// including idle or closed streams.
/// [Section 5.3]: <https://tools.ietf.org/html/rfc7540#section-5.3>
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
pub struct StreamDependency {
    /// The stream weight as received in the PRIORITY frame (0~255).
    /// According to RFC 7540 5.3.2, the actual weight is always `weight + 1` (range 1~256).
    /// That is, a value of 0 means weight 1, 255 means weight 256.
    pub weight: u16,

    /// The stream identifier this stream depends on.
    pub depends_on: u32,

    /// Whether this dependency is exclusive (1 for exclusive, 0 for non-exclusive).
    pub exclusive: u8,
}

// ==== impl PriorityFrame ====

impl TryFrom<(u32, &[u8])> for PriorityFrame {
    type Error = Error;

    fn try_from((stream_id, buf): (u32, &[u8])) -> Result<Self, Self::Error> {
        let priority = StreamDependency::try_from(buf)?;

        if stream_id == priority.depends_on {
            return Err(Error::InvalidStreamId);
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
    type Error = Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() != 5 {
            return Err(Error::BadFrameSize);
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
