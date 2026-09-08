//! HTTP/2 connection liveness probes.

use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// A PING request or acknowledgement, as defined by
/// [RFC 9113, Section 6.7](https://www.rfc-editor.org/rfc/rfc9113#section-6.7).
/// The payload is opaque, not a timestamp or an integer defined by HTTP/2.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PingFrameRepr")]
pub struct PingFrame {
    /// Frame category, always [`FrameType::Ping`].
    pub frame_type: FrameType,

    /// Connection identifier, always zero.
    pub stream_id: u32,

    /// Payload length, always eight bytes.
    pub length: usize,

    /// Original flags, including ACK (`0x01`) and any unused bits.
    pub flags: u8,

    /// Eight bytes echoed unchanged by the acknowledgement.
    pub payload: [u8; 8],
}

/// Saved PING fields validated before constructing the public model.
#[derive(Deserialize)]
struct PingFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved connection identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Original flag byte.
    flags: u8,

    /// Original opaque data.
    payload: [u8; 8],
}

impl PingFrame {
    /// Returns whether this frame acknowledges a previous PING.
    pub const fn is_ack(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl TryFrom<PingFrameRepr> for PingFrame {
    type Error = &'static str;

    fn try_from(repr: PingFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Ping || repr.stream_id != 0 || repr.length != 8 {
            return Err("PING requires frame_type Ping, stream zero, and eight payload bytes");
        }
        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            payload: repr.payload,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for PingFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id != 0 {
            return Err(FrameError::InvalidStreamId);
        }
        let payload = payload.try_into().map_err(|_| FrameError::BadFrameSize)?;
        Ok(Self {
            frame_type: FrameType::Ping,
            stream_id,
            length: 8,
            flags,
            payload,
        })
    }
}
