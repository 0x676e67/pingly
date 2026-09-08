//! HTTP/2 connection shutdown metadata.

use serde::{Deserialize, Serialize};

use super::{ErrorCode, FrameError, FrameType};

/// A GOAWAY frame, as defined by
/// [RFC 9113, Section 6.8](https://www.rfc-editor.org/rfc/rfc9113#section-6.8).
/// Existing streams up to `last_stream_id` may continue after this frame.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GoAwayFrameRepr")]
pub struct GoAwayFrame {
    /// Frame category, always [`FrameType::GoAway`].
    pub frame_type: FrameType,

    /// Connection identifier, always zero.
    pub stream_id: u32,

    /// Payload length, including the eight-byte fixed prefix.
    pub length: usize,

    /// Original unused flag byte.
    pub flags: u8,

    /// Highest peer-initiated stream that might have been processed.
    pub last_stream_id: u32,

    /// Reason for shutting down the connection.
    pub error_code: ErrorCode,

    /// Optional diagnostic bytes, whose format is endpoint-specific.
    pub debug_data: Box<[u8]>,
}

/// Saved GOAWAY fields checked for consistent lengths and identifiers.
#[derive(Deserialize)]
struct GoAwayFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved connection identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Original flags.
    flags: u8,

    /// Saved last processed stream identifier.
    last_stream_id: u32,

    /// Saved error code and name.
    error_code: ErrorCode,

    /// Saved diagnostic data.
    debug_data: Box<[u8]>,
}

impl TryFrom<GoAwayFrameRepr> for GoAwayFrame {
    type Error = &'static str;

    fn try_from(repr: GoAwayFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::GoAway || repr.stream_id != 0 {
            return Err("GOAWAY requires frame_type GoAway and stream zero");
        }
        if repr.last_stream_id > 0x7fff_ffff {
            return Err("GOAWAY last_stream_id must be a 31-bit value");
        }
        if repr.length > 0x00ff_ffff || repr.debug_data.len().checked_add(8) != Some(repr.length) {
            return Err("GOAWAY length does not match its diagnostic data");
        }
        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            last_stream_id: repr.last_stream_id,
            error_code: repr.error_code,
            debug_data: repr.debug_data,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for GoAwayFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id != 0 {
            return Err(FrameError::InvalidStreamId);
        }
        let prefix = payload.get(..8).ok_or(FrameError::BadFrameSize)?;
        if payload.len() > 0x00ff_ffff {
            return Err(FrameError::BadFrameSize);
        }
        Ok(Self {
            frame_type: FrameType::GoAway,
            stream_id,
            length: payload.len(),
            flags,
            last_stream_id: u32::from_be_bytes([prefix[0] & 0x7f, prefix[1], prefix[2], prefix[3]]),
            error_code: u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]).into(),
            debug_data: payload[8..].into(),
        })
    }
}
