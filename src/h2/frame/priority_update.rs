//! HTTP/2 extensible-priority update frames.

use std::str;

use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// A `PRIORITY_UPDATE` frame carrying the latest priority signal for one stream.
///
/// The frame itself uses stream ID zero. `prioritized_stream_id` identifies the request or push
/// stream whose response priority changed. See
/// [RFC 9218, Section 7.1](https://www.rfc-editor.org/rfc/rfc9218#section-7.1).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PriorityUpdateFrameRepr")]
pub struct PriorityUpdateFrame {
    /// The frame category, always [`FrameType::PriorityUpdate`].
    pub frame_type: FrameType,

    /// Connection-level stream identifier from the frame header, always zero.
    pub stream_id: u32,

    /// Payload length, including the four-byte target stream identifier.
    pub length: usize,

    /// Original unused flag byte retained for wire analysis.
    pub flags: u8,

    /// Stream whose response priority is being updated.
    pub prioritized_stream_id: u32,

    /// RFC 9218 Priority Field Value carried as ASCII text.
    pub priority: Box<str>,
}

/// Deserialization shape validated before constructing [`PriorityUpdateFrame`].
#[derive(Deserialize)]
struct PriorityUpdateFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved connection-level stream identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Saved unused flag byte.
    flags: u8,

    /// Saved target stream identifier.
    prioritized_stream_id: u32,

    /// Saved Priority Field Value.
    priority: Box<str>,
}

impl TryFrom<PriorityUpdateFrameRepr> for PriorityUpdateFrame {
    type Error = &'static str;

    fn try_from(repr: PriorityUpdateFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::PriorityUpdate {
            return Err("PRIORITY_UPDATE frame_type must be PriorityUpdate");
        }
        if repr.stream_id != 0 {
            return Err("PRIORITY_UPDATE must use connection stream zero");
        }
        if repr.prioritized_stream_id == 0 || repr.prioritized_stream_id > 0x7fff_ffff {
            return Err("PRIORITY_UPDATE target must be a nonzero 31-bit stream ID");
        }
        if repr.priority.is_empty() || !repr.priority.is_ascii() {
            return Err("PRIORITY_UPDATE value must be nonempty ASCII text");
        }
        if 4usize.checked_add(repr.priority.len()) != Some(repr.length) {
            return Err("PRIORITY_UPDATE length does not match its value");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            prioritized_stream_id: repr.prioritized_stream_id,
            priority: repr.priority,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for PriorityUpdateFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id != 0 {
            return Err(FrameError::InvalidStreamId);
        }
        let target = payload.get(..4).ok_or(FrameError::BadFrameSize)?;
        let prioritized_stream_id =
            u32::from_be_bytes([target[0] & 0x7f, target[1], target[2], target[3]]);
        if prioritized_stream_id == 0 {
            return Err(FrameError::InvalidStreamId);
        }

        let priority = payload.get(4..).ok_or(FrameError::BadFrameSize)?;
        if priority.is_empty() || !priority.is_ascii() {
            return Err(FrameError::MalformedMessage);
        }
        let priority = str::from_utf8(priority)
            .map_err(|_| FrameError::MalformedMessage)?
            .into();

        Ok(Self {
            frame_type: FrameType::PriorityUpdate,
            stream_id,
            length: payload.len(),
            flags,
            prioritized_stream_id,
            priority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PriorityUpdateFrame;

    #[test]
    fn priority_update_preserves_target_value_and_json_shape() {
        let payload = [0, 0, 0, 3, b'u', b'=', b'1', b',', b' ', b'i'];
        let frame = PriorityUpdateFrame::try_from((0xa5, 0, &payload[..])).unwrap();

        assert_eq!(frame.prioritized_stream_id, 3);
        assert_eq!(&*frame.priority, "u=1, i");
        assert_eq!(frame.flags, 0xa5);

        let json = serde_json::to_value(&frame).unwrap();
        let restored: PriorityUpdateFrame = serde_json::from_value(json).unwrap();
        assert_eq!(restored, frame);

        assert!(PriorityUpdateFrame::try_from((0, 1, &payload[..])).is_err());
        assert!(PriorityUpdateFrame::try_from((0, 0, &[0, 0, 0, 0, b'u'][..])).is_err());
    }
}
