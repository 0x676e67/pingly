use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// A decoded HTTP/2 PRIORITY frame.
///
/// This frame is deprecated but its wire format remains defined by
/// [RFC 9113, Section 6.3](https://www.rfc-editor.org/rfc/rfc9113#section-6.3).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PriorityFrameRepr")]
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

/// Deserialization shape used to validate a saved PRIORITY frame.
#[derive(Deserialize)]
struct PriorityFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Stream that carries the PRIORITY frame.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Decoded dependency fields.
    priority: StreamDependency,
}

/// Represents a stream dependency in HTTP/2 priority frames.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "StreamDependencyRepr")]
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

/// Deserialization shape used to validate decoded priority fields.
#[derive(Deserialize)]
struct StreamDependencyRepr {
    /// Effective decoded weight.
    weight: u16,

    /// Stream dependency identifier.
    depends_on: u32,

    /// Numeric exclusive bit.
    exclusive: u8,
}

// ==== impl PriorityFrame ====

impl TryFrom<PriorityFrameRepr> for PriorityFrame {
    type Error = &'static str;

    fn try_from(repr: PriorityFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Priority {
            return Err("PRIORITY frame_type must be Priority");
        }
        if repr.stream_id == 0 || repr.stream_id > 0x7fff_ffff {
            return Err("PRIORITY stream_id must be a nonzero 31-bit value");
        }
        if repr.length != 5 {
            return Err("PRIORITY payload length must be five");
        }
        if repr.priority.depends_on == repr.stream_id {
            return Err("a stream cannot depend on itself");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            priority: repr.priority,
        })
    }
}

impl TryFrom<StreamDependencyRepr> for StreamDependency {
    type Error = &'static str;

    fn try_from(repr: StreamDependencyRepr) -> Result<Self, Self::Error> {
        if !(1..=256).contains(&repr.weight) {
            return Err("priority weight must be in the inclusive range 1..=256");
        }
        if repr.depends_on > 0x7fff_ffff {
            return Err("priority dependency must be a 31-bit stream identifier");
        }
        if repr.exclusive > 1 {
            return Err("priority exclusive value must be zero or one");
        }

        Ok(Self {
            weight: repr.weight,
            depends_on: repr.depends_on,
            exclusive: repr.exclusive,
        })
    }
}

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
    use crate::h2::frame::FrameError;

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

    #[test]
    fn priority_deserialization_rejects_invalid_ranges() {
        let bad_weight = r#"{"weight":0,"depends_on":0,"exclusive":0}"#;
        let bad_frame = r#"{
            "frame_type":"Priority",
            "stream_id":3,
            "length":5,
            "priority":{"weight":16,"depends_on":3,"exclusive":0}
        }"#;

        assert!(serde_json::from_str::<StreamDependency>(bad_weight).is_err());
        assert!(serde_json::from_str::<PriorityFrame>(bad_frame).is_err());
    }
}
