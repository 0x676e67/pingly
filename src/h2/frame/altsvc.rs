//! HTTP/2 alternative-service advertisements.

use serde::{Deserialize, Serialize};

use super::{headers::header_bytes, FrameError, FrameType};

/// An ALTSVC advertisement from
/// [RFC 7838, Section 4](https://www.rfc-editor.org/rfc/rfc7838#section-4).
/// Capturing an advertisement does not establish that the sender is authoritative for its origin.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AltSvcFrameRepr")]
pub struct AltSvcFrame {
    /// Frame category, always [`FrameType::AltSvc`].
    pub frame_type: FrameType,

    /// Associated request stream, or zero when an explicit origin is present.
    pub stream_id: u32,

    /// Payload length, including the two-byte origin length.
    pub length: usize,

    /// Original unused flag byte.
    pub flags: u8,

    /// Explicit origin, empty when the associated request supplies it.
    #[serde(with = "header_bytes")]
    pub origin: Box<[u8]>,

    /// Alt-Svc field value, retaining text or non-UTF-8 bytes without normalization.
    #[serde(with = "header_bytes")]
    pub field_value: Box<[u8]>,
}

/// Saved ALTSVC fields, including lossless origin and field-value bytes.
#[derive(Deserialize)]
struct AltSvcFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved associated stream.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Original flags.
    flags: u8,

    /// Saved origin bytes.
    #[serde(with = "header_bytes")]
    origin: Box<[u8]>,

    /// Saved Alt-Svc value bytes.
    #[serde(with = "header_bytes")]
    field_value: Box<[u8]>,
}

impl AltSvcFrame {
    /// Returns whether the origin's presence matches the stream scope in RFC 7838 Section 4.
    /// Invalid advertisements remain observable, but clients must ignore them.
    pub fn has_valid_origin_scope(&self) -> bool {
        (self.stream_id == 0) != self.origin.is_empty()
    }
}

impl TryFrom<AltSvcFrameRepr> for AltSvcFrame {
    type Error = &'static str;

    fn try_from(repr: AltSvcFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::AltSvc || repr.stream_id > 0x7fff_ffff {
            return Err("ALTSVC requires frame_type AltSvc and a 31-bit stream ID");
        }
        if repr.origin.len() > usize::from(u16::MAX)
            || repr.length > 0x00ff_ffff
            || repr
                .origin
                .len()
                .checked_add(2)
                .and_then(|len| len.checked_add(repr.field_value.len()))
                != Some(repr.length)
        {
            return Err("ALTSVC length does not match its origin and field value");
        }
        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            origin: repr.origin,
            field_value: repr.field_value,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for AltSvcFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id > 0x7fff_ffff {
            return Err(FrameError::InvalidStreamId);
        }
        let prefix = payload.get(..2).ok_or(FrameError::BadFrameSize)?;
        let origin_end = 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        let origin = payload.get(2..origin_end).ok_or(FrameError::BadFrameSize)?;
        if payload.len() > 0x00ff_ffff {
            return Err(FrameError::BadFrameSize);
        }
        Ok(Self {
            frame_type: FrameType::AltSvc,
            stream_id,
            length: payload.len(),
            flags,
            origin: origin.into(),
            field_value: payload[origin_end..].into(),
        })
    }
}
