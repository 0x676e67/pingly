//! HTTP/2 origin advertisements.

use serde::{Deserialize, Serialize};

use super::{headers::header_bytes, FrameError, FrameType};

/// One length-prefixed origin entry from
/// [RFC 8336, Section 2.1](https://www.rfc-editor.org/rfc/rfc8336#section-2.1).
/// Invalid origin strings are retained for analysis, not treated as authorized origins.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OriginEntry {
    /// Original bytes, serialized as text when UTF-8 or as a hexadecimal object otherwise.
    #[serde(with = "header_bytes")]
    pub value: Box<[u8]>,
}

/// An ORIGIN frame. Origin entries do not authorize connection reuse by themselves.
/// See [RFC 8336, Section 2](https://www.rfc-editor.org/rfc/rfc8336#section-2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OriginFrameRepr")]
pub struct OriginFrame {
    /// Frame category, always [`FrameType::Origin`].
    pub frame_type: FrameType,

    /// Connection identifier; nonzero values must be ignored by endpoints.
    pub stream_id: u32,

    /// Payload length, including each decoded entry's two-byte length prefix.
    pub length: usize,

    /// Original flags. The lower four bits signal unsupported, incompatible semantics.
    pub flags: u8,

    /// Entries in wire order, including duplicates and invalid origin strings.
    pub origins: Vec<OriginEntry>,

    /// Uninterpreted payload when incompatible flags prevent decoding the entry layout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque_payload: Option<Box<[u8]>>,
}

/// Saved ORIGIN fields validated against the wire layout and flag semantics.
#[derive(Deserialize)]
struct OriginFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved connection identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Original flags.
    flags: u8,

    /// Saved origin entries.
    origins: Vec<OriginEntry>,

    /// Payload preserved without decoding incompatible flags.
    #[serde(default)]
    opaque_payload: Option<Box<[u8]>>,
}

impl OriginFrame {
    /// Returns whether the stream and flags permit RFC 8336 processing.
    /// TLS, proxy configuration, origin syntax, and server authority must be checked separately.
    pub const fn has_supported_context(&self) -> bool {
        self.stream_id == 0 && self.flags & 0x0f == 0
    }
}

impl TryFrom<OriginFrameRepr> for OriginFrame {
    type Error = &'static str;

    fn try_from(repr: OriginFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Origin
            || repr.stream_id > 0x7fff_ffff
            || repr.length > 0x00ff_ffff
        {
            return Err("ORIGIN frame metadata is invalid");
        }
        let length = if repr.flags & 0x0f != 0 {
            if !repr.origins.is_empty() {
                return Err("ORIGIN with incompatible flags cannot contain decoded entries");
            }
            repr.opaque_payload.as_ref().map(|payload| payload.len())
        } else {
            if repr.opaque_payload.is_some() {
                return Err("ORIGIN without incompatible flags must use decoded entries");
            }
            repr.origins.iter().try_fold(0usize, |length, origin| {
                if origin.value.len() > usize::from(u16::MAX) {
                    return None;
                }
                length.checked_add(2)?.checked_add(origin.value.len())
            })
        };
        if length != Some(repr.length) {
            return Err("ORIGIN length does not match its entries or opaque payload");
        }
        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            origins: repr.origins,
            opaque_payload: repr.opaque_payload,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for OriginFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id > 0x7fff_ffff {
            return Err(FrameError::InvalidStreamId);
        }
        if payload.len() > 0x00ff_ffff {
            return Err(FrameError::BadFrameSize);
        }
        let mut frame = Self {
            frame_type: FrameType::Origin,
            stream_id,
            length: payload.len(),
            flags,
            origins: Vec::new(),
            opaque_payload: None,
        };
        // RFC 8336 Section 2.2 reserves these flags for incompatible changes to the layout.
        if flags & 0x0f != 0 {
            frame.opaque_payload = Some(payload.into());
            return Ok(frame);
        }
        let mut remaining = payload;
        while !remaining.is_empty() {
            let prefix = remaining.get(..2).ok_or(FrameError::BadFrameSize)?;
            let end = 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
            let value = remaining.get(2..end).ok_or(FrameError::BadFrameSize)?;
            frame.origins.push(OriginEntry {
                value: value.into(),
            });
            remaining = &remaining[end..];
        }
        Ok(frame)
    }
}
