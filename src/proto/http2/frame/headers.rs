use httlib_hpack::Decoder;
use serde::{Deserialize, Serialize};

use super::{priority::StreamDependency, FrameError, FrameType};

/// A decoded HTTP/2 field, preserving its position in the field section.
///
/// HTTP/2 field handling is defined by
/// [RFC 9113, Section 8.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    /// The decoded field name, including the leading `:` for pseudo-fields.
    pub name: Box<str>,

    /// The decoded field value.
    pub value: Box<str>,
}

/// A decoded HTTP/2 HEADERS frame.
///
/// See [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersFrame {
    /// The type of the frame
    pub frame_type: FrameType,

    /// The ID of the stream with which this frame is associated.
    pub stream_id: u32,

    /// The length of the frame payload
    pub length: usize,

    /// The headers in the frame
    pub headers: Vec<HeaderField>,

    /// The associated flags
    pub flags: HeadersFlags,

    /// The stream dependency information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<StreamDependency>,

    /// CONTINUATION frames that completed this field block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub continuations: Vec<ContinuationFrame>,
}

/// A CONTINUATION frame associated with a decoded HEADERS field block.
///
/// See [RFC 9113, Section 6.10](https://www.rfc-editor.org/rfc/rfc9113#section-6.10).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuationFrame {
    /// The frame type, always [`FrameType::Continuation`].
    pub frame_type: FrameType,

    /// The stream identifier shared with the opening HEADERS frame.
    pub stream_id: u32,

    /// The payload length, excluding the 9-byte frame header.
    pub length: usize,

    /// The associated CONTINUATION flags.
    pub flags: ContinuationFlags,
}

/// An HTTP/2 CONTINUATION flag byte and the set bits decoded from it.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ContinuationFlagsRepr")]
pub struct ContinuationFlags {
    /// The original flag byte from the frame header.
    raw: u8,

    /// The individual set bits decoded from the flag byte.
    values: Vec<ContinuationFlag>,
}

/// Deserialization shape used to validate a saved CONTINUATION flag byte and its decoded bits.
#[derive(Deserialize)]
struct ContinuationFlagsRepr {
    /// The original flag byte stored in JSON.
    raw: u8,

    /// The decoded set bits stored alongside the raw byte.
    values: Vec<ContinuationFlag>,
}

/// One set bit from an HTTP/2 CONTINUATION frame flag byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuationFlag {
    /// The set bit as a numeric mask.
    pub id: u8,

    /// The RFC-defined meaning of the bit for a CONTINUATION frame.
    pub name: ContinuationFlagName,
}

/// The meaning of a flag bit in an HTTP/2 CONTINUATION frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[repr(u8)]
pub enum ContinuationFlagName {
    /// A set bit with no defined CONTINUATION-frame meaning.
    Unknown = 0,

    /// `END_HEADERS` (`0x04`) completes the field block.
    EndHeaders = 0x04,
}

/// A HEADERS field block that may still require CONTINUATION frames.
#[derive(Debug)]
pub(super) struct PendingHeaders {
    /// The stream that owns the incomplete field block.
    stream_id: u32,

    /// The accumulated payload length across HEADERS and CONTINUATION frames.
    length: usize,

    /// The flags from the opening HEADERS frame.
    flags: HeadersFlags,

    /// The optional priority fields from the opening HEADERS frame.
    priority: Option<StreamDependency>,

    /// The compressed field block accumulated so far.
    block: Vec<u8>,

    /// Metadata for the CONTINUATION frames received so far.
    continuations: Vec<ContinuationFrame>,
}

/// An HTTP/2 HEADERS flag byte and the set bits decoded from it.
///
/// HEADERS defines four known flags; unused set bits remain visible as
/// [`HeadersFlagName::Unknown`]. See
/// [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "HeadersFlagsRepr")]
pub struct HeadersFlags {
    /// The original flag byte from the frame header.
    raw: u8,

    /// The individual set bits decoded from the flag byte.
    values: Vec<HeadersFlag>,
}

/// Deserialization shape used to validate a saved HEADERS flag byte and its decoded bits.
#[derive(Deserialize)]
struct HeadersFlagsRepr {
    /// The original flag byte stored in JSON.
    raw: u8,

    /// The decoded set bits stored alongside the raw byte.
    values: Vec<HeadersFlag>,
}

/// One set bit from an HTTP/2 HEADERS frame flag byte.
///
/// The ID retains the original bit value, including bits unused by
/// [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersFlag {
    /// The set bit as a numeric mask, such as `0x04` for `END_HEADERS`.
    pub id: u8,

    /// The RFC-defined meaning of the bit for a HEADERS frame.
    pub name: HeadersFlagName,
}

/// The meaning of a flag bit in an HTTP/2 HEADERS frame.
///
/// These meanings are specific to HEADERS frames. See
/// [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[repr(u8)]
pub enum HeadersFlagName {
    /// A set bit with no defined HEADERS-frame meaning.
    Unknown = 0,

    /// `END_STREAM` (`0x01`) marks the last field section sent on the stream.
    EndStream = 0x01,

    /// `END_HEADERS` (`0x04`) marks the end of the compressed field block.
    EndHeaders = 0x04,

    /// `PADDED` (`0x08`) indicates that padding fields are present.
    Padded = 0x08,

    /// `PRIORITY` (`0x20`) indicates that legacy priority fields are present.
    Priority = 0x20,
}

// ==== impl HeadersFlags ====

impl HeadersFlags {
    /// Returns the original HEADERS flag byte.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.raw
    }

    /// Returns each set flag bit in ascending bit order.
    #[inline]
    pub fn values(&self) -> &[HeadersFlag] {
        &self.values
    }

    /// Returns whether the requested HEADERS flag is set.
    ///
    /// [`HeadersFlagName::Unknown`] has no single wire bit and always returns
    /// `false`; inspect [`Self::values`] to find unknown set bits.
    #[inline]
    pub const fn contains(&self, flag: HeadersFlagName) -> bool {
        self.raw & flag.id() != 0
    }

    #[inline]
    fn has_padding(&self) -> bool {
        self.contains(HeadersFlagName::Padded)
    }

    #[inline]
    fn has_priority(&self) -> bool {
        self.contains(HeadersFlagName::Priority)
    }

    #[inline]
    pub(super) fn has_end_headers(&self) -> bool {
        self.contains(HeadersFlagName::EndHeaders)
    }
}

impl From<u8> for HeadersFlags {
    fn from(raw: u8) -> Self {
        let mut values = Vec::with_capacity(raw.count_ones() as usize);

        for bit in 0..u8::BITS {
            let id = 1u8 << bit;
            if raw & id != 0 {
                values.push(HeadersFlag::from(id));
            }
        }

        Self { raw, values }
    }
}

impl TryFrom<HeadersFlagsRepr> for HeadersFlags {
    type Error = &'static str;

    fn try_from(repr: HeadersFlagsRepr) -> Result<Self, Self::Error> {
        let expected = Self::from(repr.raw);
        if repr.values != expected.values {
            return Err("HEADERS flag values do not match the raw flag byte");
        }

        Ok(expected)
    }
}

impl From<u8> for HeadersFlag {
    fn from(id: u8) -> Self {
        Self {
            id,
            name: HeadersFlagName::from(id),
        }
    }
}

impl HeadersFlagName {
    #[inline]
    const fn id(self) -> u8 {
        self as u8
    }
}

impl From<u8> for HeadersFlagName {
    fn from(id: u8) -> Self {
        // RFC 9113 Section 6.2 defines four flags for HEADERS frames. Every
        // other bit is unused for this frame type and remains visible as Unknown.
        // See: <https://www.rfc-editor.org/rfc/rfc9113#section-6.2>
        match id {
            0x01 => Self::EndStream,
            0x04 => Self::EndHeaders,
            0x08 => Self::Padded,
            0x20 => Self::Priority,
            _ => Self::Unknown,
        }
    }
}

// ==== impl ContinuationFlags ====

impl ContinuationFlags {
    /// Returns the original CONTINUATION flag byte.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.raw
    }

    /// Returns each set flag bit in ascending bit order.
    #[inline]
    pub fn values(&self) -> &[ContinuationFlag] {
        &self.values
    }

    #[inline]
    fn has_end_headers(&self) -> bool {
        self.raw & ContinuationFlagName::EndHeaders as u8 != 0
    }
}

impl From<u8> for ContinuationFlags {
    fn from(raw: u8) -> Self {
        let mut values = Vec::with_capacity(raw.count_ones() as usize);

        for bit in 0..u8::BITS {
            let id = 1u8 << bit;
            if raw & id != 0 {
                values.push(ContinuationFlag::from(id));
            }
        }

        Self { raw, values }
    }
}

impl TryFrom<ContinuationFlagsRepr> for ContinuationFlags {
    type Error = &'static str;

    fn try_from(repr: ContinuationFlagsRepr) -> Result<Self, Self::Error> {
        let expected = Self::from(repr.raw);
        if repr.values != expected.values {
            return Err("CONTINUATION flag values do not match the raw flag byte");
        }

        Ok(expected)
    }
}

impl From<u8> for ContinuationFlag {
    fn from(id: u8) -> Self {
        let name = match id {
            0x04 => ContinuationFlagName::EndHeaders,
            _ => ContinuationFlagName::Unknown,
        };

        Self { id, name }
    }
}

// ==== impl PendingHeaders ====

impl PendingHeaders {
    pub(super) fn is_complete(&self) -> bool {
        self.flags.has_end_headers()
    }

    pub(super) fn push_continuation(
        &mut self,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<bool, FrameError> {
        if stream_id != self.stream_id {
            return Err(FrameError::UnexpectedContinuation);
        }

        let flags = ContinuationFlags::from(flags);
        let complete = flags.has_end_headers();
        self.block.extend_from_slice(payload);
        self.continuations.push(ContinuationFrame {
            frame_type: FrameType::Continuation,
            stream_id,
            length: payload.len(),
            flags,
        });

        Ok(complete)
    }

    pub(super) fn finish(mut self) -> Result<HeadersFrame, FrameError> {
        let mut decoder = Decoder::default();
        let mut decoded = Vec::new();

        if decoder.decode(&mut self.block, &mut decoded).is_err() {
            return Err(FrameError::MalformedMessage);
        }

        let mut headers = Vec::with_capacity(decoded.len());
        for (name, value, _) in decoded {
            if name == b":" {
                tracing::warn!("Invalid pseudo-header: {:?}", name);
                return Err(FrameError::MalformedMessage);
            }

            headers.push(HeaderField {
                name: into_boxed_utf8_lossy(name),
                value: into_boxed_utf8_lossy(value),
            });
        }

        Ok(HeadersFrame {
            frame_type: FrameType::Headers,
            stream_id: self.stream_id,
            length: self.length,
            headers,
            flags: self.flags,
            priority: self.priority,
            continuations: self.continuations,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for PendingHeaders {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id == 0 {
            return Err(FrameError::InvalidStreamId);
        }

        let flags = HeadersFlags::from(flags);
        let padded = flags.has_padding();
        let priority_offset = usize::from(padded);
        let fragment_offset = priority_offset + if flags.has_priority() { 5 } else { 0 };

        if payload.len() < fragment_offset {
            return Err(FrameError::BadFrameSize);
        }

        let padding_len = if padded { payload[0] as usize } else { 0 };
        let data = &payload[fragment_offset..];

        if data.len() < padding_len {
            return Err(FrameError::TooMuchPadding);
        }

        let priority = if flags.has_priority() {
            let priority_end = priority_offset + 5;
            Some(StreamDependency::try_from(
                &payload[priority_offset..priority_end],
            )?)
        } else {
            None
        };

        if priority
            .as_ref()
            .is_some_and(|priority| priority.depends_on == stream_id)
        {
            return Err(FrameError::InvalidStreamDependency);
        }

        Ok(Self {
            stream_id,
            length: payload.len(),
            flags,
            priority,
            block: data[..data.len() - padding_len].to_vec(),
            continuations: Vec::new(),
        })
    }
}

// ==== impl HeadersFrame ====

impl TryFrom<(u8, u32, &[u8])> for HeadersFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        let pending = PendingHeaders::try_from((flags, stream_id, payload))?;
        if !pending.is_complete() {
            return Err(FrameError::ExpectedContinuation);
        }

        pending.finish()
    }
}

fn into_boxed_utf8_lossy(value: Vec<u8>) -> Box<str> {
    match String::from_utf8(value) {
        Ok(value) => value.into_boxed_str(),
        Err(error) => String::from_utf8_lossy(&error.into_bytes())
            .into_owned()
            .into_boxed_str(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        into_boxed_utf8_lossy, HeaderField, HeadersFlag, HeadersFlagName, HeadersFlags,
        HeadersFrame,
    };
    use crate::proto::http2::frame::{FrameError, FrameType};

    #[test]
    fn header_field_serializes_name_and_value_separately() {
        let header = HeaderField {
            name: Box::from(":method"),
            value: Box::from("GET"),
        };

        assert_eq!(
            serde_json::to_value(header).unwrap(),
            json!({"name": ":method", "value": "GET"})
        );
    }

    #[test]
    fn headers_flags_serialize_known_and_unknown_bits() {
        let flags = HeadersFlags::from(0x2f);
        let value = serde_json::to_value(&flags).unwrap();

        assert_eq!(
            value,
            json!({
                "raw": 47,
                "values": [
                    {"id": 1, "name": "EndStream"},
                    {"id": 2, "name": "Unknown"},
                    {"id": 4, "name": "EndHeaders"},
                    {"id": 8, "name": "Padded"},
                    {"id": 32, "name": "Priority"}
                ]
            })
        );
    }

    #[test]
    fn header_text_is_boxed_with_lossy_utf8_fallback() {
        assert_eq!(
            &*into_boxed_utf8_lossy(b"content-type".to_vec()),
            "content-type"
        );
        assert_eq!(&*into_boxed_utf8_lossy(vec![0xff]), "\u{fffd}");
    }

    #[test]
    fn headers_frame_serializes_raw_and_decoded_flags() {
        let frame = HeadersFrame {
            frame_type: FrameType::Headers,
            stream_id: 1,
            length: 0,
            headers: Vec::new(),
            flags: HeadersFlags::from(0x25),
            priority: None,
            continuations: Vec::new(),
        };

        assert_eq!(
            serde_json::to_value(frame).unwrap(),
            json!({
                "frame_type": "Headers",
                "stream_id": 1,
                "length": 0,
                "headers": [],
                "flags": {
                    "raw": 37,
                    "values": [
                        {"id": 1, "name": "EndStream"},
                        {"id": 4, "name": "EndHeaders"},
                        {"id": 32, "name": "Priority"}
                    ]
                }
            })
        );
    }

    #[test]
    fn headers_flags_roundtrip_with_derived_serde() {
        let flags = HeadersFlags::from(0x28);
        let serialized = serde_json::to_value(&flags).unwrap();
        let deserialized: HeadersFlags = serde_json::from_value(serialized).unwrap();

        assert_eq!(deserialized, flags);
        assert!(deserialized.has_padding());
        assert!(deserialized.has_priority());
        assert!(deserialized.values.contains(&HeadersFlag {
            id: 0x20,
            name: HeadersFlagName::Priority,
        }));
        assert_eq!(deserialized.raw, 0x28);
    }

    #[test]
    fn headers_flags_reject_inconsistent_deserialized_values() {
        let missing = serde_json::from_value::<HeadersFlags>(json!({
            "raw": 4,
            "values": []
        }));
        let wrong_name = serde_json::from_value::<HeadersFlags>(json!({
            "raw": 1,
            "values": [{"id": 1, "name": "Priority"}]
        }));

        assert!(missing.is_err());
        assert!(wrong_name.is_err());
    }

    #[test]
    fn headers_require_a_nonzero_distinct_stream_dependency() {
        assert_eq!(
            super::PendingHeaders::try_from((0x04, 0, &[0x82][..])).unwrap_err(),
            FrameError::InvalidStreamId
        );
        assert_eq!(
            super::PendingHeaders::try_from((0x24, 1, &[0, 0, 0, 1, 0][..])).unwrap_err(),
            FrameError::InvalidStreamDependency
        );
    }

    #[test]
    fn headers_require_complete_optional_prefix_fields() {
        assert_eq!(
            super::PendingHeaders::try_from((0x24, 1, &[0; 4][..])).unwrap_err(),
            FrameError::BadFrameSize
        );
    }
}
