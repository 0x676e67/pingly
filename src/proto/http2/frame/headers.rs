use httlib_hpack::Decoder;
use serde::{Deserialize, Serialize};

use super::{priority::StreamDependency, FrameError, FrameType};

/// A decoded HTTP/2 field, preserving its position in the field section.
///
/// HTTP/2 field handling is defined by
/// [RFC 9113, Section 8.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    /// The decoded field name bytes, including the leading `:` for pseudo-fields.
    ///
    /// HPACK treats field names and values as opaque octet sequences. Valid UTF-8 is serialized
    /// as a JSON string; other byte sequences use an object containing lowercase hexadecimal.
    #[serde(with = "header_bytes")]
    pub name: Box<[u8]>,

    /// The decoded field value bytes.
    #[serde(with = "header_bytes")]
    pub value: Box<[u8]>,
}

/// A decoded HTTP/2 HEADERS frame.
///
/// See [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "HeadersFrameRepr")]
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

/// Deserialization shape used to validate a saved HEADERS frame and its continuations.
#[derive(Deserialize)]
struct HeadersFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Stream that owns the field section.
    stream_id: u32,

    /// Opening HEADERS payload length.
    length: usize,

    /// Decoded fields in wire order.
    headers: Vec<HeaderField>,

    /// Opening HEADERS flags.
    flags: HeadersFlags,

    /// Optional decoded priority fields.
    #[serde(default)]
    priority: Option<StreamDependency>,

    /// CONTINUATION metadata in wire order.
    #[serde(default)]
    continuations: Vec<ContinuationFrame>,
}

/// A CONTINUATION frame associated with a decoded HEADERS field block.
///
/// See [RFC 9113, Section 6.10](https://www.rfc-editor.org/rfc/rfc9113#section-6.10).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ContinuationFrameRepr")]
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

/// Deserialization shape used to validate saved CONTINUATION metadata.
#[derive(Deserialize)]
struct ContinuationFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Stream that owns the field section.
    stream_id: u32,

    /// CONTINUATION payload length.
    length: usize,

    /// CONTINUATION flags.
    flags: ContinuationFlags,
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

    /// The opening HEADERS payload length, excluding the 9-byte frame header.
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

impl TryFrom<ContinuationFrameRepr> for ContinuationFrame {
    type Error = &'static str;

    fn try_from(repr: ContinuationFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Continuation {
            return Err("CONTINUATION frame_type must be Continuation");
        }
        if repr.stream_id == 0 || repr.stream_id > 0x7fff_ffff {
            return Err("CONTINUATION stream_id must be a nonzero 31-bit value");
        }
        if repr.length > 0x00ff_ffff {
            return Err("CONTINUATION payload length exceeds the HTTP/2 frame limit");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
        })
    }
}

impl TryFrom<HeadersFrameRepr> for HeadersFrame {
    type Error = &'static str;

    fn try_from(repr: HeadersFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Headers {
            return Err("HEADERS frame_type must be Headers");
        }
        if repr.stream_id == 0 || repr.stream_id > 0x7fff_ffff {
            return Err("HEADERS stream_id must be a nonzero 31-bit value");
        }
        if repr.length > 0x00ff_ffff {
            return Err("HEADERS payload length exceeds the HTTP/2 frame limit");
        }

        let prefix_length =
            usize::from(repr.flags.has_padding()) + if repr.flags.has_priority() { 5 } else { 0 };
        if repr.length < prefix_length {
            return Err("HEADERS payload is too short for its flagged prefix fields");
        }
        if repr.flags.has_priority() != repr.priority.is_some() {
            return Err("HEADERS PRIORITY flag does not match its priority fields");
        }
        if repr
            .priority
            .as_ref()
            .is_some_and(|priority| priority.depends_on == repr.stream_id)
        {
            return Err("a HEADERS stream cannot depend on itself");
        }
        if repr
            .headers
            .iter()
            .any(|header| header.name.as_ref() == b":")
        {
            return Err("a pseudo-header name cannot contain only a colon");
        }

        if repr.flags.has_end_headers() {
            if !repr.continuations.is_empty() {
                return Err("END_HEADERS opening frames cannot have CONTINUATION metadata");
            }
        } else {
            if repr.continuations.is_empty() {
                return Err("an incomplete HEADERS frame requires CONTINUATION metadata");
            }
            let continuation_count = repr.continuations.len();
            for (index, continuation) in repr.continuations.iter().enumerate() {
                if continuation.stream_id != repr.stream_id {
                    return Err("CONTINUATION stream_id does not match the opening HEADERS frame");
                }
                let is_last = index + 1 == continuation_count;
                if continuation.flags.has_end_headers() != is_last {
                    return Err("only the final CONTINUATION frame may set END_HEADERS");
                }
            }
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            headers: repr.headers,
            flags: repr.flags,
            priority: repr.priority,
            continuations: repr.continuations,
        })
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

    pub(super) fn finish(mut self, decoder: &mut Decoder<'_>) -> Result<HeadersFrame, FrameError> {
        let mut decoded = Vec::new();

        if decoder.decode(&mut self.block, &mut decoded).is_err() {
            return Err(FrameError::CompressionError);
        }

        let mut headers = Vec::with_capacity(decoded.len());
        for (name, value, _) in decoded {
            if name == b":" {
                tracing::warn!("Invalid pseudo-header: {:?}", name);
                return Err(FrameError::MalformedMessage);
            }

            headers.push(HeaderField {
                name: name.into_boxed_slice(),
                value: value.into_boxed_slice(),
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

        let mut decoder = Decoder::default();
        pending.finish(&mut decoder)
    }
}

mod header_bytes {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Text(Box<str>),
        Bytes { hex: Box<str> },
    }

    pub(super) fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match std::str::from_utf8(value) {
            Ok(value) => value.serialize(serializer),
            Err(_) => HexBytes {
                hex: hex::encode(value).into_boxed_str(),
            }
            .serialize(serializer),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Box<[u8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Repr::deserialize(deserializer)? {
            Repr::Text(value) => Ok(value.as_bytes().into()),
            Repr::Bytes { hex } => hex::decode(hex.as_ref())
                .map(Vec::into_boxed_slice)
                .map_err(de::Error::custom),
        }
    }

    #[derive(Serialize)]
    struct HexBytes {
        hex: Box<str>,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{HeaderField, HeadersFlag, HeadersFlagName, HeadersFlags, HeadersFrame};
    use crate::proto::http2::frame::{FrameError, FrameType, StreamDependency};

    #[test]
    fn header_field_serializes_name_and_value_separately() {
        let header = HeaderField {
            name: Box::from(&b":method"[..]),
            value: Box::from(&b"GET"[..]),
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
    fn non_utf8_header_bytes_roundtrip_without_loss() {
        let header = HeaderField {
            name: Box::from(&b"x-bytes"[..]),
            value: Box::from(&[0xff, 0x00][..]),
        };

        let json = serde_json::to_value(&header).unwrap();
        assert_eq!(json, json!({"name": "x-bytes", "value": {"hex": "ff00"}}));

        let restored: HeaderField = serde_json::from_value(json).unwrap();
        assert_eq!(restored, header);
    }

    #[test]
    fn headers_frame_serializes_raw_and_decoded_flags() {
        let frame = HeadersFrame {
            frame_type: FrameType::Headers,
            stream_id: 1,
            length: 5,
            headers: Vec::new(),
            flags: HeadersFlags::from(0x25),
            priority: Some(StreamDependency {
                weight: 1,
                depends_on: 0,
                exclusive: 0,
            }),
            continuations: Vec::new(),
        };

        let json = serde_json::to_value(frame).unwrap();
        assert_eq!(
            json,
            json!({
                "frame_type": "Headers",
                "stream_id": 1,
                "length": 5,
                "headers": [],
                "flags": {
                    "raw": 37,
                    "values": [
                        {"id": 1, "name": "EndStream"},
                        {"id": 4, "name": "EndHeaders"},
                        {"id": 32, "name": "Priority"}
                    ]
                },
                "priority": {
                    "weight": 1,
                    "depends_on": 0,
                    "exclusive": 0
                }
            })
        );
        assert!(serde_json::from_value::<HeadersFrame>(json).is_ok());
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

    #[test]
    fn headers_deserialization_rejects_inconsistent_metadata() {
        let missing_priority = json!({
            "frame_type": "Headers",
            "stream_id": 1,
            "length": 5,
            "headers": [],
            "flags": {
                "raw": 36,
                "values": [
                    {"id": 4, "name": "EndHeaders"},
                    {"id": 32, "name": "Priority"}
                ]
            }
        });
        let missing_continuation = json!({
            "frame_type": "Headers",
            "stream_id": 1,
            "length": 1,
            "headers": [],
            "flags": {"raw": 0, "values": []}
        });

        assert!(serde_json::from_value::<HeadersFrame>(missing_priority).is_err());
        assert!(serde_json::from_value::<HeadersFrame>(missing_continuation).is_err());
    }
}
