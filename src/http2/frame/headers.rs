use httlib_hpack::Decoder;
use serde::{Deserialize, Serialize};

use super::{error::Error, priority::StreamDependency, FrameType};

/// A decoded HTTP/2 field, preserving its position in the field section.
///
/// HTTP/2 field handling is defined by
/// [RFC 9113, Section 8.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2).
#[derive(Debug, Serialize)]
pub struct HeaderField {
    /// The decoded field name, including the leading `:` for pseudo-fields.
    pub name: Box<str>,

    /// The decoded field value.
    pub value: Box<str>,
}

/// A decoded HTTP/2 HEADERS frame.
///
/// See [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, Serialize)]
pub struct HeadersFrame {
    /// The type of the frame
    pub frame_type: FrameType,

    /// The ID of the stream with which this frame is associated.
    pub stream_id: u32,

    /// The length of the frame payload
    pub length: usize,

    /// The short pseudo-header names
    #[serde(skip)]
    pub pseudo_headers: Vec<char>,

    /// The headers in the frame
    pub headers: Vec<HeaderField>,

    /// The associated flags
    pub flags: HeadersFlags,

    /// The stream dependency information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<StreamDependency>,
}

/// An HTTP/2 HEADERS flag byte and the set bits decoded from it.
///
/// HEADERS defines four known flags; unused set bits remain visible as
/// [`HeadersFlagName::Unknown`]. See
/// [RFC 9113, Section 6.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersFlags {
    raw: u8,
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
    #[inline]
    fn contains(&self, flag: HeadersFlagName) -> bool {
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

// ==== impl HeadersFrame ====

impl TryFrom<(u8, u32, &[u8])> for HeadersFrame {
    type Error = Error;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        let flags = HeadersFlags::from(flags);
        let padded = flags.has_padding();
        let priority_offset = usize::from(padded);
        let fragment_offset = priority_offset + if flags.has_priority() { 5 } else { 0 };

        if payload.len() < fragment_offset {
            return Err(Error::TooMuchPadding);
        }

        let padding_len = if padded { payload[0] as usize } else { 0 };
        let data = &payload[fragment_offset..];

        if data.len() < padding_len {
            return Err(Error::TooMuchPadding);
        }

        let priority = if flags.has_priority() {
            let priority_end = priority_offset + 5;
            Some(StreamDependency::try_from(
                &payload[priority_offset..priority_end],
            )?)
        } else {
            None
        };

        let mut decoder = Decoder::default();
        let mut block = data[..data.len() - padding_len].to_vec();
        let mut decoded = Vec::new();

        if decoder.decode(&mut block, &mut decoded).is_err() {
            return Err(Error::MalformedMessage);
        }

        let mut headers = Vec::with_capacity(decoded.len());
        let mut pseudo_headers = Vec::with_capacity(4);
        for (name, value, _) in decoded {
            if name.starts_with(b":") {
                if let Some(first_char) = name.get(1).copied() {
                    pseudo_headers.push(first_char as char);
                } else {
                    tracing::warn!("Invalid pseudo-header: {:?}", name);
                    return Err(Error::MalformedMessage);
                }
            }

            headers.push(HeaderField {
                name: into_boxed_utf8_lossy(name),
                value: into_boxed_utf8_lossy(value),
            });
        }

        Ok(HeadersFrame {
            frame_type: FrameType::Headers,
            stream_id,
            length: payload.len(),
            pseudo_headers,
            headers,
            flags,
            priority,
        })
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
    use crate::http2::frame::FrameType;

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
            pseudo_headers: Vec::new(),
            headers: Vec::new(),
            flags: HeadersFlags::from(0x25),
            priority: None,
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
}
