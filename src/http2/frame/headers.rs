use httlib_hpack::Decoder;
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

use super::{error::Error, priority::StreamDependency, FrameType};

/// A decoded HTTP header field, preserving the wire order.
#[derive(Debug, Serialize)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

/// Header frame
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

/// HTTP/2 HEADERS frame flags decoded from the wire bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadersFlags {
    raw: u8,
}

/// A single known HTTP/2 HEADERS frame flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersFlag {
    pub id: u8,
    pub name: HeadersFlagName,
}

/// A human-readable name for a known HTTP/2 HEADERS frame flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum HeadersFlagName {
    EndStream,
    EndHeaders,
    Padded,
    Priority,
    Unknown,
}

// ==== impl HeadersFlags ====

impl HeadersFlags {
    // RFC 9113 Section 6.2 defines the known HEADERS frame flags.
    // See: <https://www.rfc-editor.org/rfc/rfc9113#section-6.2>
    const END_STREAM: HeadersFlag = HeadersFlag {
        id: 0x1,
        name: HeadersFlagName::EndStream,
    };
    const END_HEADERS: HeadersFlag = HeadersFlag {
        id: 0x4,
        name: HeadersFlagName::EndHeaders,
    };
    const PADDED: HeadersFlag = HeadersFlag {
        id: 0x8,
        name: HeadersFlagName::Padded,
    };
    const PRIORITY: HeadersFlag = HeadersFlag {
        id: 0x20,
        name: HeadersFlagName::Priority,
    };
    const KNOWN: [HeadersFlag; 4] = [
        Self::END_STREAM,
        Self::END_HEADERS,
        Self::PADDED,
        Self::PRIORITY,
    ];

    #[inline]
    pub fn raw(self) -> u8 {
        self.raw
    }

    #[inline]
    fn contains(self, flag: HeadersFlag) -> bool {
        self.raw & flag.id != 0
    }

    #[inline]
    fn has_padding(self) -> bool {
        self.contains(Self::PADDED)
    }

    #[inline]
    fn has_priority(self) -> bool {
        self.contains(Self::PRIORITY)
    }

    #[inline]
    fn flag_by_id(id: u8) -> HeadersFlag {
        Self::KNOWN
            .iter()
            .copied()
            .find(|flag| flag.id == id)
            .unwrap_or(HeadersFlag {
                id,
                name: HeadersFlagName::Unknown,
            })
    }
}

impl From<u8> for HeadersFlags {
    fn from(raw: u8) -> Self {
        Self { raw }
    }
}

impl Serialize for HeadersFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = self.raw().count_ones() as usize;
        let mut seq = serializer.serialize_seq(Some(len))?;

        for bit in 0..u8::BITS {
            let id = 1u8 << bit;
            if self.raw() & id != 0 {
                seq.serialize_element(&Self::flag_by_id(id))?;
            }
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for HeadersFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let flags = Vec::<HeadersFlag>::deserialize(deserializer)?;
        let mut raw = 0u8;

        for flag in flags {
            if !flag.id.is_power_of_two() {
                return Err(serde::de::Error::custom(format!(
                    "invalid HTTP/2 flag id {}",
                    flag.id
                )));
            }
            raw |= flag.id;
        }

        Ok(Self { raw })
    }
}

// ==== impl HeadersFrame ====

impl TryFrom<(u8, u32, &[u8])> for HeadersFrame {
    type Error = Error;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        let flags = HeadersFlags::from(flags);
        let mut fragment_offset = 0;
        let padded = flags.has_padding();

        if flags.has_priority() {
            fragment_offset += 5;
        }

        if padded {
            fragment_offset += 1;
        }

        if payload.len() < fragment_offset {
            return Err(Error::TooMuchPadding);
        }

        let padding_len = if padded { payload[0] as usize } else { 0 };
        let data = &payload[fragment_offset..];

        if data.len() < padding_len {
            return Err(Error::TooMuchPadding);
        }

        let mut decoder = Decoder::default();
        let mut buf = data[..data.len() - padding_len].to_vec();
        let mut dst = Vec::new();

        if decoder.decode(&mut buf, &mut dst).is_err() {
            return Err(Error::MalformedMessage);
        }

        let mut headers = Vec::with_capacity(dst.len());
        let mut pseudo_headers = Vec::with_capacity(4);
        for (name, value, _) in dst {
            if name.starts_with(b":") {
                if let Some(first_char) = name.get(1).copied() {
                    pseudo_headers.push(first_char as char);
                } else {
                    tracing::warn!("Invalid pseudo-header: {:?}", name);
                    return Err(Error::MalformedMessage);
                }
            }

            headers.push(HeaderField {
                name: String::from_utf8_lossy(&name).into_owned(),
                value: String::from_utf8_lossy(&value).into_owned(),
            });
        }

        let priority = if flags.has_priority() {
            let buf = &payload[fragment_offset - 5..fragment_offset];
            let priority = StreamDependency::try_from(buf)?;
            Some(priority)
        } else {
            None
        };

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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{HeaderField, HeadersFlag, HeadersFlagName, HeadersFlags};

    #[test]
    fn header_field_serializes_name_and_value_separately() {
        let header = HeaderField {
            name: ":method".to_owned(),
            value: "GET".to_owned(),
        };

        assert_eq!(
            serde_json::to_value(header).unwrap(),
            json!({"name": ":method", "value": "GET"})
        );
    }

    #[test]
    fn headers_flags_serialize_known_and_unknown_bits() {
        let flags = HeadersFlags::from(0x2f);
        let value = serde_json::to_value(flags).unwrap();

        assert_eq!(
            value,
            json!([
                {"id": 1, "name": "EndStream"},
                {"id": 2, "name": "Unknown"},
                {"id": 4, "name": "EndHeaders"},
                {"id": 8, "name": "Padded"},
                {"id": 32, "name": "Priority"}
            ])
        );
    }

    #[test]
    fn headers_flags_roundtrip_from_serialized_flags() {
        let flags: HeadersFlags = serde_json::from_value(json!([
            {"id": 8, "name": "Padded"},
            {"id": 32, "name": "Priority"}
        ]))
        .unwrap();

        assert!(flags.has_padding());
        assert!(flags.has_priority());
        assert!(flags.contains(HeadersFlag {
            id: 0x20,
            name: HeadersFlagName::Priority,
        }));
        assert_eq!(flags.raw(), 0x28);
    }
}
