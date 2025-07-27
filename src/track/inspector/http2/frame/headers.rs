use super::error::Error;
use httlib_hpack::Decoder;
use serde::{Serialize, Serializer};
use std::fmt::Write;

use super::{priority::StreamDependency, FrameType};

/// Header frame
///
/// This could be either a request.
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
    pub headers: Vec<String>,

    /// The associated flags
    pub flags: HeadersFlag,

    /// The stream dependency information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<StreamDependency>,
}

/// Headers flags
#[derive(Debug)]
pub struct HeadersFlag(pub u8);

// ==== impl HeadersFlag ====

impl Serialize for HeadersFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        const END_STREAM: u8 = 0x1;
        const END_HEADERS: u8 = 0x4;
        const PADDED: u8 = 0x8;
        const PRIORITY: u8 = 0x20;

        let mut flags = Vec::new();

        if self.0 & END_STREAM != 0 {
            flags.push("EndStream (0x1)");
        }
        if self.0 & END_HEADERS != 0 {
            flags.push("EndHeaders (0x4)");
        }
        if self.0 & PADDED != 0 {
            flags.push("Padded (0x8)");
        }
        if self.0 & PRIORITY != 0 {
            flags.push("Priority (0x20)");
        }

        flags.serialize(serializer)
    }
}

// ==== impl HeadersFrame ====

impl TryFrom<(u8, u32, &[u8])> for HeadersFrame {
    type Error = Error;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        let mut fragment_offset = 0;
        let padded = flags & 0x8 != 0;

        if flags & 0x20 != 0 {
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

            let mut kv = String::with_capacity(name.len() + value.len() + 2);
            write!(
                &mut kv,
                "{}: {}",
                String::from_utf8_lossy(&name),
                String::from_utf8_lossy(&value)
            )
            .map_err(|_| Error::MalformedMessage)?;
            headers.push(kv);
        }

        let priority = if flags & 0x20 != 0 {
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
            flags: HeadersFlag(flags),
            priority,
        })
    }
}
