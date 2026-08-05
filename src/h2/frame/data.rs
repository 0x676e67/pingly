//! HTTP/2 DATA frame payloads and flags.

use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// A decoded HTTP/2 DATA frame.
///
/// Server-side capture may truncate `data` while retaining `data_length` and the original frame
/// length. DATA framing is defined by
/// [RFC 9113, Section 6.1](https://www.rfc-editor.org/rfc/rfc9113#section-6.1).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DataFrameRepr")]
pub struct DataFrame {
    /// The frame category, always [`FrameType::Data`].
    pub frame_type: FrameType,

    /// Stream carrying this message body fragment.
    pub stream_id: u32,

    /// Original payload length, including optional padding fields.
    pub length: usize,

    /// DATA-specific frame flags.
    pub flags: DataFlags,

    /// Original unpadded application-data length.
    pub data_length: usize,

    /// Captured application bytes, possibly shortened by [`Self::truncate`].
    pub data: Vec<u8>,

    /// Number of padding octets following the application data.
    pub padding_length: u8,

    /// Whether `data` contains only a prefix of the original application bytes.
    pub truncated: bool,
}

impl DataFrame {
    /// Retains at most `limit` application bytes while preserving wire lengths.
    pub fn truncate(&mut self, limit: usize) {
        if self.data.len() > limit {
            self.data.truncate(limit);
            self.data.shrink_to_fit();
            self.truncated = true;
        }
    }

    /// Returns whether this frame closes the sending side of its stream.
    #[inline]
    pub const fn is_end_stream(&self) -> bool {
        self.flags.contains(DataFlagName::EndStream)
    }
}

/// Deserialization shape validated before constructing [`DataFrame`].
#[derive(Deserialize)]
struct DataFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved stream identifier.
    stream_id: u32,

    /// Saved original payload length.
    length: usize,

    /// Saved DATA flags.
    flags: DataFlags,

    /// Saved original application-data length.
    data_length: usize,

    /// Saved full data or captured prefix.
    data: Vec<u8>,

    /// Saved padding length.
    padding_length: u8,

    /// Saved truncation state.
    truncated: bool,
}

impl TryFrom<DataFrameRepr> for DataFrame {
    type Error = &'static str;

    fn try_from(repr: DataFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Data {
            return Err("DATA frame_type must be Data");
        }
        if repr.stream_id == 0 || repr.stream_id > 0x7fff_ffff {
            return Err("DATA must use a nonzero 31-bit stream ID");
        }
        if !repr.flags.contains(DataFlagName::Padded) && repr.padding_length != 0 {
            return Err("unpadded DATA cannot retain a padding length");
        }
        if repr.data.len() > repr.data_length
            || repr.truncated != (repr.data.len() < repr.data_length)
        {
            return Err("DATA captured bytes do not match its truncation metadata");
        }

        let prefix_length = usize::from(repr.flags.contains(DataFlagName::Padded));
        let expected_length = prefix_length
            .checked_add(repr.data_length)
            .and_then(|length| length.checked_add(usize::from(repr.padding_length)))
            .ok_or("DATA payload length overflow")?;
        if repr.length != expected_length {
            return Err("DATA length does not match its payload metadata");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            data_length: repr.data_length,
            data: repr.data,
            padding_length: repr.padding_length,
            truncated: repr.truncated,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for DataFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id == 0 {
            return Err(FrameError::InvalidStreamId);
        }

        let flags = DataFlags::from(flags);
        let (data, padding_length) = if flags.contains(DataFlagName::Padded) {
            let (&padding_length, payload) =
                payload.split_first().ok_or(FrameError::BadFrameSize)?;
            let data_length = payload
                .len()
                .checked_sub(usize::from(padding_length))
                .ok_or(FrameError::TooMuchPadding)?;
            (&payload[..data_length], padding_length)
        } else {
            (payload, 0)
        };

        Ok(Self {
            frame_type: FrameType::Data,
            stream_id,
            length: payload.len(),
            flags,
            data_length: data.len(),
            data: data.to_vec(),
            padding_length,
            truncated: false,
        })
    }
}

/// DATA flags in raw and decoded form.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DataFlagsRepr")]
pub struct DataFlags {
    /// Original frame flag byte.
    raw: u8,

    /// Set bits in ascending wire-bit order.
    values: Vec<DataFlag>,
}

/// Deserialization shape used to validate [`DataFlags`].
#[derive(Deserialize)]
struct DataFlagsRepr {
    /// Saved raw flag byte.
    raw: u8,

    /// Saved decoded set bits.
    values: Vec<DataFlag>,
}

impl DataFlags {
    /// Returns the original frame flag byte.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.raw
    }

    /// Returns each set flag bit in ascending bit order.
    #[inline]
    pub fn values(&self) -> &[DataFlag] {
        &self.values
    }

    /// Returns whether a DATA flag is set.
    #[inline]
    pub const fn contains(&self, flag: DataFlagName) -> bool {
        self.raw & flag as u8 != 0
    }
}

impl From<u8> for DataFlags {
    fn from(raw: u8) -> Self {
        let values = (0..u8::BITS)
            .map(|bit| 1u8 << bit)
            .filter(|id| raw & id != 0)
            .map(DataFlag::from)
            .collect();
        Self { raw, values }
    }
}

impl TryFrom<DataFlagsRepr> for DataFlags {
    type Error = &'static str;

    fn try_from(repr: DataFlagsRepr) -> Result<Self, Self::Error> {
        let expected = Self::from(repr.raw);
        if repr.values != expected.values {
            return Err("DATA flag values do not match the raw flag byte");
        }
        Ok(expected)
    }
}

/// One set bit from an HTTP/2 DATA flag byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlag {
    /// Numeric bit mask observed on the wire.
    pub id: u8,

    /// RFC-defined meaning of the bit for DATA frames.
    pub name: DataFlagName,
}

impl From<u8> for DataFlag {
    fn from(id: u8) -> Self {
        Self {
            id,
            name: DataFlagName::from(id),
        }
    }
}

/// Meaning of one HTTP/2 DATA flag bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[repr(u8)]
pub enum DataFlagName {
    /// A set bit with no DATA-specific meaning.
    Unknown = 0,

    /// `END_STREAM` (`0x01`) closes this direction of the stream.
    EndStream = 0x01,

    /// `PADDED` (`0x08`) adds a pad-length field and trailing padding.
    Padded = 0x08,
}

impl From<u8> for DataFlagName {
    fn from(id: u8) -> Self {
        match id {
            0x01 => Self::EndStream,
            0x08 => Self::Padded,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DataFrame;

    #[test]
    fn data_frame_preserves_wire_metadata_after_capture_truncation() {
        let payload = [2, 0xaa, 0xbb, 0xcc, 0, 0];
        let mut frame = DataFrame::try_from((0x09, 3, &payload[..])).unwrap();

        assert!(frame.is_end_stream());
        assert_eq!(frame.data, [0xaa, 0xbb, 0xcc]);
        assert_eq!(frame.padding_length, 2);

        frame.truncate(2);
        assert_eq!(frame.data_length, 3);
        assert_eq!(frame.data, [0xaa, 0xbb]);
        assert!(frame.truncated);

        let json = serde_json::to_value(&frame).unwrap();
        let restored: DataFrame = serde_json::from_value(json).unwrap();
        assert_eq!(restored, frame);
        assert!(DataFrame::try_from((0, 0, &[][..])).is_err());
    }
}
