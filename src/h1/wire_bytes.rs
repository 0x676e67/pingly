//! Serde helpers for HTTP/1 field values and reason phrases.

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
