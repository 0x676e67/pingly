const MAX_VALUE: u64 = (1 << 62) - 1;

/// Decodes one QUIC variable-length integer and returns its value and encoded width.
///
/// The two most significant bits of the first byte select a width of 1, 2, 4, or 8 bytes.
/// See [RFC 9000, Section 16](https://www.rfc-editor.org/rfc/rfc9000#section-16).
pub(crate) fn decode(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let width = 1usize << usize::from(first >> 6);
    let bytes = input.get(..width)?;

    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }

    Some((value, width))
}

/// Serde helpers for QUIC variable-length integers in interoperable JSON.
///
/// QUIC integers are limited to 62 bits by
/// [RFC 9000, Section 16](https://www.rfc-editor.org/rfc/rfc9000#section-16), while JSON
/// consumers commonly preserve integers exactly only through 2^53 - 1; see
/// [RFC 7493, Section 2.2](https://www.rfc-editor.org/rfc/rfc7493#section-2.2). Values above
/// that JSON-safe boundary are therefore serialized as decimal strings.
pub(crate) mod serde {
    use std::fmt;

    use ::serde::{
        de::{self, Visitor},
        ser::Error as _,
        Deserializer, Serializer,
    };

    use super::MAX_VALUE;

    const JSON_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;

    /// Serializes a QUIC varint as a JSON-safe number or decimal string.
    pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_range(*value).map_err(S::Error::custom)?;

        if *value <= JSON_SAFE_INTEGER_MAX {
            serializer.serialize_u64(*value)
        } else {
            serializer.collect_str(value)
        }
    }

    /// Deserializes a canonical QUIC varint from a safe number or large decimal string.
    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(QuicVarIntVisitor)
    }

    struct QuicVarIntVisitor;

    impl<'de> Visitor<'de> for QuicVarIntVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a QUIC variable-length integer as a number or decimal string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            validate_number(value).map_err(E::custom)
        }

        fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let value = u64::try_from(value)
                .map_err(|_| E::custom("QUIC variable-length integer exceeds 62 bits"))?;
            validate_number(value).map_err(E::custom)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let value = u64::try_from(value)
                .map_err(|_| E::custom("QUIC variable-length integer cannot be negative"))?;
            validate_number(value).map_err(E::custom)
        }

        fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let value = u64::try_from(value).map_err(|_| {
                E::custom("QUIC variable-length integer is outside its valid range")
            })?;
            validate_number(value).map_err(E::custom)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_decimal(value).map_err(E::custom)
        }
    }

    /// Validates a QUIC varint represented by a JSON numeric token.
    pub(crate) fn validate_number(value: u64) -> Result<u64, &'static str> {
        validate_range(value)?;
        if value <= JSON_SAFE_INTEGER_MAX {
            Ok(value)
        } else {
            Err("QUIC integers above 2^53 - 1 must be encoded as decimal strings")
        }
    }

    /// Parses a canonical decimal-string QUIC varint without an intermediate allocation.
    pub(crate) fn parse_decimal(value: &str) -> Result<u64, &'static str> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("QUIC variable-length integer string must contain only decimal digits");
        }
        if value.len() > 1 && value.starts_with('0') {
            return Err("QUIC variable-length integer strings must not contain leading zeros");
        }

        let value = value
            .parse::<u64>()
            .map_err(|_| "QUIC variable-length integer exceeds 62 bits")?;
        validate_range(value)?;
        if value > JSON_SAFE_INTEGER_MAX {
            Ok(value)
        } else {
            Err("QUIC integers through 2^53 - 1 must be encoded as JSON numbers")
        }
    }

    fn validate_range(value: u64) -> Result<u64, &'static str> {
        if value <= MAX_VALUE {
            Ok(value)
        } else {
            Err("QUIC variable-length integer exceeds 62 bits")
        }
    }
}

#[cfg(test)]
pub(crate) fn encode(value: u64, output: &mut Vec<u8>) -> Result<(), &'static str> {
    let width = match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        1_073_741_824..=MAX_VALUE => 8,
        _ => return Err("QUIC variable-length integer exceeds 62 bits"),
    };

    let marker = match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => return Err("invalid QUIC variable-length integer width"),
    };
    let bytes = value.to_be_bytes();
    let start = bytes.len() - width;
    output.push(bytes[start] | marker);
    output.extend_from_slice(&bytes[start + 1..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ::serde::{Deserialize, Serialize};

    use super::{decode, encode};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct JsonVarInt {
        #[serde(with = "super::serde")]
        value: u64,
    }

    #[test]
    fn quic_varints_roundtrip_at_each_width_boundary() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ] {
            let mut encoded = Vec::new();
            encode(value, &mut encoded).unwrap();

            assert_eq!(decode(&encoded), Some((value, encoded.len())));
        }
    }

    #[test]
    fn incomplete_quic_varint_waits_for_more_bytes() {
        assert_eq!(decode(&[0x40]), None);
        assert_eq!(decode(&[0x80, 0, 0]), None);
        assert_eq!(decode(&[0xc0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn json_varints_use_numbers_only_within_the_exact_interoperable_range() {
        assert_eq!(
            serde_json::to_string(&JsonVarInt {
                value: 9_007_199_254_740_991,
            })
            .unwrap(),
            r#"{"value":9007199254740991}"#
        );
        assert_eq!(
            serde_json::to_string(&JsonVarInt {
                value: 9_007_199_254_740_992,
            })
            .unwrap(),
            r#"{"value":"9007199254740992"}"#
        );
        assert_eq!(
            serde_json::to_string(&JsonVarInt {
                value: 4_611_686_018_427_387_903,
            })
            .unwrap(),
            r#"{"value":"4611686018427387903"}"#
        );
    }

    #[test]
    fn json_varints_accept_only_the_canonical_number_or_string_form() {
        for json in [
            r#"{"value":42}"#,
            r#"{"value":9007199254740991}"#,
            r#"{"value":"9007199254740992"}"#,
            r#"{"value":"4611686018427387903"}"#,
        ] {
            assert!(serde_json::from_str::<JsonVarInt>(json).is_ok(), "{json}");
        }
    }

    #[test]
    fn json_varints_reject_invalid_or_out_of_range_values() {
        for json in [
            r#"{"value":-1}"#,
            r#"{"value":"-1"}"#,
            r#"{"value":"+1"}"#,
            r#"{"value":"1.0"}"#,
            r#"{"value":" 1"}"#,
            r#"{"value":"0"}"#,
            r#"{"value":"00"}"#,
            r#"{"value":"42"}"#,
            r#"{"value":"9007199254740991"}"#,
            r#"{"value":"09007199254740992"}"#,
            r#"{"value":9007199254740992}"#,
            r#"{"value":4611686018427387904}"#,
            r#"{"value":"4611686018427387904"}"#,
        ] {
            assert!(serde_json::from_str::<JsonVarInt>(json).is_err(), "{json}");
        }

        assert!(serde_json::to_string(&JsonVarInt {
            value: 4_611_686_018_427_387_904,
        })
        .is_err());
    }
}
