use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::varint;
use crate::tls::HexBytes;

/// One QUIC transport parameter in its original ClientHello order.
///
/// Each parameter is encoded as an identifier, byte length, and value. Unknown and GREASE
/// parameters remain available as bytes so a saved capture does not lose wire information.
/// See [RFC 9000, Section 18](https://www.rfc-editor.org/rfc/rfc9000#section-18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "QuicTransportParameterRepr")]
pub struct QuicTransportParameter {
    /// Numeric transport-parameter identifier observed on the wire.
    #[serde(with = "varint::serde")]
    pub id: u64,

    /// Registered, reserved, or unassigned meaning of the identifier.
    pub name: QuicTransportParameterName,

    /// Decoded integer, opaque bytes, or compatible-version information.
    pub value: QuicTransportParameterValue,
}

/// Semantic name of a QUIC transport parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicTransportParameterName {
    /// `original_destination_connection_id` (`0x00`).
    OriginalDestinationConnectionId,

    /// `max_idle_timeout` (`0x01`).
    MaxIdleTimeout,

    /// `stateless_reset_token` (`0x02`).
    StatelessResetToken,

    /// `max_udp_payload_size` (`0x03`).
    MaxUdpPayloadSize,

    /// `initial_max_data` (`0x04`).
    InitialMaxData,

    /// `initial_max_stream_data_bidi_local` (`0x05`).
    InitialMaxStreamDataBidiLocal,

    /// `initial_max_stream_data_bidi_remote` (`0x06`).
    InitialMaxStreamDataBidiRemote,

    /// `initial_max_stream_data_uni` (`0x07`).
    InitialMaxStreamDataUni,

    /// `initial_max_streams_bidi` (`0x08`).
    InitialMaxStreamsBidi,

    /// `initial_max_streams_uni` (`0x09`).
    InitialMaxStreamsUni,

    /// `ack_delay_exponent` (`0x0a`).
    AckDelayExponent,

    /// `max_ack_delay` (`0x0b`).
    MaxAckDelay,

    /// `disable_active_migration` (`0x0c`).
    DisableActiveMigration,

    /// `preferred_address` (`0x0d`).
    PreferredAddress,

    /// `active_connection_id_limit` (`0x0e`).
    ActiveConnectionIdLimit,

    /// `initial_source_connection_id` (`0x0f`).
    InitialSourceConnectionId,

    /// `retry_source_connection_id` (`0x10`).
    RetrySourceConnectionId,

    /// `version_information` (`0x11`).
    ///
    /// See [RFC 9368, Section 3](https://www.rfc-editor.org/rfc/rfc9368#section-3).
    VersionInformation,

    /// `max_datagram_frame_size` (`0x20`).
    ///
    /// See [RFC 9221, Section 3](https://www.rfc-editor.org/rfc/rfc9221#section-3).
    MaxDatagramFrameSize,

    /// The reserved QUIC fixed-bit grease parameter (`0x2ab2`).
    ///
    /// See [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287).
    GreaseQuicBit,

    /// Google's provisional `initial_rtt` parameter (`0x3127`).
    InitialRtt,

    /// Google's provisional connection-options parameter (`0x3128`).
    GoogleConnectionOptions,

    /// Google's deprecated provisional user-agent parameter (`0x3129`).
    UserAgent,

    /// A reserved value of the form `31 * N + 27`.
    ///
    /// See [RFC 9000, Section 18.1](https://www.rfc-editor.org/rfc/rfc9000#section-18.1).
    Grease,

    /// An unassigned or otherwise unsupported parameter retained as bytes.
    Other,
}

/// Value representation used by a QUIC transport parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QuicTransportParameterValue {
    /// A QUIC variable-length integer.
    Integer(#[serde(with = "varint::serde")] u64),

    /// Opaque bytes serialized as lowercase hexadecimal text.
    Bytes(HexBytes),

    /// Compatible QUIC version information.
    VersionInformation(QuicVersionInformation),
}

/// Compatible versions advertised by the `version_information` transport parameter.
///
/// Versions are fixed-width 32-bit values rather than QUIC variable-length integers. See
/// [RFC 9368, Section 3](https://www.rfc-editor.org/rfc/rfc9368#section-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicVersionInformation {
    /// Version selected for this connection.
    pub chosen_version: QuicVersion,

    /// Compatible versions offered by the endpoint in wire order.
    pub available_versions: Vec<QuicVersion>,
}

/// A 32-bit QUIC version and its recognized meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "QuicVersionRepr")]
pub struct QuicVersion {
    /// Numeric version from the handshake.
    pub id: u32,

    /// Registered, GREASE, or unsupported version name.
    pub name: QuicVersionName,
}

/// Semantic name of a QUIC version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicVersionName {
    /// QUIC version 1 (`0x00000001`).
    Version1,

    /// QUIC version 2 (`0x6b3343cf`).
    Version2,

    /// A reserved version whose four low nibbles are all `0x0a`.
    Grease,

    /// An unsupported or unassigned QUIC version.
    Other,
}

/// Errors returned while decoding a complete QUIC transport-parameter block.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QuicTransportParameterError {
    /// A parameter identifier, length, or payload ended before its declared boundary.
    #[error("incomplete QUIC transport parameter at byte offset {offset}")]
    Incomplete {
        /// Offset where decoding could not continue.
        offset: usize,
    },

    /// A parameter length could not be represented by this platform.
    #[error("QUIC transport parameter {id} length exceeds the platform limit")]
    LengthOverflow {
        /// Parameter identifier whose length overflowed.
        id: u64,
    },

    /// The same identifier appeared more than once.
    #[error("duplicate QUIC transport parameter {id}")]
    Duplicate {
        /// Repeated parameter identifier.
        id: u64,
    },

    /// An integer parameter did not contain exactly one QUIC variable-length integer.
    #[error("QUIC transport parameter {id} has an invalid integer value")]
    InvalidInteger {
        /// Malformed integer parameter identifier.
        id: u64,
    },

    /// The compatible-version payload was malformed.
    #[error("QUIC version_information transport parameter is malformed")]
    InvalidVersionInformation,
}

/// Deserialization shape used to validate a saved QUIC transport parameter.
#[derive(Deserialize)]
struct QuicTransportParameterRepr {
    /// Saved numeric parameter identifier.
    #[serde(with = "varint::serde")]
    id: u64,

    /// Saved semantic parameter name.
    name: QuicTransportParameterName,

    /// Saved decoded or opaque parameter value.
    value: QuicTransportParameterValueRepr,
}

/// Raw deserialization shape whose string values are interpreted using the parameter name.
#[derive(Deserialize)]
#[serde(untagged)]
enum QuicTransportParameterValueRepr {
    /// An integer represented by a JSON number.
    Integer(u64),

    /// A decimal QUIC integer or hexadecimal opaque bytes.
    Text(Box<str>),

    /// Compatible-version information.
    VersionInformation(QuicVersionInformation),
}

/// Deserialization shape used to validate a saved QUIC version.
#[derive(Deserialize)]
struct QuicVersionRepr {
    /// Saved 32-bit QUIC version.
    id: u32,

    /// Saved semantic version name.
    name: QuicVersionName,
}

impl QuicTransportParameter {
    /// Returns whether this identifier is reserved for QUIC extensibility testing.
    pub const fn is_grease(&self) -> bool {
        is_grease_id(self.id)
    }
}

impl TryFrom<QuicTransportParameterRepr> for QuicTransportParameter {
    type Error = &'static str;

    fn try_from(repr: QuicTransportParameterRepr) -> Result<Self, Self::Error> {
        let QuicTransportParameterRepr { id, name, value } = repr;
        let expected_name = QuicTransportParameterName::from_id(id);
        if name != expected_name {
            return Err("QUIC transport parameter name does not match its identifier");
        }

        let value = match expected_name {
            QuicTransportParameterName::MaxIdleTimeout
            | QuicTransportParameterName::MaxUdpPayloadSize
            | QuicTransportParameterName::InitialMaxData
            | QuicTransportParameterName::InitialMaxStreamDataBidiLocal
            | QuicTransportParameterName::InitialMaxStreamDataBidiRemote
            | QuicTransportParameterName::InitialMaxStreamDataUni
            | QuicTransportParameterName::InitialMaxStreamsBidi
            | QuicTransportParameterName::InitialMaxStreamsUni
            | QuicTransportParameterName::AckDelayExponent
            | QuicTransportParameterName::MaxAckDelay
            | QuicTransportParameterName::ActiveConnectionIdLimit
            | QuicTransportParameterName::MaxDatagramFrameSize
            | QuicTransportParameterName::InitialRtt => match value {
                QuicTransportParameterValueRepr::Integer(value) => {
                    QuicTransportParameterValue::Integer(varint::serde::validate_number(value)?)
                }
                QuicTransportParameterValueRepr::Text(value) => {
                    QuicTransportParameterValue::Integer(varint::serde::parse_decimal(&value)?)
                }
                QuicTransportParameterValueRepr::VersionInformation(_) => {
                    return Err("QUIC transport parameter value has the wrong representation");
                }
            },
            QuicTransportParameterName::VersionInformation => match value {
                QuicTransportParameterValueRepr::VersionInformation(value) => {
                    QuicTransportParameterValue::VersionInformation(value)
                }
                _ => {
                    return Err("QUIC transport parameter value has the wrong representation");
                }
            },
            _ => match value {
                QuicTransportParameterValueRepr::Text(value) => {
                    QuicTransportParameterValue::Bytes(deserialize_hex_bytes(&value)?)
                }
                _ => {
                    return Err("QUIC transport parameter value has the wrong representation");
                }
            },
        };

        Ok(Self { id, name, value })
    }
}

fn deserialize_hex_bytes(value: &str) -> Result<HexBytes, &'static str> {
    let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value);
    HexBytes::deserialize(deserializer)
        .map_err(|_| "QUIC transport parameter bytes must be lowercase hexadecimal")
}

impl QuicTransportParameterName {
    /// Returns the semantic name assigned to `id`.
    pub const fn from_id(id: u64) -> Self {
        match id {
            0x00 => Self::OriginalDestinationConnectionId,
            0x01 => Self::MaxIdleTimeout,
            0x02 => Self::StatelessResetToken,
            0x03 => Self::MaxUdpPayloadSize,
            0x04 => Self::InitialMaxData,
            0x05 => Self::InitialMaxStreamDataBidiLocal,
            0x06 => Self::InitialMaxStreamDataBidiRemote,
            0x07 => Self::InitialMaxStreamDataUni,
            0x08 => Self::InitialMaxStreamsBidi,
            0x09 => Self::InitialMaxStreamsUni,
            0x0a => Self::AckDelayExponent,
            0x0b => Self::MaxAckDelay,
            0x0c => Self::DisableActiveMigration,
            0x0d => Self::PreferredAddress,
            0x0e => Self::ActiveConnectionIdLimit,
            0x0f => Self::InitialSourceConnectionId,
            0x10 => Self::RetrySourceConnectionId,
            0x11 => Self::VersionInformation,
            0x20 => Self::MaxDatagramFrameSize,
            0x2ab2 => Self::GreaseQuicBit,
            0x3127 => Self::InitialRtt,
            0x3128 => Self::GoogleConnectionOptions,
            0x3129 => Self::UserAgent,
            value if is_grease_id(value) => Self::Grease,
            _ => Self::Other,
        }
    }
}

impl QuicTransportParameterValue {
    /// Returns the integer value when this parameter uses QUIC varint encoding.
    pub const fn as_integer(&self) -> Option<u64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns opaque parameter bytes when this value is byte-oriented.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value.as_bytes()),
            _ => None,
        }
    }

    /// Returns compatible-version information when this is parameter `0x11`.
    pub const fn as_version_information(&self) -> Option<&QuicVersionInformation> {
        match self {
            Self::VersionInformation(value) => Some(value),
            _ => None,
        }
    }
}

impl QuicVersion {
    /// Creates a QUIC version and derives its semantic name.
    pub const fn from_id(id: u32) -> Self {
        Self {
            id,
            name: QuicVersionName::from_id(id),
        }
    }

    /// Returns whether this is a reserved GREASE version.
    pub const fn is_grease(&self) -> bool {
        is_grease_version(self.id)
    }
}

impl TryFrom<QuicVersionRepr> for QuicVersion {
    type Error = &'static str;

    fn try_from(repr: QuicVersionRepr) -> Result<Self, Self::Error> {
        if repr.name != QuicVersionName::from_id(repr.id) {
            return Err("QUIC version name does not match its identifier");
        }

        Ok(Self {
            id: repr.id,
            name: repr.name,
        })
    }
}

impl QuicVersionName {
    /// Returns the semantic name assigned to a 32-bit QUIC version.
    pub const fn from_id(id: u32) -> Self {
        match id {
            0x0000_0001 => Self::Version1,
            0x6b33_43cf => Self::Version2,
            value if is_grease_version(value) => Self::Grease,
            _ => Self::Other,
        }
    }
}

/// Parses a complete TLS `quic_transport_parameters` extension payload.
///
/// Parameters are returned in their original wire order. Duplicate identifiers are rejected as
/// required by [RFC 9000, Section 7.4](https://www.rfc-editor.org/rfc/rfc9000#section-7.4).
pub fn parse_transport_parameters(
    input: &[u8],
) -> Result<Vec<QuicTransportParameter>, QuicTransportParameterError> {
    let mut offset = 0usize;
    let mut parameters = Vec::new();
    let mut parameter_ids = HashSet::new();

    while offset < input.len() {
        let (id, id_len) = varint::decode(&input[offset..])
            .ok_or(QuicTransportParameterError::Incomplete { offset })?;
        offset = offset
            .checked_add(id_len)
            .ok_or(QuicTransportParameterError::LengthOverflow { id })?;

        let (length, length_len) = varint::decode(&input[offset..])
            .ok_or(QuicTransportParameterError::Incomplete { offset })?;
        offset = offset
            .checked_add(length_len)
            .ok_or(QuicTransportParameterError::LengthOverflow { id })?;
        let length = usize::try_from(length)
            .map_err(|_| QuicTransportParameterError::LengthOverflow { id })?;
        let end = offset
            .checked_add(length)
            .ok_or(QuicTransportParameterError::LengthOverflow { id })?;
        let payload = input
            .get(offset..end)
            .ok_or(QuicTransportParameterError::Incomplete { offset })?;
        offset = end;

        if !parameter_ids.insert(id) {
            return Err(QuicTransportParameterError::Duplicate { id });
        }

        let name = QuicTransportParameterName::from_id(id);
        let value = match name {
            QuicTransportParameterName::MaxIdleTimeout
            | QuicTransportParameterName::MaxUdpPayloadSize
            | QuicTransportParameterName::InitialMaxData
            | QuicTransportParameterName::InitialMaxStreamDataBidiLocal
            | QuicTransportParameterName::InitialMaxStreamDataBidiRemote
            | QuicTransportParameterName::InitialMaxStreamDataUni
            | QuicTransportParameterName::InitialMaxStreamsBidi
            | QuicTransportParameterName::InitialMaxStreamsUni
            | QuicTransportParameterName::AckDelayExponent
            | QuicTransportParameterName::MaxAckDelay
            | QuicTransportParameterName::ActiveConnectionIdLimit
            | QuicTransportParameterName::MaxDatagramFrameSize
            | QuicTransportParameterName::InitialRtt => {
                let (value, consumed) = varint::decode(payload)
                    .ok_or(QuicTransportParameterError::InvalidInteger { id })?;
                if consumed != payload.len() {
                    return Err(QuicTransportParameterError::InvalidInteger { id });
                }
                QuicTransportParameterValue::Integer(value)
            }
            QuicTransportParameterName::VersionInformation => {
                QuicTransportParameterValue::VersionInformation(parse_version_information(payload)?)
            }
            _ => QuicTransportParameterValue::Bytes(HexBytes::from(payload)),
        };

        parameters.push(QuicTransportParameter { id, name, value });
    }

    Ok(parameters)
}

fn parse_version_information(
    payload: &[u8],
) -> Result<QuicVersionInformation, QuicTransportParameterError> {
    if payload.len() < 8 || !payload.len().is_multiple_of(4) {
        return Err(QuicTransportParameterError::InvalidVersionInformation);
    }

    let chosen_version = QuicVersion::from_id(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]));
    let available_versions = payload[4..]
        .chunks_exact(4)
        .map(|version| {
            QuicVersion::from_id(u32::from_be_bytes([
                version[0], version[1], version[2], version[3],
            ]))
        })
        .collect();

    Ok(QuicVersionInformation {
        chosen_version,
        available_versions,
    })
}

const fn is_grease_id(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

const fn is_grease_version(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        parse_transport_parameters, QuicTransportParameter, QuicTransportParameterError,
        QuicTransportParameterName, QuicVersionName,
    };
    use crate::quic::varint;

    #[test]
    fn transport_parameters_preserve_order_names_and_value_types() {
        let mut bytes = Vec::new();
        push_parameter(&mut bytes, 1, &encode_varint(30_000));
        push_parameter(&mut bytes, 15, &[]);
        push_parameter(
            &mut bytes,
            17,
            &[0, 0, 0, 1, 0, 0, 0, 1, 0x1a, 0x2a, 0x3a, 0x4a],
        );
        push_parameter(&mut bytes, 58, &[0xe5, 0x49]);

        let parameters = parse_transport_parameters(&bytes).unwrap();

        assert_eq!(
            parameters[0].name,
            QuicTransportParameterName::MaxIdleTimeout
        );
        assert_eq!(parameters[0].value.as_integer(), Some(30_000));
        assert_eq!(parameters[1].value.as_bytes(), Some(&[][..]));
        assert!(parameters[3].is_grease());
        let versions = parameters[2].value.as_version_information().unwrap();
        assert_eq!(versions.chosen_version.name, QuicVersionName::Version1);
        assert_eq!(versions.available_versions[1].name, QuicVersionName::Grease);

        assert_eq!(
            serde_json::to_value(&parameters[1]).unwrap(),
            json!({"id": 15, "name": "initial_source_connection_id", "value": ""})
        );
    }

    #[test]
    fn transport_parameters_reject_duplicates_and_truncation() {
        let mut duplicate = Vec::new();
        push_parameter(&mut duplicate, 1, &encode_varint(1));
        push_parameter(&mut duplicate, 1, &encode_varint(2));

        assert_eq!(
            parse_transport_parameters(&duplicate).unwrap_err(),
            QuicTransportParameterError::Duplicate { id: 1 }
        );
        assert!(matches!(
            parse_transport_parameters(&[0x01, 0x04, 0x01]),
            Err(QuicTransportParameterError::Incomplete { .. })
        ));
    }

    #[test]
    fn transport_parameters_scale_to_many_ids_and_reject_a_late_duplicate() {
        const PARAMETER_COUNT: u64 = 4_096;
        const FIRST_ID: u64 = 1 << 40;

        let mut bytes = Vec::new();
        for index in 0..PARAMETER_COUNT {
            push_parameter(&mut bytes, FIRST_ID + index * 31, &[]);
        }

        let parameters = parse_transport_parameters(&bytes).unwrap();
        assert_eq!(parameters.len(), PARAMETER_COUNT as usize);
        assert!(parameters
            .iter()
            .enumerate()
            .all(|(index, parameter)| parameter.id == FIRST_ID + index as u64 * 31));

        push_parameter(&mut bytes, FIRST_ID, &[]);
        assert_eq!(
            parse_transport_parameters(&bytes).unwrap_err(),
            QuicTransportParameterError::Duplicate { id: FIRST_ID }
        );
    }

    #[test]
    fn transport_parameter_json_preserves_large_varints() {
        let large_integer = 9_007_199_254_740_992;
        let large_id = 2_607_827_185_491_430_401;
        let mut bytes = Vec::new();
        push_parameter(&mut bytes, large_id, &[0xf4]);
        push_parameter(&mut bytes, 4, &encode_varint(large_integer));

        let parameters = parse_transport_parameters(&bytes).unwrap();
        let json = serde_json::to_value(&parameters).unwrap();

        assert_eq!(json[0]["id"], json!("2607827185491430401"));
        assert_eq!(json[1]["value"], json!("9007199254740992"));
        assert_eq!(
            serde_json::from_value::<Vec<QuicTransportParameter>>(json).unwrap(),
            parameters
        );
    }

    #[test]
    fn saved_parameter_uses_its_name_to_distinguish_bytes_from_decimal_varints() {
        let bytes = json!({
            "id": 15,
            "name": "initial_source_connection_id",
            "value": "00"
        });
        let integer = json!({
            "id": 4,
            "name": "initial_max_data",
            "value": "9007199254740992"
        });

        let bytes = serde_json::from_value::<QuicTransportParameter>(bytes).unwrap();
        let integer = serde_json::from_value::<QuicTransportParameter>(integer).unwrap();

        assert_eq!(bytes.value.as_bytes(), Some(&[0][..]));
        assert_eq!(integer.value.as_integer(), Some(9_007_199_254_740_992));
    }

    #[test]
    fn saved_parameter_rejects_noncanonical_or_out_of_range_varints() {
        for value in [
            json!({
                "id": "4",
                "name": "initial_max_data",
                "value": 42
            }),
            json!({
                "id": 2_607_827_185_491_430_401_u64,
                "name": "grease",
                "value": "f4"
            }),
            json!({
                "id": 4,
                "name": "initial_max_data",
                "value": "42"
            }),
            json!({
                "id": 4,
                "name": "initial_max_data",
                "value": 9_007_199_254_740_992_u64
            }),
            json!({
                "id": "4611686018427387904",
                "name": "other",
                "value": ""
            }),
            json!({
                "id": 4,
                "name": "initial_max_data",
                "value": "4611686018427387904"
            }),
        ] {
            assert!(serde_json::from_value::<QuicTransportParameter>(value).is_err());
        }
    }

    #[test]
    fn saved_parameter_rejects_a_mismatched_name() {
        let value = json!({"id": 1, "name": "max_udp_payload_size", "value": 30000});

        assert!(serde_json::from_value::<super::QuicTransportParameter>(value).is_err());
    }

    fn push_parameter(output: &mut Vec<u8>, id: u64, value: &[u8]) {
        varint::encode(id, output).unwrap();
        varint::encode(value.len() as u64, output).unwrap();
        output.extend_from_slice(value);
    }

    fn encode_varint(value: u64) -> Vec<u8> {
        let mut output = Vec::new();
        varint::encode(value, &mut output).unwrap();
        output
    }
}
