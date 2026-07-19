use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{quic::varint, tls::HexBytes};

/// A client-initiated HTTP/3 unidirectional stream type.
///
/// The stream type is the first QUIC varint on every unidirectional stream. See
/// [RFC 9114, Section 6.2](https://www.rfc-editor.org/rfc/rfc9114#section-6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "StreamTypeRepr")]
pub struct StreamType {
    /// Numeric stream type observed on the wire.
    #[serde(with = "varint::serde")]
    pub id: u64,

    /// Registered, reserved, or unsupported meaning of the stream type.
    pub name: StreamTypeName,
}

/// Semantic name of an HTTP/3 unidirectional stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum StreamTypeName {
    /// The HTTP/3 control stream (`0x00`).
    Control,

    /// A server push stream (`0x01`).
    Push,

    /// The QPACK encoder stream (`0x02`).
    QpackEncoder,

    /// The QPACK decoder stream (`0x03`).
    QpackDecoder,

    /// A WebTransport unidirectional stream (`0x54`).
    WebTransport,

    /// A reserved stream type of the form `31 * N + 33`.
    Grease,

    /// An unsupported stream type that HTTP/3 requires recipients to ignore.
    Other,
}

/// One HTTP/3 SETTINGS parameter in its original wire order.
///
/// Both the identifier and value are QUIC variable-length integers. See
/// [RFC 9114, Section 7.2.8](https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SettingRepr")]
pub struct Setting {
    /// Numeric SETTINGS identifier observed on the wire.
    #[serde(with = "varint::serde")]
    pub id: u64,

    /// Registered, reserved, or unsupported meaning of the identifier.
    pub name: SettingName,

    /// SETTINGS value using the canonical representation for its identifier.
    pub value: SettingValue,
}

/// A canonical HTTP/3 SETTINGS value.
///
/// SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM, and the draft
/// H3_DATAGRAM setting use Self::Bool. Every other setting uses Self::Number.
/// See [RFC 9220, Section 3](https://www.rfc-editor.org/rfc/rfc9220#section-3),
/// [RFC 9297, Section 2.1.1](https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1), and
/// [draft-ietf-masque-h3-datagram-08, Section 2.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram-08#section-2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SettingValue {
    /// A numeric QUIC variable-length integer value.
    Number(#[serde(with = "varint::serde")] u64),

    /// A setting whose wire value is exactly 0 or 1.
    Bool(bool),
}

/// Semantic name of an HTTP/3 SETTINGS identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SettingName {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`0x01`).
    QpackMaxTableCapacity,

    /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (`0x06`).
    MaxFieldSectionSize,

    /// `SETTINGS_QPACK_BLOCKED_STREAMS` (`0x07`).
    QpackBlockedStreams,

    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x08`).
    ///
    /// See [RFC 9220, Section 3](https://www.rfc-editor.org/rfc/rfc9220#section-3).
    EnableConnectProtocol,

    /// `SETTINGS_H3_DATAGRAM` (`0x33`).
    ///
    /// See [RFC 9297, Section 2.1.1](https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1).
    H3Datagram,

    /// Draft `H3_DATAGRAM` (`0xffd277`) used before RFC 9297 assigned `0x33`.
    ///
    /// See [draft-ietf-masque-h3-datagram-08, Section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram-08#section-5.1).
    H3DatagramDraft,

    /// Provisional `SETTINGS_ENABLE_METADATA` (`0x4d44`).
    ///
    /// See the [IANA HTTP/3 Settings registry](https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml#http3-parameters-2).
    EnableMetadata,

    /// Early `SETTINGS_ENABLE_WEBTRANSPORT` (`0x2b603742`) from IETF drafts 00 through 06.
    ///
    /// See [draft-ietf-webtrans-http3-06](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-06).
    EnableWebTransportDraft,

    /// Draft `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` and `SETTINGS_WT_MAX_SESSIONS`.
    ///
    /// Drafts 04-05 used `0x2b603743`, draft 06 used `0x3c48d522`, drafts 07-12
    /// used `0xc671706a`, and drafts 13-14 used `0x14e9cd29`.
    /// See [draft-05](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-05#section-8.2),
    /// [draft-06](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-06#section-8.2),
    /// [draft-12](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-12#section-9.2), and
    /// [draft-14](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-14#section-9.2).
    WebTransportMaxSessionsDraft,

    /// Draft `SETTINGS_WT_ENABLED` used from draft 15 onward.
    ///
    /// See [draft-ietf-webtrans-http3-16, Section 9.2](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-9.2).
    WebTransportEnabledDraft,

    /// Draft initial unidirectional WebTransport stream limit (`0x2b64`) used since draft 12.
    ///
    /// See [draft-ietf-webtrans-http3-16, Section 9.2](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-9.2).
    WebTransportInitialMaxStreamsUniDraft,

    /// Draft initial bidirectional WebTransport stream limit (`0x2b65`) used since draft 12.
    ///
    /// See [draft-ietf-webtrans-http3-16, Section 9.2](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-9.2).
    WebTransportInitialMaxStreamsBidiDraft,

    /// Draft initial WebTransport session data limit (`0x2b61`) used since draft 12.
    ///
    /// See [draft-ietf-webtrans-http3-16, Section 9.2](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-9.2).
    WebTransportInitialMaxDataDraft,

    /// A reserved setting identifier of the form `31 * N + 33`.
    Grease,

    /// An unsupported setting retained for analysis.
    Other,
}

/// A decoded HTTP field preserving its QPACK field-section position.
///
/// HTTP/3 uses the same field semantics as HTTP/2 while QPACK carries the wire representation.
/// See [RFC 9114, Section 4.2](https://www.rfc-editor.org/rfc/rfc9114#section-4.2).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    /// Decoded field-name bytes, including the leading `:` for pseudo-fields.
    #[serde(with = "header_bytes")]
    pub name: Box<[u8]>,

    /// Decoded field-value bytes.
    #[serde(with = "header_bytes")]
    pub value: Box<[u8]>,
}

/// A decoded HTTP/3 SETTINGS frame.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SettingsFrameRepr")]
pub struct SettingsFrame {
    /// Frame category, always [`FrameType::Settings`].
    pub frame_type: FrameType,

    /// Payload length excluding the two QUIC varints in the frame header.
    pub length: usize,

    /// Settings in their original wire order.
    pub settings: Vec<Setting>,
}

/// A decoded HTTP/3 HEADERS frame.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "HeadersFrameRepr")]
pub struct HeadersFrame {
    /// Frame category, always [`FrameType::Headers`].
    pub frame_type: FrameType,

    /// Encoded QPACK payload length.
    pub length: usize,

    /// Decoded fields in their original field-section order.
    pub headers: Vec<HeaderField>,
}

/// A frame retained without type-specific payload decoding.
///
/// The semantic frame type is derived from the numeric identifier, so registered,
/// extension, GREASE, and genuinely unknown frames remain distinguishable.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OpaqueFrameRepr")]
pub struct OpaqueFrame {
    /// Semantic frame category derived from Self::type_id.
    pub frame_type: FrameType,

    /// Numeric HTTP/3 frame type observed on the wire.
    #[serde(with = "varint::serde")]
    pub type_id: u64,

    /// Payload length excluding the frame type and length varints.
    pub length: usize,

    /// Payload retained as lowercase hexadecimal text.
    pub payload: HexBytes,
}

/// HTTP/3 frames represented by the analyzer.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Frame {
    /// A SETTINGS frame from the control stream.
    Settings(SettingsFrame),

    /// A QPACK-decoded HEADERS frame.
    Headers(HeadersFrame),

    /// A frame retained with its semantic type, numeric identifier, and payload.
    Opaque(OpaqueFrame),
}

/// Semantic HTTP/3 frame types represented by [`Frame`].
///
/// Registered values follow the [IANA HTTP/3 Frame Types registry](https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml#http3-parameters-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    /// DATA (0x00).
    Data,

    /// HEADERS (`0x01`).
    Headers,

    /// An HTTP/2 frame type reserved by HTTP/3 (0x02, 0x06, 0x08, or 0x09).
    Http2Reserved,

    /// CANCEL_PUSH (0x03).
    CancelPush,

    /// SETTINGS (`0x04`).
    Settings,

    /// PUSH_PROMISE (0x05).
    PushPromise,

    /// GOAWAY (0x07).
    GoAway,

    /// ORIGIN (0x0c).
    Origin,

    /// MAX_PUSH_ID (0x0d).
    MaxPushId,

    /// Request-stream PRIORITY_UPDATE (0x0f0700).
    PriorityUpdateRequest,

    /// Push-stream PRIORITY_UPDATE (0x0f0701).
    PriorityUpdatePush,

    /// A reserved frame type of the form 31 * N + 33.
    Grease,

    /// An unregistered frame type.
    Other,
}

/// Protocol errors found in a complete HTTP/3 frame payload.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Http3FrameError {
    /// A SETTINGS payload ended between an identifier and value.
    #[error("incomplete HTTP/3 SETTINGS parameter")]
    IncompleteSetting,

    /// A SETTINGS identifier appeared more than once.
    #[error("duplicate HTTP/3 setting {id}")]
    DuplicateSetting {
        /// Repeated setting identifier.
        id: u64,
    },

    /// An HTTP/2-only identifier was sent in HTTP/3 SETTINGS.
    #[error("HTTP/2 setting identifier {id} is forbidden in HTTP/3")]
    ForbiddenSetting {
        /// Forbidden setting identifier.
        id: u64,
    },

    /// A Boolean SETTINGS value was not encoded as 0 or 1.
    #[error("HTTP/3 Boolean setting {id} has invalid value {value}")]
    InvalidBooleanSetting {
        /// Setting identifier whose value was invalid.
        id: u64,

        /// Numeric value observed on the wire.
        value: u64,
    },

    /// QPACK could not decode a complete HEADERS field section.
    #[error("failed to decode the HTTP/3 QPACK field section")]
    QpackDecompression,
}

/// Deserialization shape used to validate a saved unidirectional stream type.
#[derive(Deserialize)]
struct StreamTypeRepr {
    /// Saved numeric stream type.
    #[serde(with = "varint::serde")]
    id: u64,

    /// Saved semantic stream type name.
    name: StreamTypeName,
}

/// Deserialization shape used to validate a saved HTTP/3 setting.
#[derive(Deserialize)]
struct SettingRepr {
    /// Saved numeric setting identifier.
    #[serde(with = "varint::serde")]
    id: u64,

    /// Saved semantic setting name.
    name: SettingName,

    /// Saved canonical setting value.
    value: SettingValue,
}

/// Deserialization shape used to validate a saved SETTINGS frame.
#[derive(Deserialize)]
struct SettingsFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved encoded payload length.
    length: usize,

    /// Saved settings in wire order.
    settings: Vec<Setting>,
}

/// Deserialization shape used to validate a saved HEADERS frame.
#[derive(Deserialize)]
struct HeadersFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved encoded QPACK payload length.
    length: usize,

    /// Saved decoded fields in field-section order.
    headers: Vec<HeaderField>,
}

/// Deserialization shape used to validate a saved opaque frame.
#[derive(Deserialize)]
struct OpaqueFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved numeric frame type.
    #[serde(with = "varint::serde")]
    type_id: u64,

    /// Saved payload length.
    length: usize,

    /// Saved opaque payload bytes.
    payload: HexBytes,
}

/// Deserialization shape used to select and validate a saved HTTP/3 frame.
#[derive(Deserialize)]
#[serde(untagged)]
enum FrameRepr {
    /// Saved SETTINGS frame.
    Settings(SettingsFrame),

    /// Saved HEADERS frame.
    Headers(HeadersFrame),

    /// Saved frame without a dedicated decoded model.
    Opaque(OpaqueFrame),
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match FrameRepr::deserialize(deserializer)? {
            FrameRepr::Settings(frame) => Ok(Self::Settings(frame)),
            FrameRepr::Headers(frame) => Ok(Self::Headers(frame)),
            FrameRepr::Opaque(frame) => Ok(Self::Opaque(frame)),
        }
    }
}

impl StreamType {
    /// Creates a stream type from its wire identifier.
    pub const fn from_id(id: u64) -> Self {
        Self {
            id,
            name: StreamTypeName::from_id(id),
        }
    }

    /// Returns whether the identifier is reserved for extensibility testing.
    pub const fn is_grease(&self) -> bool {
        is_grease_id(self.id)
    }
}

impl TryFrom<StreamTypeRepr> for StreamType {
    type Error = &'static str;

    fn try_from(repr: StreamTypeRepr) -> Result<Self, Self::Error> {
        if repr.name != StreamTypeName::from_id(repr.id) {
            return Err("HTTP/3 stream type name does not match its identifier");
        }

        Ok(Self {
            id: repr.id,
            name: repr.name,
        })
    }
}

impl StreamTypeName {
    /// Returns the semantic name assigned to a stream type identifier.
    pub const fn from_id(id: u64) -> Self {
        match id {
            0x00 => Self::Control,
            0x01 => Self::Push,
            0x02 => Self::QpackEncoder,
            0x03 => Self::QpackDecoder,
            0x54 => Self::WebTransport,
            value if is_grease_id(value) => Self::Grease,
            _ => Self::Other,
        }
    }
}

impl Setting {
    /// Creates a setting after its wire value has been validated.
    const fn from_validated_wire(id: u64, value: u64) -> Self {
        let name = SettingName::from_id(id);
        Self {
            id,
            name,
            value: SettingValue::from_wire(name, value),
        }
    }

    /// Validates a wire value and creates its canonical setting representation.
    pub fn try_from_wire(id: u64, value: u64) -> Result<Self, Http3FrameError> {
        if SettingName::from_id(id).uses_boolean_value() && value > 1 {
            return Err(Http3FrameError::InvalidBooleanSetting { id, value });
        }

        Ok(Self::from_validated_wire(id, value))
    }

    /// Returns the original numeric value used by the HTTP/3 wire format.
    pub const fn wire_value(&self) -> u64 {
        self.value.wire_value()
    }

    /// Returns whether the identifier is an HTTP/3 GREASE setting.
    pub const fn is_grease(&self) -> bool {
        is_grease_id(self.id)
    }
}

impl TryFrom<SettingRepr> for Setting {
    type Error = &'static str;

    fn try_from(repr: SettingRepr) -> Result<Self, Self::Error> {
        if repr.name != SettingName::from_id(repr.id) {
            return Err("HTTP/3 setting name does not match its identifier");
        }
        if repr.name.uses_boolean_value() != matches!(repr.value, SettingValue::Bool(_)) {
            return Err("HTTP/3 setting value does not use its canonical JSON representation");
        }

        Ok(Self {
            id: repr.id,
            name: repr.name,
            value: repr.value,
        })
    }
}

impl SettingValue {
    const fn from_wire(name: SettingName, value: u64) -> Self {
        if name.uses_boolean_value() && value <= 1 {
            Self::Bool(value == 1)
        } else {
            Self::Number(value)
        }
    }

    /// Returns the numeric value used by the HTTP/3 wire format.
    pub const fn wire_value(self) -> u64 {
        match self {
            Self::Number(value) => value,
            Self::Bool(value) => value as u64,
        }
    }
}

impl SettingName {
    /// Returns the semantic name assigned to a SETTINGS identifier.
    pub const fn from_id(id: u64) -> Self {
        match id {
            0x01 => Self::QpackMaxTableCapacity,
            0x06 => Self::MaxFieldSectionSize,
            0x07 => Self::QpackBlockedStreams,
            0x08 => Self::EnableConnectProtocol,
            0x33 => Self::H3Datagram,
            0xff_d277 => Self::H3DatagramDraft,
            0x4d44 => Self::EnableMetadata,
            0x2b60_3742 => Self::EnableWebTransportDraft,
            0x2b60_3743 | 0x3c48_d522 | 0xc671_706a | 0x14e9_cd29 => {
                Self::WebTransportMaxSessionsDraft
            }
            0x2c7c_f000 => Self::WebTransportEnabledDraft,
            0x2b64 => Self::WebTransportInitialMaxStreamsUniDraft,
            0x2b65 => Self::WebTransportInitialMaxStreamsBidiDraft,
            0x2b61 => Self::WebTransportInitialMaxDataDraft,
            value if is_grease_id(value) => Self::Grease,
            _ => Self::Other,
        }
    }

    /// Returns whether this setting uses the RFC-defined Boolean value form.
    pub const fn uses_boolean_value(self) -> bool {
        matches!(
            self,
            Self::EnableConnectProtocol | Self::H3Datagram | Self::H3DatagramDraft
        )
    }
}

impl FrameType {
    /// Returns the semantic frame type assigned to a wire identifier.
    pub const fn from_id(id: u64) -> Self {
        match id {
            0x00 => Self::Data,
            0x01 => Self::Headers,
            0x02 | 0x06 | 0x08 | 0x09 => Self::Http2Reserved,
            0x03 => Self::CancelPush,
            0x04 => Self::Settings,
            0x05 => Self::PushPromise,
            0x07 => Self::GoAway,
            0x0c => Self::Origin,
            0x0d => Self::MaxPushId,
            0x0f_0700 => Self::PriorityUpdateRequest,
            0x0f_0701 => Self::PriorityUpdatePush,
            value if is_grease_id(value) => Self::Grease,
            _ => Self::Other,
        }
    }

    /// Returns whether RFC 9114 reserves this HTTP/2 frame identifier.
    pub const fn is_http2_reserved(self) -> bool {
        matches!(self, Self::Http2Reserved)
    }
}

impl Frame {
    /// Returns the decoded frame category.
    pub const fn frame_type(&self) -> FrameType {
        match self {
            Self::Settings(_) => FrameType::Settings,
            Self::Headers(_) => FrameType::Headers,
            Self::Opaque(frame) => frame.frame_type,
        }
    }

    /// Returns the payload length excluding the frame type and length varints.
    pub const fn payload_len(&self) -> usize {
        match self {
            Self::Settings(frame) => frame.length,
            Self::Headers(frame) => frame.length,
            Self::Opaque(frame) => frame.length,
        }
    }
}

impl TryFrom<SettingsFrameRepr> for SettingsFrame {
    type Error = &'static str;

    fn try_from(repr: SettingsFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Settings {
            return Err("HTTP/3 SETTINGS frame_type must be Settings");
        }
        validate_settings(&repr.settings).map_err(|_| "invalid HTTP/3 SETTINGS parameter list")?;

        Ok(Self {
            frame_type: repr.frame_type,
            length: repr.length,
            settings: repr.settings,
        })
    }
}

impl TryFrom<HeadersFrameRepr> for HeadersFrame {
    type Error = &'static str;

    fn try_from(repr: HeadersFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Headers {
            return Err("HTTP/3 HEADERS frame_type must be Headers");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            length: repr.length,
            headers: repr.headers,
        })
    }
}

impl TryFrom<OpaqueFrameRepr> for OpaqueFrame {
    type Error = &'static str;

    fn try_from(repr: OpaqueFrameRepr) -> Result<Self, Self::Error> {
        let expected = FrameType::from_id(repr.type_id);
        if matches!(expected, FrameType::Headers | FrameType::Settings) {
            return Err("a decoded HTTP/3 frame type cannot use OpaqueFrame");
        }
        if expected.is_http2_reserved() {
            return Err("an HTTP/2-reserved frame type is forbidden in HTTP/3");
        }
        if repr.frame_type != expected {
            return Err("opaque HTTP/3 frame_type does not match its identifier");
        }
        if repr.length != repr.payload.len() {
            return Err("opaque HTTP/3 frame length does not match its payload");
        }

        Ok(Self {
            frame_type: expected,
            type_id: repr.type_id,
            length: repr.length,
            payload: repr.payload,
        })
    }
}

pub(super) fn parse_settings(payload: &[u8]) -> Result<SettingsFrame, Http3FrameError> {
    let mut offset = 0usize;
    let mut settings = Vec::new();
    let mut setting_ids = HashSet::new();

    while offset < payload.len() {
        let (id, id_len) =
            varint::decode(&payload[offset..]).ok_or(Http3FrameError::IncompleteSetting)?;
        offset += id_len;
        let (value, value_len) =
            varint::decode(&payload[offset..]).ok_or(Http3FrameError::IncompleteSetting)?;
        offset += value_len;

        validate_setting_id(&mut setting_ids, id)?;
        settings.push(Setting::try_from_wire(id, value)?);
    }

    Ok(SettingsFrame {
        frame_type: FrameType::Settings,
        length: payload.len(),
        settings,
    })
}

pub(super) fn parse_headers(
    payload: &[u8],
    max_field_section_size: u64,
) -> Result<HeadersFrame, Http3FrameError> {
    let mut encoded = payload;
    let decoded = ::qpack::decode_stateless(&mut encoded, max_field_section_size)
        .map_err(|_| Http3FrameError::QpackDecompression)?;
    let headers = decoded
        .fields
        .into_iter()
        .map(|field| {
            let (name, value) = field.into_inner();
            HeaderField {
                name: name.into_owned().into_boxed_slice(),
                value: value.into_owned().into_boxed_slice(),
            }
        })
        .collect();

    Ok(HeadersFrame {
        frame_type: FrameType::Headers,
        length: payload.len(),
        headers,
    })
}

fn validate_settings(settings: &[Setting]) -> Result<(), Http3FrameError> {
    let mut setting_ids = HashSet::with_capacity(settings.len());
    for setting in settings {
        validate_setting_id(&mut setting_ids, setting.id)?;
    }
    Ok(())
}

fn validate_setting_id(setting_ids: &mut HashSet<u64>, id: u64) -> Result<(), Http3FrameError> {
    if matches!(id, 0x02..=0x05) {
        return Err(Http3FrameError::ForbiddenSetting { id });
    }
    if !setting_ids.insert(id) {
        return Err(Http3FrameError::DuplicateSetting { id });
    }
    Ok(())
}

const fn is_grease_id(id: u64) -> bool {
    id >= 33 && (id - 33).is_multiple_of(31)
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

    use super::{
        parse_settings, FrameType, HeaderField, Http3FrameError, OpaqueFrame, Setting,
        SettingValue, SettingsFrame, StreamType,
    };
    use crate::quic::varint;
    #[test]
    fn setting_names_cover_registered_and_draft_ids() {
        use super::SettingName;

        let cases = [
            (0x01, SettingName::QpackMaxTableCapacity),
            (0x06, SettingName::MaxFieldSectionSize),
            (0x07, SettingName::QpackBlockedStreams),
            (0x08, SettingName::EnableConnectProtocol),
            (0x33, SettingName::H3Datagram),
            (0xff_d277, SettingName::H3DatagramDraft),
            (0x4d44, SettingName::EnableMetadata),
            (0x2b60_3742, SettingName::EnableWebTransportDraft),
            (0x2b60_3743, SettingName::WebTransportMaxSessionsDraft),
            (0x3c48_d522, SettingName::WebTransportMaxSessionsDraft),
            (0xc671_706a, SettingName::WebTransportMaxSessionsDraft),
            (0x14e9_cd29, SettingName::WebTransportMaxSessionsDraft),
            (0x2c7c_f000, SettingName::WebTransportEnabledDraft),
            (0x2b64, SettingName::WebTransportInitialMaxStreamsUniDraft),
            (0x2b65, SettingName::WebTransportInitialMaxStreamsBidiDraft),
            (0x2b61, SettingName::WebTransportInitialMaxDataDraft),
        ];

        for (id, expected) in cases {
            assert_eq!(SettingName::from_id(id), expected, "setting {id:#x}");
        }
    }

    #[test]
    fn settings_preserve_unknown_and_grease_values() {
        let mut payload = Vec::new();
        for (id, value) in [(1, 65_536), (51, 1), (64, 123), (99, 456)] {
            varint::encode(id, &mut payload).unwrap();
            varint::encode(value, &mut payload).unwrap();
        }

        let frame = parse_settings(&payload).unwrap();
        assert_eq!(
            frame.settings[0],
            Setting::try_from_wire(1, 65_536).unwrap()
        );
        assert!(frame.settings[2].is_grease());
        assert!(!frame.settings[3].is_grease());
    }

    #[test]
    fn settings_reject_duplicates_and_http2_identifiers() {
        let mut duplicate = Vec::new();
        for value in [1, 2] {
            varint::encode(1, &mut duplicate).unwrap();
            varint::encode(value, &mut duplicate).unwrap();
        }
        assert_eq!(
            parse_settings(&duplicate).unwrap_err(),
            Http3FrameError::DuplicateSetting { id: 1 }
        );
        assert_eq!(
            parse_settings(&[0x02, 0x00]).unwrap_err(),
            Http3FrameError::ForbiddenSetting { id: 2 }
        );
    }

    #[test]
    fn settings_scale_to_many_unique_ids_and_reject_a_late_duplicate() {
        const SETTING_COUNT: u64 = 4_096;
        const FIRST_ID: u64 = 1 << 40;

        let mut payload = Vec::new();
        for index in 0..SETTING_COUNT {
            varint::encode(FIRST_ID + index * 31, &mut payload).unwrap();
            varint::encode(0, &mut payload).unwrap();
        }

        let frame = parse_settings(&payload).unwrap();
        assert_eq!(frame.settings.len(), SETTING_COUNT as usize);
        assert!(frame
            .settings
            .iter()
            .enumerate()
            .all(|(index, setting)| setting.id == FIRST_ID + index as u64 * 31));

        let mut duplicate_payload = payload;
        varint::encode(FIRST_ID, &mut duplicate_payload).unwrap();
        varint::encode(0, &mut duplicate_payload).unwrap();
        assert_eq!(
            parse_settings(&duplicate_payload).unwrap_err(),
            Http3FrameError::DuplicateSetting { id: FIRST_ID }
        );

        let mut duplicate_json = serde_json::to_value(frame).unwrap();
        let first_setting = duplicate_json["settings"][0].clone();
        duplicate_json["settings"]
            .as_array_mut()
            .unwrap()
            .push(first_setting);
        assert!(serde_json::from_value::<SettingsFrame>(duplicate_json).is_err());
    }

    #[test]
    fn stream_and_setting_names_are_derived_from_ids() {
        assert!(StreamType::from_id(33).is_grease());
        assert!(serde_json::from_value::<StreamType>(json!({
            "id": 0,
            "name": "QpackEncoder"
        }))
        .is_err());
    }
    #[test]
    fn boolean_settings_are_canonical_and_reject_invalid_wire_values() {
        let mut payload = Vec::new();
        for (id, value) in [(0x08, 0), (0x33, 1), (0xff_d277, 1), (0x01, 1)] {
            varint::encode(id, &mut payload).unwrap();
            varint::encode(value, &mut payload).unwrap();
        }

        let frame = parse_settings(&payload).unwrap();
        assert_eq!(frame.settings[0].value, SettingValue::Bool(false));
        assert_eq!(frame.settings[1].value, SettingValue::Bool(true));
        assert_eq!(frame.settings[2].value, SettingValue::Bool(true));
        assert_eq!(frame.settings[3].value, SettingValue::Number(1));
        assert_eq!(
            serde_json::to_value(&frame.settings[1]).unwrap()["value"],
            json!(true)
        );

        for id in [0x08, 0x33, 0xff_d277] {
            assert_eq!(
                Setting::try_from_wire(id, 2).unwrap_err(),
                Http3FrameError::InvalidBooleanSetting { id, value: 2 }
            );
            let mut invalid = Vec::new();
            varint::encode(id, &mut invalid).unwrap();
            varint::encode(2, &mut invalid).unwrap();
            assert_eq!(
                parse_settings(&invalid).unwrap_err(),
                Http3FrameError::InvalidBooleanSetting { id, value: 2 }
            );
        }
    }

    #[test]
    fn setting_json_rejects_noncanonical_value_types() {
        for value in [
            json!({"id": 0x08, "name": "EnableConnectProtocol", "value": 1}),
            json!({"id": 0x33, "name": "H3Datagram", "value": "1"}),
            json!({"id": 0xff_d277, "name": "H3DatagramDraft", "value": 0}),
            json!({"id": 0x01, "name": "QpackMaxTableCapacity", "value": true}),
        ] {
            assert!(serde_json::from_value::<Setting>(value).is_err());
        }
    }

    #[test]
    fn frame_types_cover_registered_reserved_grease_and_other_ids() {
        let cases = [
            (0x00, FrameType::Data),
            (0x01, FrameType::Headers),
            (0x02, FrameType::Http2Reserved),
            (0x03, FrameType::CancelPush),
            (0x04, FrameType::Settings),
            (0x05, FrameType::PushPromise),
            (0x06, FrameType::Http2Reserved),
            (0x07, FrameType::GoAway),
            (0x08, FrameType::Http2Reserved),
            (0x09, FrameType::Http2Reserved),
            (0x0c, FrameType::Origin),
            (0x0d, FrameType::MaxPushId),
            (0x0f_0700, FrameType::PriorityUpdateRequest),
            (0x0f_0701, FrameType::PriorityUpdatePush),
            (0x21, FrameType::Grease),
            (0x10, FrameType::Other),
        ];

        for (id, expected) in cases {
            assert_eq!(FrameType::from_id(id), expected, "frame {id:#x}");
        }
    }

    #[test]
    fn opaque_frame_json_validates_its_semantic_type() {
        let frame: OpaqueFrame = serde_json::from_value(json!({
            "frame_type": "Data",
            "type_id": 0,
            "length": 0,
            "payload": ""
        }))
        .unwrap();
        assert_eq!(frame.frame_type, FrameType::Data);

        assert!(serde_json::from_value::<OpaqueFrame>(json!({
            "frame_type": "Grease",
            "type_id": 0,
            "length": 0,
            "payload": ""
        }))
        .is_err());
        assert!(serde_json::from_value::<OpaqueFrame>(json!({
            "frame_type": "Http2Reserved",
            "type_id": 2,
            "length": 0,
            "payload": ""
        }))
        .is_err());
    }

    #[test]
    fn h3_wire_varints_roundtrip_as_lossless_json_strings() {
        const UNSAFE_INTEGER: u64 = 9_007_199_254_740_992;

        let stream_type = StreamType::from_id(UNSAFE_INTEGER);
        let stream_json = serde_json::to_value(stream_type).unwrap();
        assert_eq!(stream_json["id"], json!(UNSAFE_INTEGER.to_string()));
        assert_eq!(
            serde_json::from_value::<StreamType>(stream_json).unwrap(),
            stream_type
        );

        let setting = Setting::try_from_wire(UNSAFE_INTEGER, UNSAFE_INTEGER).unwrap();
        let setting_json = serde_json::to_value(&setting).unwrap();
        assert_eq!(setting_json["id"], json!(UNSAFE_INTEGER.to_string()));
        assert_eq!(setting_json["value"], json!(UNSAFE_INTEGER.to_string()));
        assert_eq!(
            serde_json::from_value::<Setting>(setting_json).unwrap(),
            setting
        );

        let opaque_json = json!({
            "frame_type": "Other",
            "type_id": UNSAFE_INTEGER.to_string(),
            "length": 0,
            "payload": ""
        });
        let opaque: OpaqueFrame = serde_json::from_value(opaque_json).unwrap();
        let serialized = serde_json::to_value(&opaque).unwrap();
        assert_eq!(serialized["type_id"], json!(UNSAFE_INTEGER.to_string()));
        assert_eq!(
            serde_json::from_value::<OpaqueFrame>(serialized).unwrap(),
            opaque
        );
    }

    #[test]
    fn header_bytes_roundtrip_without_utf8_loss() {
        let field = HeaderField {
            name: b"x-bytes".as_slice().into(),
            value: [0xff, 0x00].as_slice().into(),
        };
        let json = serde_json::to_value(&field).unwrap();
        let restored: HeaderField = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(restored, field);
        assert_eq!(json, json!({"name": "x-bytes", "value": {"hex": "ff00"}}));
    }
}
