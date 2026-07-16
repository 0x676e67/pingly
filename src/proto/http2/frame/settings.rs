use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

/// A decoded parameter from an HTTP/2 SETTINGS frame.
///
/// Every parameter uses a 16-bit identifier and a 32-bit wire value. See
/// [RFC 9113, Section 6.5.1](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.1).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SettingRepr")]
pub enum Setting {
    /// `SETTINGS_HEADER_TABLE_SIZE` (`0x01`) controls the HPACK table limit.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    HeaderTableSize {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_ENABLE_PUSH` (`0x02`) enables or disables server push.
    /// Its value must be `0` or `1`. See
    /// [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    EnablePush {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (`0x03`) advises a stream limit.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    MaxConcurrentStreams {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_INITIAL_WINDOW_SIZE` (`0x04`) sets the initial stream window.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    InitialWindowSize {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_MAX_FRAME_SIZE` (`0x05`) advertises the largest accepted frame.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    MaxFrameSize {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (`0x06`) advises a field-section limit.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    MaxHeaderListSize {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x08`) enables Extended CONNECT.
    /// Its value must be `0` or `1`. See
    /// [RFC 8441, Section 3](https://www.rfc-editor.org/rfc/rfc8441#section-3).
    EnableConnectProtocol {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// `SETTINGS_NO_RFC7540_PRIORITIES` (`0x09`) disables legacy priorities.
    /// Its value must be `0` or `1`. See
    /// [RFC 9218, Section 2.1](https://www.rfc-editor.org/rfc/rfc9218#section-2.1).
    NoRfc7540Priorities {
        /// The numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The 32-bit SETTINGS value.
        value: SettingValue,
    },

    /// An unrecognized setting retained for analysis. HTTP/2 recipients ignore
    /// unsupported identifiers as required by
    /// [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    Unknown {
        /// The unsupported numeric SETTINGS identifier observed on the wire.
        id: u16,

        /// The unrecognized setting's 32-bit value.
        value: SettingValue,
    },
}

/// Deserialization shape used to validate setting IDs and value representations.
#[derive(Deserialize)]
enum SettingRepr {
    /// Saved SETTINGS_HEADER_TABLE_SIZE value.
    HeaderTableSize { id: u16, value: SettingValue },

    /// Saved SETTINGS_ENABLE_PUSH value.
    EnablePush { id: u16, value: SettingValue },

    /// Saved SETTINGS_MAX_CONCURRENT_STREAMS value.
    MaxConcurrentStreams { id: u16, value: SettingValue },

    /// Saved SETTINGS_INITIAL_WINDOW_SIZE value.
    InitialWindowSize { id: u16, value: SettingValue },

    /// Saved SETTINGS_MAX_FRAME_SIZE value.
    MaxFrameSize { id: u16, value: SettingValue },

    /// Saved SETTINGS_MAX_HEADER_LIST_SIZE value.
    MaxHeaderListSize { id: u16, value: SettingValue },

    /// Saved SETTINGS_ENABLE_CONNECT_PROTOCOL value.
    EnableConnectProtocol { id: u16, value: SettingValue },

    /// Saved SETTINGS_NO_RFC7540_PRIORITIES value.
    NoRfc7540Priorities { id: u16, value: SettingValue },

    /// Saved unsupported setting.
    Unknown { id: u16, value: SettingValue },
}

/// The JSON representation of an HTTP/2 setting's 32-bit wire value.
///
/// Ordinary settings remain numbers. Settings whose specifications restrict
/// values to `0` and `1` use booleans when the wire value is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SettingValue {
    /// A numeric setting or an invalid boolean-setting value retained verbatim.
    /// The wire field is defined by
    /// [RFC 9113, Section 6.5.1](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.1).
    Number(u32),

    /// A valid `0` or `1` setting exposed as `false` or `true` in JSON.
    /// Boolean settings are defined by
    /// [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2),
    /// [RFC 8441, Section 3](https://www.rfc-editor.org/rfc/rfc8441#section-3), and
    /// [RFC 9218, Section 2.1](https://www.rfc-editor.org/rfc/rfc9218#section-2.1).
    Bool(bool),
}

/// Deserialization shape used to validate a saved SETTINGS frame.
#[derive(Deserialize)]
struct SettingsFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Connection-level stream identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Saved ACK state.
    #[serde(default, rename = "ack")]
    is_ack: bool,

    /// Saved settings in wire order.
    settings: Vec<Setting>,
}

/// A decoded HTTP/2 SETTINGS frame.
///
/// See [RFC 9113, Section 6.5](https://www.rfc-editor.org/rfc/rfc9113#section-6.5).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SettingsFrameRepr")]
pub struct SettingsFrame {
    /// The frame type, always [`FrameType::Settings`].
    pub frame_type: FrameType,

    /// The connection-level stream identifier, which must be zero.
    pub stream_id: u32,

    /// The payload length, excluding the 9-byte frame header.
    pub length: usize,

    /// Whether this frame acknowledges the peer's settings.
    #[serde(default, rename = "ack", skip_serializing_if = "is_false")]
    pub(crate) is_ack: bool,

    /// Settings in their original wire order.
    pub settings: Vec<Setting>,
}

// ==== impl Setting ====

impl TryFrom<SettingRepr> for Setting {
    type Error = String;

    fn try_from(repr: SettingRepr) -> Result<Self, Self::Error> {
        macro_rules! known {
            ($variant:ident, $id:expr, $value:expr, $expected:expr, $boolean:expr) => {{
                let value = validate_setting_value($id, $value, $expected, $boolean)?;
                Ok(Self::$variant { id: $id, value })
            }};
        }

        match repr {
            SettingRepr::HeaderTableSize { id, value } => {
                known!(HeaderTableSize, id, value, 1, false)
            }
            SettingRepr::EnablePush { id, value } => known!(EnablePush, id, value, 2, true),
            SettingRepr::MaxConcurrentStreams { id, value } => {
                known!(MaxConcurrentStreams, id, value, 3, false)
            }
            SettingRepr::InitialWindowSize { id, value } => {
                known!(InitialWindowSize, id, value, 4, false)
            }
            SettingRepr::MaxFrameSize { id, value } => {
                known!(MaxFrameSize, id, value, 5, false)
            }
            SettingRepr::MaxHeaderListSize { id, value } => {
                known!(MaxHeaderListSize, id, value, 6, false)
            }
            SettingRepr::EnableConnectProtocol { id, value } => {
                known!(EnableConnectProtocol, id, value, 8, true)
            }
            SettingRepr::NoRfc7540Priorities { id, value } => {
                known!(NoRfc7540Priorities, id, value, 9, true)
            }
            SettingRepr::Unknown { id, value } => {
                if matches!(id, 1..=6 | 8 | 9) {
                    return Err(format!("known SETTINGS identifier {id} cannot use Unknown"));
                }
                if matches!(value, SettingValue::Bool(_)) {
                    return Err("unknown SETTINGS values must use their numeric wire form".into());
                }
                Ok(Self::Unknown { id, value })
            }
        }
    }
}

fn validate_setting_value(
    id: u16,
    value: SettingValue,
    expected_id: u16,
    boolean: bool,
) -> Result<SettingValue, String> {
    if id != expected_id {
        return Err(format!(
            "SETTINGS variant expects identifier {expected_id}, got {id}"
        ));
    }

    match (boolean, value) {
        (false, SettingValue::Bool(_)) => {
            Err(format!("SETTINGS identifier {id} requires a numeric value"))
        }
        (true, SettingValue::Number(0 | 1)) => Err(format!(
            "SETTINGS identifier {id} must serialize valid 0/1 values as booleans"
        )),
        _ => Ok(value),
    }
}

impl From<(u16, u32)> for Setting {
    fn from((id, value): (u16, u32)) -> Self {
        match id {
            1 => Setting::HeaderTableSize {
                id,
                value: SettingValue::Number(value),
            },
            2 => Setting::EnablePush {
                id,
                value: SettingValue::from_bool_wire_value(value),
            },
            3 => Setting::MaxConcurrentStreams {
                id,
                value: SettingValue::Number(value),
            },
            4 => Setting::InitialWindowSize {
                id,
                value: SettingValue::Number(value),
            },
            5 => Setting::MaxFrameSize {
                id,
                value: SettingValue::Number(value),
            },
            6 => Setting::MaxHeaderListSize {
                id,
                value: SettingValue::Number(value),
            },
            8 => Setting::EnableConnectProtocol {
                id,
                value: SettingValue::from_bool_wire_value(value),
            },
            9 => Setting::NoRfc7540Priorities {
                id,
                value: SettingValue::from_bool_wire_value(value),
            },
            _ => Setting::Unknown {
                id,
                value: SettingValue::Number(value),
            },
        }
    }
}

// ==== impl SettingValue ====

impl SettingValue {
    // These three HTTP/2 settings use 0 and 1 as boolean values:
    // <https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2>,
    // <https://www.rfc-editor.org/rfc/rfc8441#section-3>, and
    // <https://www.rfc-editor.org/rfc/rfc9218#section-2.1>.
    fn from_bool_wire_value(value: u32) -> Self {
        match value {
            0 => Self::Bool(false),
            1 => Self::Bool(true),
            _ => Self::Number(value),
        }
    }

    const fn to_wire_value(self) -> u32 {
        match self {
            Self::Number(value) => value,
            Self::Bool(false) => 0,
            Self::Bool(true) => 1,
        }
    }
}

impl Setting {
    /// Returns the setting identifier and original 32-bit wire value.
    ///
    /// This numeric form is used by the Akamai fingerprint. See the SETTINGS
    /// wire format in
    /// [RFC 9113, Section 6.5.1](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.1).
    pub fn value(&self) -> (u16, u32) {
        match self {
            Setting::HeaderTableSize { id, value } => (*id, value.to_wire_value()),
            Setting::EnablePush { id, value } => (*id, value.to_wire_value()),
            Setting::MaxConcurrentStreams { id, value } => (*id, value.to_wire_value()),
            Setting::InitialWindowSize { id, value } => (*id, value.to_wire_value()),
            Setting::MaxFrameSize { id, value } => (*id, value.to_wire_value()),
            Setting::MaxHeaderListSize { id, value } => (*id, value.to_wire_value()),
            Setting::EnableConnectProtocol { id, value } => (*id, value.to_wire_value()),
            Setting::NoRfc7540Priorities { id, value } => (*id, value.to_wire_value()),
            Setting::Unknown { id, value } => (*id, value.to_wire_value()),
        }
    }
}

// ==== impl SettingsFrame ====

impl SettingsFrame {
    /// Returns whether this SETTINGS frame carries the ACK flag.
    #[inline]
    pub const fn is_ack(&self) -> bool {
        self.is_ack
    }
}

impl TryFrom<SettingsFrameRepr> for SettingsFrame {
    type Error = &'static str;

    fn try_from(repr: SettingsFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::Settings {
            return Err("SETTINGS frame_type must be Settings");
        }
        if repr.stream_id != 0 {
            return Err("SETTINGS stream_id must be zero");
        }
        if repr.length > 0x00ff_ffff {
            return Err("SETTINGS payload length exceeds the HTTP/2 frame limit");
        }

        let expected_length = repr
            .settings
            .len()
            .checked_mul(6)
            .ok_or("SETTINGS payload length overflow")?;
        if repr.is_ack {
            if repr.length != 0 || !repr.settings.is_empty() {
                return Err("SETTINGS ACK frames must have an empty payload");
            }
        } else if repr.length != expected_length {
            return Err("SETTINGS length does not match its parameter list");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            is_ack: repr.is_ack,
            settings: repr.settings,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for SettingsFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id != 0 {
            return Err(FrameError::InvalidStreamId);
        }

        // SETTINGS defines only ACK (0x01); unknown flag bits are ignored.
        // See: <https://www.rfc-editor.org/rfc/rfc9113#section-6.5>
        let is_ack = flags & 0x01 != 0;
        if is_ack && !payload.is_empty() {
            tracing::debug!("Invalid SETTINGS frame size: {}", payload.len());
            return Err(FrameError::BadFrameSize);
        }

        if payload.len() % 6 != 0 {
            tracing::debug!("Invalid SETTINGS frame size: {}", payload.len());
            return Err(FrameError::BadFrameSize);
        }

        let settings = payload
            .chunks_exact(6)
            .map(|data| {
                let id = u16::from_be_bytes([data[0], data[1]]);
                let value = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                Setting::from((id, value))
            })
            .collect();

        Ok(SettingsFrame {
            frame_type: FrameType::Settings,
            stream_id,
            length: payload.len(),
            is_ack,
            settings,
        })
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Setting, SettingsFrame};
    use crate::proto::http2::frame::FrameError;

    #[test]
    fn settings_serialize_numeric_and_boolean_values() {
        let settings = [
            Setting::from((1, 65_536)),
            Setting::from((2, 0)),
            Setting::from((4, 6_291_456)),
            Setting::from((6, 262_144)),
            Setting::from((8, 1)),
            Setting::from((9, 0)),
        ];

        assert_eq!(
            serde_json::to_value(settings).unwrap(),
            json!([
                {"HeaderTableSize": {"id": 1, "value": 65536}},
                {"EnablePush": {"id": 2, "value": false}},
                {"InitialWindowSize": {"id": 4, "value": 6291456}},
                {"MaxHeaderListSize": {"id": 6, "value": 262144}},
                {"EnableConnectProtocol": {"id": 8, "value": true}},
                {"NoRfc7540Priorities": {"id": 9, "value": false}}
            ])
        );
    }

    #[test]
    fn invalid_boolean_setting_preserves_the_wire_value() {
        let setting = Setting::from((2, 2));

        assert_eq!(setting.value(), (2, 2));
        assert_eq!(
            serde_json::to_value(setting).unwrap(),
            json!({"EnablePush": {"id": 2, "value": 2}})
        );
    }

    #[test]
    fn empty_settings_and_ack_frames_are_valid() {
        let settings = SettingsFrame::try_from((0x00, 0, &[][..])).unwrap();
        let ack = SettingsFrame::try_from((0x01, 0, &[][..])).unwrap();

        assert!(settings.settings.is_empty());
        assert!(ack.settings.is_empty());
        assert!(!settings.is_ack());
        assert!(ack.is_ack());
        let json = serde_json::to_value(&ack).unwrap();
        assert_eq!(
            json,
            json!({
                "frame_type": "Settings",
                "stream_id": 0,
                "length": 0,
                "ack": true,
                "settings": []
            })
        );

        let restored: SettingsFrame = serde_json::from_value(json).unwrap();
        assert_eq!(restored, ack);
    }

    #[test]
    fn settings_reject_invalid_frame_boundaries() {
        assert_eq!(
            SettingsFrame::try_from((0x01, 0, &[0; 6][..])).unwrap_err(),
            FrameError::BadFrameSize
        );
        assert_eq!(
            SettingsFrame::try_from((0x00, 0, &[0; 5][..])).unwrap_err(),
            FrameError::BadFrameSize
        );
        assert_eq!(
            SettingsFrame::try_from((0x00, 1, &[][..])).unwrap_err(),
            FrameError::InvalidStreamId
        );
    }

    #[test]
    fn settings_deserialization_rejects_noncanonical_states() {
        assert!(serde_json::from_value::<Setting>(json!({
            "HeaderTableSize": {"id": 2, "value": 65536}
        }))
        .is_err());
        assert!(serde_json::from_value::<Setting>(json!({
            "EnablePush": {"id": 2, "value": 0}
        }))
        .is_err());
        assert!(serde_json::from_value::<SettingsFrame>(json!({
            "frame_type": "Settings",
            "stream_id": 0,
            "length": 6,
            "settings": []
        }))
        .is_err());
    }
}
