use serde::{Deserialize, Serialize};

use super::{error::Error, FrameType};

/// A decoded parameter from an HTTP/2 SETTINGS frame.
///
/// Every parameter uses a 16-bit identifier and a 32-bit wire value. See
/// [RFC 9113, Section 6.5.1](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.1).
#[derive(Debug, Serialize)]
pub enum Setting {
    /// `SETTINGS_HEADER_TABLE_SIZE` (`0x01`) controls the HPACK table limit.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    HeaderTableSize { id: u16, value: SettingValue },

    /// `SETTINGS_ENABLE_PUSH` (`0x02`) enables or disables server push.
    /// Its value must be `0` or `1`. See
    /// [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    EnablePush { id: u16, value: SettingValue },

    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (`0x03`) advises a stream limit.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    MaxConcurrentStreams { id: u16, value: SettingValue },

    /// `SETTINGS_INITIAL_WINDOW_SIZE` (`0x04`) sets the initial stream window.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    InitialWindowSize { id: u16, value: SettingValue },

    /// `SETTINGS_MAX_FRAME_SIZE` (`0x05`) advertises the largest accepted frame.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    MaxFrameSize { id: u16, value: SettingValue },

    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (`0x06`) advises a field-section limit.
    /// See [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
    MaxHeaderListSize { id: u16, value: SettingValue },

    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x08`) enables Extended CONNECT.
    /// Its value must be `0` or `1`. See
    /// [RFC 8441, Section 3](https://www.rfc-editor.org/rfc/rfc8441#section-3).
    EnableConnectProtocol { id: u16, value: SettingValue },

    /// `SETTINGS_NO_RFC7540_PRIORITIES` (`0x09`) disables legacy priorities.
    /// Its value must be `0` or `1`. See
    /// [RFC 9218, Section 2.1](https://www.rfc-editor.org/rfc/rfc9218#section-2.1).
    NoRfc7540Priorities { id: u16, value: SettingValue },

    /// An unrecognized setting retained for analysis. HTTP/2 recipients ignore
    /// unsupported identifiers as required by
    /// [RFC 9113, Section 6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2).
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

/// A decoded HTTP/2 SETTINGS frame.
///
/// See [RFC 9113, Section 6.5](https://www.rfc-editor.org/rfc/rfc9113#section-6.5).
#[derive(Debug, Serialize)]
pub struct SettingsFrame {
    /// The frame type, always [`FrameType::Settings`].
    pub frame_type: FrameType,

    /// The connection-level stream identifier, which must be zero.
    pub stream_id: u32,

    /// The payload length, excluding the 9-byte frame header.
    pub length: usize,

    /// Settings in their original wire order.
    pub settings: Vec<Setting>,
}

// ==== impl Setting ====

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

impl TryFrom<(u8, u32, &[u8])> for SettingsFrame {
    type Error = Error;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id != 0 {
            return Err(Error::InvalidStreamId);
        }

        // SETTINGS defines only ACK (0x01); unknown flag bits are ignored.
        // See: <https://www.rfc-editor.org/rfc/rfc9113#section-6.5>
        let is_ack = flags & 0x01 != 0;
        if is_ack && !payload.is_empty() {
            tracing::debug!("Invalid SETTINGS frame size: {}", payload.len());
            return Err(Error::BadFrameSize);
        }

        if payload.len() % 6 != 0 {
            tracing::debug!("Invalid SETTINGS frame size: {}", payload.len());
            return Err(Error::BadFrameSize);
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
            settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Setting, SettingsFrame};
    use crate::http2::frame::error::Error;

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
        assert!(settings.settings.is_empty());
        assert!(ack.settings.is_empty());
        assert_eq!(
            serde_json::to_value(ack).unwrap(),
            json!({
                "frame_type": "Settings",
                "stream_id": 0,
                "length": 0,
                "settings": []
            })
        );
    }

    #[test]
    fn settings_reject_invalid_frame_boundaries() {
        assert_eq!(
            SettingsFrame::try_from((0x01, 0, &[0; 6][..])).unwrap_err(),
            Error::BadFrameSize
        );
        assert_eq!(
            SettingsFrame::try_from((0x00, 0, &[0; 5][..])).unwrap_err(),
            Error::BadFrameSize
        );
        assert_eq!(
            SettingsFrame::try_from((0x00, 1, &[][..])).unwrap_err(),
            Error::InvalidStreamId
        );
    }
}
