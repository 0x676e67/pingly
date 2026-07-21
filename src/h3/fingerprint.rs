use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{HeaderField, HeadersFrame, Setting, SettingsFrame};

/// An HTTP/3 SETTINGS and request pseudo-field-order fingerprint.
///
/// SETTINGS use normalized `id:value` pairs followed by the request pseudo-field order, such as
/// `|m,a,s,p`. HTTP/3 requires pseudo-fields to precede regular fields, and their captured order is
/// retained here. See [RFC 9114, Section 4.2](https://www.rfc-editor.org/rfc/rfc9114#section-4.2)
/// and [Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http3Fingerprint {
    /// Normalized SETTINGS and request pseudo-field-order groups.
    pub h3_text: Box<str>,

    /// Lowercase MD5 digest of [`Self::h3_text`].
    pub h3_text_hash: Box<str>,
}

impl Http3Fingerprint {
    /// Computes the fingerprint from the client control-stream SETTINGS and request HEADERS frames.
    pub fn from_frames(settings: &SettingsFrame, headers: &HeadersFrame) -> Self {
        let mut normalized_settings = settings.settings.iter().collect::<Vec<_>>();
        normalized_settings.sort_by_key(|setting| (setting.is_grease(), setting.id));
        let mut h3_text = settings_text(normalized_settings);
        h3_text.push('|');
        push_pseudo_header_order(&mut h3_text, &headers.headers);

        Self {
            h3_text_hash: md5_hash(&h3_text),
            h3_text: h3_text.into_boxed_str(),
        }
    }
}

fn settings_text<'a>(settings: impl IntoIterator<Item = &'a Setting>) -> String {
    let mut output = String::new();
    for setting in settings {
        push_separator(&mut output);
        if setting.is_grease() {
            output.push_str("GREASE");
        } else {
            let _ = write!(output, "{}:{}", setting.id, setting.wire_value());
        }
    }
    output
}

fn push_pseudo_header_order(output: &mut String, headers: &[HeaderField]) {
    let group_start = output.len();

    for header in headers {
        let Some(short_name) = header
            .name
            .strip_prefix(b":")
            .and_then(|name| std::str::from_utf8(name).ok())
            .and_then(|name| name.chars().next())
        else {
            continue;
        };

        if output.len() > group_start {
            output.push(',');
        }
        output.push(short_name);
    }
}

fn push_separator(output: &mut String) {
    if !output.is_empty() {
        output.push(';');
    }
}

fn md5_hash(value: &str) -> Box<str> {
    hex::encode(md5::compute(value).as_slice()).into_boxed_str()
}

#[cfg(test)]
mod tests {
    use super::Http3Fingerprint;
    use crate::h3::{FrameType, HeaderField, HeadersFrame, Setting, SettingsFrame};

    #[test]
    fn fingerprint_normalizes_settings_and_appends_pseudo_header_order() {
        let settings = SettingsFrame {
            frame_type: FrameType::Settings,
            length: 0,
            settings: vec![
                Setting::try_from_wire(51, 1).unwrap(),
                Setting::try_from_wire(39_484_089_984, 2_235_535_436).unwrap(),
                Setting::try_from_wire(7, 100).unwrap(),
                Setting::try_from_wire(1, 65_536).unwrap(),
            ],
        };
        let headers = HeadersFrame {
            frame_type: FrameType::Headers,
            length: 0,
            headers: vec![
                header(b":method"),
                header(b":authority"),
                header(b":scheme"),
                header(b":path"),
                header(b"user-agent"),
            ],
        };

        let fingerprint = Http3Fingerprint::from_frames(&settings, &headers);

        assert_eq!(
            fingerprint.h3_text.as_ref(),
            "1:65536;7:100;51:1;GREASE|m,a,s,p"
        );
        assert_eq!(
            fingerprint.h3_text_hash.as_ref(),
            "b4eb54404dffe4bd2f75bd24785bb476"
        );
    }

    fn header(name: &[u8]) -> HeaderField {
        HeaderField {
            name: name.into(),
            value: Box::default(),
        }
    }
}
