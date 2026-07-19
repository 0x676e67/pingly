use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::Setting;

/// An HTTP/3 SETTINGS fingerprint and its order-normalized form.
///
/// The source text follows ScrapFly's `id:value` SETTINGS format while preserving wire order.
/// See [RFC 9114, Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http3Fingerprint {
    /// Client SETTINGS as numeric `id:value` pairs in their original wire order.
    pub h3_text: Box<str>,

    /// Lowercase MD5 digest of [`Self::h3_text`].
    pub h3_text_hash: Box<str>,

    /// SETTINGS sorted by numeric identifier, with random GREASE entries normalized.
    pub normalized_h3_text: Box<str>,

    /// Lowercase MD5 digest of [`Self::normalized_h3_text`].
    pub normalized_h3_text_hash: Box<str>,
}

impl Http3Fingerprint {
    /// Computes raw and normalized forms from a client SETTINGS frame.
    pub fn from_settings(settings: &[Setting]) -> Self {
        let h3_text = settings_text(settings.iter(), false);

        let mut normalized_settings = settings.iter().collect::<Vec<_>>();
        normalized_settings.sort_by_key(|setting| (setting.is_grease(), setting.id));
        let normalized_h3_text = settings_text(normalized_settings, true);

        Self {
            h3_text_hash: md5_hash(&h3_text),
            h3_text: h3_text.into_boxed_str(),
            normalized_h3_text_hash: md5_hash(&normalized_h3_text),
            normalized_h3_text: normalized_h3_text.into_boxed_str(),
        }
    }
}

fn settings_text<'a>(
    settings: impl IntoIterator<Item = &'a Setting>,
    normalize_grease: bool,
) -> String {
    let mut output = String::new();
    for setting in settings {
        push_separator(&mut output);
        if normalize_grease && setting.is_grease() {
            output.push_str("GREASE");
        } else {
            let _ = write!(output, "{}:{}", setting.id, setting.wire_value());
        }
    }
    output
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
    use crate::h3::Setting;

    #[test]
    fn fingerprint_matches_the_scrapfly_settings_format() {
        let settings = [
            Setting::try_from_wire(1, 65_536).unwrap(),
            Setting::try_from_wire(7, 100).unwrap(),
            Setting::try_from_wire(51, 1).unwrap(),
            Setting::try_from_wire(39_484_089_984, 2_235_535_436).unwrap(),
        ];

        let fingerprint = Http3Fingerprint::from_settings(&settings);

        assert_eq!(
            fingerprint.h3_text.as_ref(),
            "1:65536;7:100;51:1;39484089984:2235535436"
        );
        assert_eq!(
            fingerprint.h3_text_hash.as_ref(),
            "3ea2ceb1247f05496538d350915beeb6"
        );
        assert_eq!(
            fingerprint.normalized_h3_text.as_ref(),
            "1:65536;7:100;51:1;GREASE"
        );
        assert_eq!(
            fingerprint.normalized_h3_text_hash.as_ref(),
            "f4bfa085ff8b171d48c081102c325a2e"
        );
    }
}
