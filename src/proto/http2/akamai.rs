use std::fmt::Write;

use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};

use super::frame::Frame;

/// The Akamai HTTP/2 fingerprint and its MD5 digest.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AkamaiFingerprint {
    /// The unhashed SETTINGS, window, PRIORITY, and pseudo-field-order groups.
    pub fingerprint: Box<str>,

    /// The lowercase hexadecimal MD5 digest used by compatible fingerprint APIs.
    pub hash: Box<str>,
}

impl AkamaiFingerprint {
    /// Computes a fingerprint from decoded frames in their original wire order.
    pub fn from_frames<'a>(frames: impl IntoIterator<Item = &'a Frame>) -> Option<Self> {
        let mut frames = frames.into_iter().peekable();
        frames.peek()?;

        let fingerprint = compute_fingerprint(frames);
        let hash = compute_hash(&fingerprint);

        Some(Self {
            fingerprint: fingerprint.into_boxed_str(),
            hash,
        })
    }
}

fn compute_hash(fingerprint: &str) -> Box<str> {
    let hash = md5::compute(fingerprint);
    hex_encode(hash.as_slice()).into_boxed_str()
}

fn compute_fingerprint<'a>(frames: impl IntoIterator<Item = &'a Frame>) -> String {
    let mut setting_group = String::new();
    let mut window_update_group = None;
    let mut priority_group = String::new();
    let mut headers_group = String::new();
    let mut has_initial_settings = false;
    let mut headers_count = 0usize;

    for frame in frames {
        match frame {
            Frame::Settings(frame) if !has_initial_settings && !frame.is_ack() => {
                has_initial_settings = true;
                for setting in &frame.settings {
                    let (id, value) = setting.value();
                    if !setting_group.is_empty() {
                        setting_group.push(';');
                    }
                    let _ = write!(setting_group, "{id}:{value}");
                }
            }
            Frame::Settings(_) => {}
            Frame::WindowUpdate(frame) if frame.stream_id == 0 && window_update_group.is_none() => {
                window_update_group = Some(frame.increment);
            }
            Frame::WindowUpdate(_) => {}
            Frame::Priority(frame) => {
                if !priority_group.is_empty() {
                    priority_group.push(',');
                }
                let _ = write!(
                    priority_group,
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    frame.priority.exclusive,
                    frame.priority.depends_on,
                    frame.priority.weight
                );
            }
            Frame::Headers(frame) => {
                if headers_count > 0 {
                    headers_group.push(';');
                }
                headers_count += 1;

                let mut pseudo_count = 0usize;
                for header in &frame.headers {
                    let Some(short_name) = header
                        .name
                        .strip_prefix(b":")
                        .and_then(|name| std::str::from_utf8(name).ok())
                        .and_then(|name| name.chars().next())
                    else {
                        continue;
                    };
                    if pseudo_count > 0 {
                        headers_group.push(',');
                    }
                    pseudo_count += 1;
                    headers_group.push(short_name);
                }
            }
            Frame::Unknown(value) => {
                tracing::trace!("Unknown http2 frame: {:?}", value);
            }
        }
    }

    let window_update_group = window_update_group
        .map(|window_update| window_update.to_string())
        .unwrap_or_else(|| "00".to_owned());
    let priority_group = (!priority_group.is_empty()).then_some(priority_group);

    format!(
        "{}|{}|{}|{}",
        setting_group,
        window_update_group,
        priority_group.as_deref().unwrap_or("0"),
        headers_group
    )
}

#[cfg(test)]
mod tests {
    use super::{super::frame, AkamaiFingerprint};

    #[test]
    fn akamai_fingerprint_matches_frame_vector() {
        let mut frames = Vec::new();
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0xc8,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(
            fingerprint.fingerprint.as_ref(),
            "1:65536;3:1000|983041|3:0:0:201|"
        );
        assert_eq!(
            fingerprint.hash.as_ref(),
            "acc97607debc130f466a9f588ee3a2ba"
        );
    }

    #[test]
    fn akamai_fingerprint_is_none_without_frames() {
        let frames: Vec<frame::Frame> = Vec::new();

        assert!(AkamaiFingerprint::from_frames(&frames).is_none());
    }

    #[test]
    fn akamai_fingerprint_ignores_headers_priority_values() {
        let mut frames = Vec::new();
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x05, 0x01, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc8,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint.as_ref(), "1:65536;3:1000|983041|0|");
        assert_eq!(
            fingerprint.hash.as_ref(),
            "fc449c09e9d86239792bc6798d859012"
        );
    }

    #[test]
    fn akamai_fingerprint_uses_initial_settings_and_connection_window_update() {
        let mut frames = Vec::new();
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );
        push_frame(
            &mut frames,
            &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x01,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            ],
        );
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint.as_ref(), "1:65536;3:1000|3|0|");
    }

    #[test]
    fn akamai_fingerprint_uses_zero_marker_without_window_update() {
        let mut frames = Vec::new();
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint.as_ref(), "1:65536;3:1000|00|0|");
    }

    #[test]
    fn akamai_fingerprint_survives_frame_json_roundtrip() {
        let mut frames = Vec::new();
        push_frame(
            &mut frames,
            &[
                0x00, 0x00, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x84,
            ],
        );
        let expected = AkamaiFingerprint::from_frames(&frames).unwrap();
        assert_eq!(expected.fingerprint.as_ref(), "|00|0|m,p");

        let json = serde_json::to_vec(&frames).unwrap();
        let restored: Vec<frame::Frame> = serde_json::from_slice(&json).unwrap();
        let actual = AkamaiFingerprint::from_frames(&restored).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), json);
    }

    fn push_frame(frames: &mut Vec<frame::Frame>, data: &[u8]) {
        let frame = frame::FrameParser::default()
            .parse(data)
            .unwrap()
            .into_frame()
            .unwrap();
        frames.push(frame);
    }
}
