use crate::encoding::hex_encode;

use super::{frame::Frame, Http2Frame};

pub(crate) struct AkamaiFingerprint {
    pub(crate) fingerprint: String,
    pub(crate) hash: String,
}

impl AkamaiFingerprint {
    pub(crate) fn from_frames(sent_frames: &Http2Frame) -> Option<Self> {
        if sent_frames.is_empty() {
            return None;
        }

        let fingerprint = compute_fingerprint(sent_frames);
        let hash = compute_hash(&fingerprint);

        Some(Self { fingerprint, hash })
    }
}

fn compute_hash(fingerprint: &str) -> String {
    let hash = md5::compute(fingerprint);
    hex_encode(hash.as_slice())
}

fn compute_fingerprint(sent_frames: &Http2Frame) -> String {
    let mut setting_group = Vec::new();
    let mut window_update_group = None;
    let mut priority_group = None;
    let mut headers_group = Vec::with_capacity(4);
    let mut has_initial_settings = false;

    for (_, frame) in sent_frames.iter() {
        match frame {
            Frame::Settings(frame) if !has_initial_settings && !frame.is_ack() => {
                has_initial_settings = true;
                for setting in &frame.settings {
                    let (id, value) = setting.value();
                    setting_group.push(format!("{id}:{value}"));
                }
            }
            Frame::Settings(_) => {}
            Frame::WindowUpdate(frame) if frame.stream_id == 0 && window_update_group.is_none() => {
                window_update_group = Some(frame.increment);
            }
            Frame::WindowUpdate(_) => {}
            Frame::Priority(frame) => {
                let priority_group = priority_group.get_or_insert_with(Vec::new);
                priority_group.push(format!(
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    frame.priority.exclusive,
                    frame.priority.depends_on,
                    frame.priority.weight
                ));
            }
            Frame::Headers(frame) => {
                headers_group.push(
                    frame
                        .pseudo_headers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            Frame::Unknown(value) => {
                tracing::trace!("Unknown http2 frame: {:?}", value);
            }
        }
    }

    let window_update_group = window_update_group
        .map(|window_update| window_update.to_string())
        .unwrap_or_else(|| "00".to_owned());
    let priority_group = priority_group
        .map(|priority| priority.join(","))
        .unwrap_or_else(|| "0".to_owned());

    format!(
        "{}|{}|{}|{}",
        setting_group.join(";"),
        window_update_group,
        priority_group,
        headers_group.join(";")
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{super::frame, AkamaiFingerprint, Http2Frame};

    #[test]
    fn akamai_fingerprint_matches_frame_vector() {
        let frames = Arc::new(boxcar::Vec::new());
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0xc8,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint, "1:65536;3:1000|983041|3:0:0:201|");
        assert_eq!(fingerprint.hash, "acc97607debc130f466a9f588ee3a2ba");
    }

    #[test]
    fn akamai_fingerprint_is_none_without_frames() {
        let frames = Arc::new(boxcar::Vec::new());

        assert!(AkamaiFingerprint::from_frames(&frames).is_none());
    }

    #[test]
    fn akamai_fingerprint_ignores_headers_priority_values() {
        let frames = Arc::new(boxcar::Vec::new());
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x05, 0x01, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc8,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint, "1:65536;3:1000|983041|0|");
        assert_eq!(fingerprint.hash, "fc449c09e9d86239792bc6798d859012");
    }

    #[test]
    fn akamai_fingerprint_uses_initial_settings_and_connection_window_update() {
        let frames = Arc::new(boxcar::Vec::new());
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );
        push_frame(
            &frames,
            &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x01,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            ],
        );
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint, "1:65536;3:1000|3|0|");
    }

    #[test]
    fn akamai_fingerprint_uses_zero_marker_without_window_update() {
        let frames = Arc::new(boxcar::Vec::new());
        push_frame(
            &frames,
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            ],
        );

        let fingerprint = AkamaiFingerprint::from_frames(&frames).unwrap();

        assert_eq!(fingerprint.fingerprint, "1:65536;3:1000|00|0|");
    }

    fn push_frame(frames: &Http2Frame, data: &[u8]) {
        let (_, frame) = frame::FrameParser::default().parse(data);
        frames.push(frame.unwrap());
    }
}
