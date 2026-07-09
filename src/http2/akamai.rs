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

    for (_, frame) in sent_frames.iter() {
        match frame {
            Frame::Settings(frame) => {
                for setting in &frame.settings {
                    let (id, value) = setting.value();
                    setting_group.push(format!("{id}:{value}"));
                }
            }
            Frame::WindowUpdate(frame) => {
                window_update_group = Some(frame.increment);
            }
            Frame::Priority(frame) => {
                let priority_group = priority_group.get_or_insert_with(Vec::new);
                priority_group.push(format!(
                    "{}:{}:{}:{}",
                    frame.stream_id,
                    frame.priority.exclusive,
                    frame.priority.depends_on,
                    frame.priority.weight + 1
                ));
            }
            Frame::Headers(frame) => {
                headers_group.push(format!("{}", frame.stream_id));
                headers_group.push(
                    frame
                        .pseudo_headers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                headers_group.push(format!("{}", frame.flags.0));
                if let Some(ref priority) = frame.priority {
                    headers_group.push(format!(
                        "{}:{}:{}",
                        priority.exclusive, priority.depends_on, priority.weight
                    ));
                }
            }
            Frame::Unknown(value) => {
                tracing::trace!("Unknown http2 frame: {:?}", value);
            }
        }
    }

    let mut fingerprint = Vec::with_capacity(4);

    fingerprint.push(setting_group.join(";"));

    if let Some(window_update_group) = window_update_group {
        fingerprint.push(window_update_group.to_string());
    }

    if let Some(priority_group) = priority_group {
        fingerprint.push(priority_group.join(","));
    }

    fingerprint.push(headers_group.join(";"));

    fingerprint.join("|")
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

        assert_eq!(fingerprint.fingerprint, "1:65536;3:1000|983041|3:0:0:202|");
        assert_eq!(fingerprint.hash, "ba2883d991a97ee2e0cdff59b10df98e");
    }

    #[test]
    fn akamai_fingerprint_is_none_without_frames() {
        let frames = Arc::new(boxcar::Vec::new());

        assert!(AkamaiFingerprint::from_frames(&frames).is_none());
    }

    fn push_frame(frames: &Http2Frame, data: &[u8]) {
        let (_, frame) = frame::parse(data);
        frames.push(frame.unwrap());
    }
}
