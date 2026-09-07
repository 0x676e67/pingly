//! Pingly HTTP/2 fingerprints built from the ordered opening frame sequence.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{frame::Frame, md5_hash, push_pseudo_header_order};

/// Pingly's ordered HTTP/2 fingerprint and its MD5 digest.
///
/// Frame names and targets remain explicit so connection and stream flow-control
/// updates cannot be confused. The next `HEADERS` field section ends the sample;
/// it can carry trailers on the same stream or open another request stream.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2Fingerprint {
    /// Pingly-defined opening-frame sequence in original wire order.
    pub h2_text: Box<str>,

    /// Lowercase MD5 digest of [`Self::h2_text`].
    pub h2_text_hash: Box<str>,
}

impl Http2Fingerprint {
    /// Builds a fingerprint from client frames in their original wire order.
    ///
    /// The first `HEADERS` frame selects the request stream. Supported control
    /// frames are retained until, but not including, the next `HEADERS` field
    /// section; `DATA` and opaque frames are omitted. See
    /// [RFC 9113, Section 8.1](https://www.rfc-editor.org/rfc/rfc9113#section-8.1).
    ///
    /// `WINDOW_UPDATE` targets follow
    /// [RFC 9113, Section 6.9](https://www.rfc-editor.org/rfc/rfc9113#section-6.9).
    /// `PRIORITY_UPDATE` uses its payload target as defined by
    /// [RFC 9218, Section 7.1](https://www.rfc-editor.org/rfc/rfc9218#section-7.1).
    pub fn from_frames<'a>(frames: impl IntoIterator<Item = &'a Frame>) -> Option<Self> {
        let mut opening_frames = Vec::with_capacity(8);
        let mut stream_id = None;

        for frame in frames {
            if let Frame::Headers(headers) = frame {
                if stream_id.is_some() {
                    break;
                }
                stream_id = Some(headers.stream_id);
            }
            if !matches!(frame, Frame::Data(_) | Frame::Unknown(_)) {
                opening_frames.push(frame);
            }
        }

        let h2_text = fingerprint_text(&opening_frames, stream_id?);
        Some(Self {
            h2_text_hash: md5_hash(&h2_text),
            h2_text: h2_text.into_boxed_str(),
        })
    }
}

fn fingerprint_text(frames: &[&Frame], stream_id: u32) -> String {
    let mut output = String::new();
    let mut has_settings = false;

    for frame in frames {
        match frame {
            Frame::Settings(frame) if !has_settings && !frame.is_ack() => {
                has_settings = true;
                push_token(&mut output);
                output.push_str("SETTINGS:");
                for (index, setting) in frame.settings.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    let (id, value) = setting.value();
                    let _ = write!(output, "{id}={value}");
                }
            }
            Frame::Settings(_) | Frame::Data(_) | Frame::Unknown(_) => {}
            Frame::WindowUpdate(frame) => {
                push_token(&mut output);
                push_target(&mut output, "WINDOW_UPDATE", frame.stream_id, stream_id);
                let _ = write!(output, ":{}", frame.increment);
            }
            Frame::Priority(frame) => {
                push_token(&mut output);
                push_target(&mut output, "PRIORITY", frame.stream_id, stream_id);
                let _ = write!(
                    output,
                    ":{}:{}:{}",
                    frame.priority.exclusive, frame.priority.depends_on, frame.priority.weight
                );
            }
            Frame::PriorityUpdate(frame) => {
                push_token(&mut output);
                push_target(
                    &mut output,
                    "PRIORITY_UPDATE",
                    frame.prioritized_stream_id,
                    stream_id,
                );
                output.push(':');
                output.push_str(&frame.priority);
            }
            Frame::Headers(frame) => {
                push_token(&mut output);
                output.push_str("HEADERS(stream):");
                push_pseudo_header_order(&mut output, frame);
            }
        }
    }

    output
}

fn push_target(output: &mut String, frame: &str, target: u32, stream_id: u32) {
    output.push_str(frame);
    if target == 0 {
        output.push_str("(connection)");
    } else if target == stream_id {
        output.push_str("(stream)");
    } else {
        let _ = write!(output, "(stream={target})");
    }
}

fn push_token(output: &mut String) {
    if !output.is_empty() {
        output.push('|');
    }
}

#[cfg(test)]
mod tests {
    use super::Http2Fingerprint;
    use crate::h2::FrameParser;

    #[test]
    fn fingerprint_labels_ordered_connection_and_stream_signals() {
        let mut parser = FrameParser::default();
        let mut frames = Vec::new();
        for wire in [
            &[
                0, 0, 24, 4, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0, 2, 0, 0,
                0, 5, 0, 0, 64, 0,
            ][..],
            &[0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 191, 0, 1],
            &[0, 0, 2, 1, 5, 0, 0, 0, 3, 130, 132],
            &[0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 190, 0, 0],
            &[
                0, 0, 9, 16, 0, 0, 0, 0, 0, 0, 0, 0, 3, b'u', b'=', b'0', b',', b'i',
            ],
            &[0, 0, 2, 1, 5, 0, 0, 0, 5, 130, 132],
        ] {
            frames.push(parser.parse(wire).unwrap().into_frame().unwrap());
        }

        let fingerprint = Http2Fingerprint::from_frames(&frames).unwrap();

        assert_eq!(
            fingerprint.h2_text.as_ref(),
            "SETTINGS:1=65536,2=0,4=131072,5=16384|WINDOW_UPDATE(connection):12517377|HEADERS(stream):m,p|WINDOW_UPDATE(stream):12451840|PRIORITY_UPDATE(stream):u=0,i"
        );
        assert_eq!(
            fingerprint.h2_text_hash.as_ref(),
            "49e6f8e09061061919cd946b0d94ce56"
        );
    }
}
