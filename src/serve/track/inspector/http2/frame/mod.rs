mod error;
mod headers;
mod priority;
mod settings;
mod window_update;

use headers::HeadersFrame;
use priority::PriorityFrame;
use serde::Serialize;
use settings::SettingsFrame;
use window_update::WindowUpdateFrame;

pub fn parse(data: &[u8]) -> (usize, Option<Frame>) {
    const FRAME_HEADER_LEN: usize = 9;

    if data.len() < FRAME_HEADER_LEN {
        return (0, None);
    }
    let header = &data[..FRAME_HEADER_LEN];
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let ty = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
    let payload = &data[FRAME_HEADER_LEN..];
    if payload.len() < length {
        return (0, None);
    }

    match Frame::try_from((ty, flags, stream_id, &payload[..length])) {
        Ok(frame) => (FRAME_HEADER_LEN + length, Some(frame)),
        Err(err) => {
            tracing::warn!("Failed to parse frame: {:?}", err);
            (FRAME_HEADER_LEN + length, None)
        }
    }
}

/// Represents HTTP/2 frame.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Frame {
    Settings(SettingsFrame),
    WindowUpdate(WindowUpdateFrame),
    Priority(PriorityFrame),
    Headers(HeadersFrame),
    Unknown(UnknownFrame),
}

/// Represents frame types for serialization.
#[derive(Debug, Serialize)]
pub enum FrameType {
    Settings,
    WindowUpdate,
    Headers,
    Priority,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct UnknownFrame {
    pub frame_type: FrameType,
    pub length: usize,
    pub payload: Vec<u8>,
}

impl TryFrom<(u8, u8, u32, &[u8])> for Frame {
    type Error = error::Error;

    fn try_from(
        (ty, flags, stream_id, payload): (u8, u8, u32, &[u8]),
    ) -> Result<Self, Self::Error> {
        match ty {
            0x1 => HeadersFrame::try_from((flags, stream_id, payload)).map(Frame::Headers),
            0x2 => PriorityFrame::try_from((stream_id, payload)).map(Frame::Priority),
            0x4 => SettingsFrame::try_from(payload).map(Frame::Settings),
            0x8 => WindowUpdateFrame::try_from(payload).map(Frame::WindowUpdate),
            _ => {
                // If the frame type is unknown, we create an UnknownFrame
                let frame = UnknownFrame {
                    frame_type: FrameType::Unknown,
                    length: payload.len(),
                    payload: payload.to_vec(),
                };
                Ok(Frame::Unknown(frame))
            }
        }
    }
}
