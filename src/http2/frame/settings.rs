use serde::Serialize;

use super::{error::Error, FrameType};

/// An enum that lists all valid settings that can be sent in a SETTINGS
/// frame.
///
/// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
#[derive(Debug, Serialize)]
pub enum Setting {
    HeaderTableSize { id: u16, value: u32 },
    EnablePush { id: u16, value: u32 },
    MaxConcurrentStreams { id: u16, value: u32 },
    InitialWindowSize { id: u16, value: u32 },
    MaxFrameSize { id: u16, value: u32 },
    MaxHeaderListSize { id: u16, value: u32 },
    EnableConnectProtocol { id: u16, value: u32 },
    NoRfc7540Priorities { id: u16, value: u32 },
    Unknown { id: u16, value: u32 },
}

/// Representing a SETTINGS frame in HTTP/2.
#[derive(Debug, Serialize)]
pub struct SettingsFrame {
    pub frame_type: FrameType,
    pub length: usize,
    pub settings: Vec<Setting>,
}

// ==== impl Setting ====

impl From<(u16, u32)> for Setting {
    fn from((id, value): (u16, u32)) -> Self {
        match id {
            1 => Setting::HeaderTableSize { id, value },
            2 => Setting::EnablePush { id, value },
            3 => Setting::MaxConcurrentStreams { id, value },
            4 => Setting::InitialWindowSize { id, value },
            5 => Setting::MaxFrameSize { id, value },
            6 => Setting::MaxHeaderListSize { id, value },
            8 => Setting::EnableConnectProtocol { id, value },
            9 => Setting::NoRfc7540Priorities { id, value },
            _ => Setting::Unknown { id, value },
        }
    }
}

impl Setting {
    pub fn value(&self) -> (u16, u32) {
        match self {
            Setting::HeaderTableSize { id, value } => (*id, *value),
            Setting::EnablePush { id, value } => (*id, *value),
            Setting::MaxConcurrentStreams { id, value } => (*id, *value),
            Setting::InitialWindowSize { id, value } => (*id, *value),
            Setting::MaxFrameSize { id, value } => (*id, *value),
            Setting::MaxHeaderListSize { id, value } => (*id, *value),
            Setting::EnableConnectProtocol { id, value } => (*id, *value),
            Setting::NoRfc7540Priorities { id, value } => (*id, *value),
            Setting::Unknown { id, value } => (*id, *value),
        }
    }
}

// ==== impl SettingsFrame ====

impl TryFrom<&[u8]> for SettingsFrame {
    type Error = Error;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.is_empty() {
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
            length: payload.len(),
            settings,
        })
    }
}
