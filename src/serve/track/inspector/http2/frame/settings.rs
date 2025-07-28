use serde::{Serialize, Serializer};

use super::{error::Error, FrameType};

/// An enum that lists all valid settings that can be sent in a SETTINGS
/// frame.
///
/// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
#[derive(Debug)]
pub enum Setting {
    HeaderTableSize(u16, u32),
    EnablePush(u16, u32),
    MaxConcurrentStreams(u16, u32),
    InitialWindowSize(u16, u32),
    MaxFrameSize(u16, u32),
    MaxHeaderListSize(u16, u32),
    EnableConnectProtocol(u16, u32),
    NoRfc7540Priorities(u16, u32),
    UnknownSetting(u16, u32),
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
            1 => Setting::HeaderTableSize(id, value),
            2 => Setting::EnablePush(id, value),
            3 => Setting::MaxConcurrentStreams(id, value),
            4 => Setting::InitialWindowSize(id, value),
            5 => Setting::MaxFrameSize(id, value),
            6 => Setting::MaxHeaderListSize(id, value),
            8 => Setting::EnableConnectProtocol(id, value),
            9 => Setting::NoRfc7540Priorities(id, value),
            _ => Setting::UnknownSetting(id, value),
        }
    }
}

impl Setting {
    pub fn value(&self) -> (u16, u32) {
        match self {
            Setting::HeaderTableSize(id, value) => (*id, *value),
            Setting::EnablePush(id, value) => (*id, *value),
            Setting::MaxConcurrentStreams(id, value) => (*id, *value),
            Setting::InitialWindowSize(id, value) => (*id, *value),
            Setting::MaxFrameSize(id, value) => (*id, *value),
            Setting::MaxHeaderListSize(id, value) => (*id, *value),
            Setting::EnableConnectProtocol(id, value) => (*id, *value),
            Setting::NoRfc7540Priorities(id, value) => (*id, *value),
            Setting::UnknownSetting(id, value) => (*id, *value),
        }
    }
}

impl Serialize for Setting {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = match self {
            Setting::HeaderTableSize(_, value) => format!("HEADER_TABLE_SIZE = {}", value),
            Setting::EnablePush(_, value) => format!("ENABLE_PUSH = {}", value),
            Setting::MaxConcurrentStreams(_, value) => {
                format!("MAX_CONCURRENT_STREAMS = {}", value)
            }
            Setting::InitialWindowSize(_, value) => format!("INITIAL_WINDOW_SIZE = {}", value),
            Setting::MaxFrameSize(_, value) => format!("MAX_FRAME_SIZE = {}", value),
            Setting::MaxHeaderListSize(_, value) => format!("MAX_HEADER_LIST_SIZE = {}", value),
            Setting::EnableConnectProtocol(_, value) => {
                format!("ENABLE_CONNECT_PROTOCOL = {}", value)
            }
            Setting::NoRfc7540Priorities(_, value) => format!("NO_RFC7540_PRIORITIES = {}", value),
            Setting::UnknownSetting(_, value) => format!("UNKNOWN_SETTING = {}", value),
        };

        serializer.serialize_str(&value)
    }
}

// ==== impl SettingsFrame ====

impl TryFrom<&[u8]> for SettingsFrame {
    type Error = Error;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.is_empty() {
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
