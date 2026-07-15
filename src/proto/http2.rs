//! HTTP/2 wire models, stream parsers, and Akamai fingerprinting.

mod akamai;
pub mod frame;
mod parser;

pub use akamai::AkamaiFingerprint;
pub use frame::{Frame, FrameError, FrameParseError, FrameParseOutcome, FrameParser, FrameType};
pub use parser::{
    parse_connection, parse_frames, Http2ParseError, Http2Parser, HTTP2_CLIENT_PREFACE,
};
