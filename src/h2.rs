//! HTTP/2 wire models, stream parsers, and client fingerprints.

mod akamai;
mod fingerprint;

/// HTTP/2 frame models, flags, and the incremental frame parser.
///
/// Frame layout and processing follow [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113).
pub mod frame;

mod parser;

pub use akamai::AkamaiFingerprint;
pub use fingerprint::Http2Fingerprint;
pub use frame::{Frame, FrameError, FrameParseError, FrameParseOutcome, FrameParser, FrameType};
pub use parser::{
    parse_connection, parse_frames, Http2ParseError, Http2Parser, Http2PushError,
    HTTP2_CLIENT_PREFACE,
};

fn md5_hash(value: &str) -> Box<str> {
    hex::encode(md5::compute(value).as_slice()).into_boxed_str()
}

fn push_pseudo_header_order(output: &mut String, headers: &frame::HeadersFrame) {
    let start = output.len();
    for header in &headers.headers {
        let Some(short_name) = header
            .name
            .strip_prefix(b":")
            .and_then(|name| std::str::from_utf8(name).ok())
            .and_then(|name| name.chars().next())
        else {
            continue;
        };

        if output.len() > start {
            output.push(',');
        }
        output.push(short_name);
    }
}
