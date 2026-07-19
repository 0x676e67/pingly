//! HTTP/3 stream models, incremental frame parsing, and fingerprinting.
//!
//! HTTP/3 frames travel on independent QUIC streams, so callers select either a request stream or
//! a client-initiated unidirectional stream when constructing [`Http3Parser`]. The parser accepts
//! decrypted stream bytes; encrypted UDP datagrams must first be processed by a QUIC stack.
//! HEADERS decoding is stateless: field sections that reference the QPACK dynamic table return
//! [`Http3ParseError::Frame`]. This matches peers configured with zero dynamic-table capacity,
//! including Pingly's server. Reconstructing arbitrary third-party connections also requires
//! processing their QPACK encoder stream.
//! Complete request and control-stream parsers require the initial HEADERS and SETTINGS frames
//! mandated by RFC 9114. Frames without a dedicated payload decoder use [`OpaqueFrame`] while
//! retaining an accurate [`FrameType`]. Boolean SETTINGS use [`SettingValue::Bool`]; numeric QUIC
//! varints above JavaScript's safe integer range serialize as decimal strings without losing
//! their wire value.
//!
//! See [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) and
//! [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204).

mod fingerprint;
mod frame;
mod parser;

pub use fingerprint::Http3Fingerprint;
pub use frame::{
    Frame, FrameType, HeaderField, HeadersFrame, Http3FrameError, OpaqueFrame, Setting,
    SettingName, SettingValue, SettingsFrame, StreamType, StreamTypeName,
};
pub use parser::{
    parse_request_stream, parse_unidirectional_stream, Http3ParseError, Http3Parser, Http3PushError,
};
