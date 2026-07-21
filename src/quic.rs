//! QUIC wire models used by TLS and HTTP/3 fingerprint analysis.
//!
//! QUIC transport parameters are carried in TLS extension 57 as an ordered sequence of
//! identifier, length, and value tuples. See
//! [RFC 9000, Section 18](https://www.rfc-editor.org/rfc/rfc9000#section-18).

pub(crate) mod varint;

mod parameter;

/// TLS extension type carrying QUIC transport parameters (`0x0039`).
///
/// See [RFC 9001, Section 8.2](https://www.rfc-editor.org/rfc/rfc9001#section-8.2).
pub const TRANSPORT_PARAMETERS_EXTENSION_ID: u16 = 0x0039;

pub use parameter::{
    parse_transport_parameters, QuicTransportParameter, QuicTransportParameterError,
    QuicTransportParameterName, QuicTransportParameterValue, QuicVersion, QuicVersionInformation,
    QuicVersionName,
};
