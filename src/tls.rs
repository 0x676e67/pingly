//! TLS ClientHello capture, parsing, and fingerprint analysis.
//!
//! The captured structures preserve client-advertised ordering and raw protocol identifiers where
//! those details are needed for JA3 and JA4 analysis.
//!
//! See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).

#[macro_use]
mod macros;
mod enums;
mod group;
mod hello;
mod ja3;
mod ja4;
mod parser;

pub use enums::{
    AuthenticatedEncryptionWithAssociatedData, CertificateCompressionAlgorithm,
    CertificateStatusType, CompressionAlgorithm, ECPointFormat, KeyDerivationFunction,
    PskKeyExchangeMode, SignatureAlgorithm, TlsVersion,
};
pub use group::NamedGroup;
pub use hello::{
    ClientHello, ClientHelloBuffer, ClientHelloParseError, ClientHelloParseStage, ECHClientHello,
    ECHClientHelloOuter, HexBytes, HpkeSymmetricCipherSuite, KeyShare, OidFilter, ProtocolName,
    ProtocolNameError, PskKeyExchangeModes, StatusRequest, TlsCipherSuite, TlsExtension,
};
pub use ja3::Ja3Fingerprint;
pub use ja4::Ja4Fingerprint;
