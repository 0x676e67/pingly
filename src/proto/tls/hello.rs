//! TLS ClientHello data captured from the wire.
//!
//! See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2)
//! for the ClientHello layout and [Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3)
//! for its extension block.

use serde::{de, Deserialize, Deserializer, Serialize};
use tls_parser::{
    TlsCipherSuite as ParsedTlsCipherSuite, TlsExtensionType, TlsMessage, TlsMessageHandshake,
};

use hex::encode as hex_encode;

use super::{
    enums::{
        is_grease_value, AuthenticatedEncryptionWithAssociatedData,
        CertificateCompressionAlgorithm, CertificateStatusType, CompressionAlgorithm,
        ECPointFormat, KeyDerivationFunction, PskKeyExchangeMode, SignatureAlgorithm, TlsVersion,
    },
    group::NamedGroup,
    ja3::Ja3Fingerprint,
    ja4::Ja4Fingerprint,
    parser,
};

const DEFAULT_CLIENT_HELLO_CAPACITY: usize = 2048;
const TLS_RECORD_HEADER_LEN: usize = 5;
const MAX_TLS_RECORD_LEN: usize = TLS_RECORD_HEADER_LEN + tls_parser::MAX_RECORD_LEN as usize;

/// Buffers raw TLS record bytes so the ClientHello can be parsed after the handshake.
///
/// Deferring parsing keeps fingerprint analysis out of the handshake path. The buffer may be filled
/// incrementally when the ClientHello spans multiple reads.
#[derive(Debug, Clone)]
pub struct ClientHelloBuffer {
    buf: Vec<u8>,
}

impl ClientHelloBuffer {
    /// Creates an empty ClientHello buffer with capacity for a typical browser handshake.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CLIENT_HELLO_CAPACITY)
    }

    /// Creates an empty ClientHello buffer with at least the requested initial capacity.
    ///
    /// The capacity only controls the initial allocation. Appended data remains limited to the
    /// largest TLS record accepted by `tls-parser`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Creates a buffer from captured TLS record bytes.
    ///
    /// Passing a `Vec<u8>` transfers its allocation into the buffer. Slices are
    /// copied because the parser owns bytes that may outlive the input read.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self { buf: bytes.into() }
    }

    /// Attempts to parse the first complete TLS ClientHello record in the buffer.
    ///
    /// The buffer remains available after either success or failure, which is
    /// useful when inspecting malformed captures.
    pub fn parse(&self) -> Result<ClientHello, ClientHelloParseError> {
        ClientHello::parse(&self.buf)
    }

    /// Parses a ClientHello once the first TLS record is complete.
    ///
    /// Returns `Ok(None)` while the 5-byte record header or its declared
    /// payload is incomplete. A complete but malformed record returns a
    /// [`ClientHelloParseError`]. TLS record framing is defined by
    /// [RFC 9846, Section 5.1](https://www.rfc-editor.org/rfc/rfc9846#section-5.1).
    pub fn try_parse(&self) -> Result<Option<ClientHello>, ClientHelloParseError> {
        let Some(length_bytes) = self.buf.get(3..TLS_RECORD_HEADER_LEN) else {
            return Ok(None);
        };
        let payload_len = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        if payload_len > usize::from(tls_parser::MAX_RECORD_LEN) {
            return Err(ClientHelloParseError::new(ClientHelloParseStage::TlsRecord));
        }

        let record_len = TLS_RECORD_HEADER_LEN + payload_len;
        if self.buf.len() < record_len {
            return Ok(None);
        }

        ClientHello::parse(&self.buf[..record_len]).map(Some)
    }

    /// Returns the currently buffered TLS bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the number of currently buffered bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns whether no TLS bytes have been buffered yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns whether the buffer contains the largest record accepted by `tls-parser`.
    ///
    /// The limit includes the 5-byte TLS record header.
    pub fn is_max_record_len(&self) -> bool {
        self.buf.len() >= MAX_TLS_RECORD_LEN
    }

    /// Appends bytes without exceeding the largest TLS record accepted by `tls-parser`.
    ///
    /// Returns the number of bytes accepted from `data`.
    pub fn extend(&mut self, data: &[u8]) -> usize {
        let accepted = data
            .len()
            .min(MAX_TLS_RECORD_LEN.saturating_sub(self.buf.len()));
        self.buf.extend_from_slice(&data[..accepted]);
        accepted
    }
}

impl Default for ClientHelloBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for ClientHelloBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<&[u8]> for ClientHelloBuffer {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// A cipher suite offered by a TLS client.
///
/// Registered identifiers use the IANA name exposed by `tls-parser`. GREASE identifiers use
/// `GREASE`, while other unregistered identifiers use `Unknown`, so every wire ID remains in
/// the client-advertised list.
///
/// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct TlsCipherSuite {
    /// The 16-bit cipher-suite identifier observed on the wire.
    pub id: u16,

    /// The registered cipher-suite name, `GREASE`, or `Unknown`.
    pub name: Box<str>,
}

impl TlsCipherSuite {
    /// Resolves a wire identifier into its canonical display name.
    pub fn from_id(id: u16) -> Self {
        Self {
            id,
            name: Self::name_for_id(id).into(),
        }
    }

    /// Resolves a registered IANA cipher-suite name.
    ///
    /// `GREASE` and `Unknown` cannot identify a unique wire value and therefore return `None`.
    pub fn from_name(name: &str) -> Option<Self> {
        ParsedTlsCipherSuite::from_name(name).map(|cipher| Self {
            id: cipher.id.0,
            name: cipher.name.into(),
        })
    }

    /// Returns whether this identifier is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(&self) -> bool {
        is_grease_value(self.id)
    }

    fn name_for_id(id: u16) -> &'static str {
        ParsedTlsCipherSuite::from_id(id)
            .map(|cipher| cipher.name)
            .unwrap_or_else(|| {
                if is_grease_value(id) {
                    "GREASE"
                } else {
                    "Unknown"
                }
            })
    }
}

impl From<u16> for TlsCipherSuite {
    fn from(id: u16) -> Self {
        Self::from_id(id)
    }
}

/// Deserialization shape used to validate a saved cipher-suite ID and name.
#[derive(Deserialize)]
struct TlsCipherSuiteRepr {
    /// The numeric identifier stored in JSON.
    id: u16,

    /// The human-readable name stored alongside the identifier.
    name: Box<str>,
}

impl<'de> Deserialize<'de> for TlsCipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = TlsCipherSuiteRepr::deserialize(deserializer)?;
        let expected = Self::name_for_id(repr.id);

        if repr.name.as_ref() != expected {
            return Err(de::Error::custom(format_args!(
                "TLS cipher suite {:#06x} has name {expected:?}, not {:?}",
                repr.id, repr.name,
            )));
        }

        Ok(Self {
            id: repr.id,
            name: repr.name,
        })
    }
}

/// A decoded TLS ClientHello and the negotiated version observed after the handshake.
///
/// Client-advertised vectors retain their wire order because order is significant to TLS client
/// fingerprinting.
///
/// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// The wire `legacy_version` field.
    ///
    /// A TLS 1.3 client normally sends TLS 1.2 (`0x0303`) here and advertises its real preferences
    /// through the `supported_versions` extension.
    pub tls_version: TlsVersion,

    /// The protocol version selected by the server, or `None` before negotiation completes.
    pub tls_version_negotiated: Option<TlsVersion>,

    /// Cipher suites in client-advertised order, including GREASE and unregistered identifiers.
    pub cipher_suites: Vec<TlsCipherSuite>,

    /// The 32-byte ClientHello random value encoded as lowercase hexadecimal.
    pub client_random: String,

    /// The legacy session identifier encoded as lowercase hexadecimal, when present.
    pub session_id: Option<String>,

    /// Compression methods in client-advertised order.
    pub compression_algorithms: Vec<CompressionAlgorithm>,

    /// Decoded extensions in the order sent by the client.
    pub extensions: Vec<TlsExtension>,
}

/// A decoded or preserved extension from a [`ClientHello`].
///
/// Every `value` field is the numeric `ExtensionType` observed on the wire. Byte-oriented payloads
/// are serialized as lowercase hexadecimal unless a variant documents another representation.
///
/// See [RFC 9846, Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsExtension {
    /// Server names advertised through Server Name Indication (SNI).
    ///
    /// See [RFC 6066, Section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
    ServerName {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Advertised names decoded as UTF-8, replacing malformed byte sequences when necessary.
        data: Vec<Box<str>>,
    },

    /// Named groups supported for key establishment.
    ///
    /// See [RFC 9846, Section 4.3.7](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.7).
    SupportedGroups {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Named groups in client preference order.
        data: Vec<NamedGroup>,
    },

    /// Elliptic-curve point formats advertised by a pre-TLS 1.3 client.
    ///
    /// See [RFC 8422, Section 5.1.2](https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2).
    EcPointFormats {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Point formats in client preference order.
        data: Vec<ECPointFormat>,
    },

    /// Signature schemes accepted by the client.
    ///
    /// See [RFC 9846, Section 4.3.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.3).
    SignatureAlgorithms {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Signature schemes in client preference order.
        data: Vec<SignatureAlgorithm>,
    },

    /// A request for a stapled certificate status response.
    ///
    /// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
    StatusRequest {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Parsed OCSP status request parameters.
        data: StatusRequest,
    },

    /// Application protocols offered through ALPN, such as `h2`.
    ///
    /// See [RFC 7301, Section 3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1).
    ApplicationLayerProtocolNegotiation {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Protocol names in client preference order, decoded as UTF-8.
        data: Vec<Box<str>>,
    },

    /// Protocol names from the former `0x4469` Application Settings code point.
    ///
    /// ALPS remains an Internet-Draft; see
    /// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
    ApplicationSettingsOld {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Application protocol names carried by the extension.
        data: Vec<Box<str>>,
    },

    /// Protocol names from the current `0x44cd` Application Settings code point.
    ///
    /// ALPS remains an Internet-Draft; see
    /// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
    ApplicationSettings {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Application protocol names carried by the extension.
        data: Vec<Box<str>>,
    },

    /// TLS versions the client is prepared to negotiate.
    ///
    /// See [RFC 9846, Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.1).
    SupportedVersions {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Versions in client preference order.
        data: Vec<TlsVersion>,
    },

    /// A TLS 1.2 session ticket offered for resumption.
    ///
    /// See [RFC 5077, Section 3.2](https://www.rfc-editor.org/rfc/rfc5077.html#section-3.2).
    SessionTicket {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Opaque ticket bytes encoded as lowercase hexadecimal.
        data: Box<str>,
    },

    /// Supported certificate compression algorithms.
    ///
    /// See [RFC 8879, Section 3](https://www.rfc-editor.org/rfc/rfc8879.html#section-3).
    CertificateCompression {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Compression algorithms in client preference order.
        data: Vec<CertificateCompressionAlgorithm>,
    },

    /// Maximum protected record size accepted by the client.
    ///
    /// See [RFC 8449, Section 4](https://www.rfc-editor.org/rfc/rfc8449.html#section-4).
    RecordSizeLimit {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Advertised record size limit in bytes.
        data: u16,
    },

    /// Signature schemes accepted for delegated credentials.
    ///
    /// See [RFC 9345, Section 4.1](https://www.rfc-editor.org/rfc/rfc9345.html#section-4.1).
    DelegatedCredentials {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Supported delegated-credential signature schemes.
        data: Vec<SignatureAlgorithm>,
    },

    /// An Encrypted ClientHello (ECH) offer.
    ///
    /// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
    EncryptedClientHello {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Parsed outer or inner ECH payload.
        data: ECHClientHello,
    },

    /// A request for Signed Certificate Timestamps through the TLS extension.
    ///
    /// See [RFC 6962, Section 3.3.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-3.3.1).
    SignedCertificateTimestamp {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Raw payload encoded as lowercase hexadecimal when one was present.
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Box<str>>,
    },

    /// The secure renegotiation indication used by TLS 1.2 and earlier.
    ///
    /// See [RFC 5746, Section 3.2](https://www.rfc-editor.org/rfc/rfc5746.html#section-3.2).
    RenegotiationInfo {
        /// Numeric extension type as observed on the wire.
        value: u16,
    },

    /// The Extended Master Secret indication used by TLS 1.2 and earlier.
    ///
    /// See [RFC 7627, Section 3](https://www.rfc-editor.org/rfc/rfc7627.html#section-3).
    ExtendedMasterSecret {
        /// Numeric extension type as observed on the wire.
        value: u16,
    },

    /// ClientHello padding used to alter the message length.
    ///
    /// See [RFC 7685, Section 3](https://www.rfc-editor.org/rfc/rfc7685.html#section-3).
    Padding {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Padding bytes encoded as lowercase hexadecimal.
        data: Box<str>,
    },

    /// Ephemeral key shares offered for TLS 1.3 key establishment.
    ///
    /// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
    KeyShare {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Parsed key shares in client preference order.
        data: Vec<KeyShare>,
    },

    /// Key exchange modes the client permits for pre-shared keys.
    ///
    /// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
    PskKeyExchangeModes {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Parsed PSK key exchange modes.
        data: PskKeyExchangeModes,
    },

    /// Pre-shared key identities and binders offered for resumption or 0-RTT.
    ///
    /// See [RFC 9846, Section 4.3.11](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.11).
    PreSharedKey {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Complete opaque extension payload encoded as lowercase hexadecimal.
        data: Box<str>,
    },

    /// A legacy experimental Encrypted Server Name Indication (ESNI) offer.
    ///
    /// ESNI was replaced by ECH; see
    /// [draft-ietf-tls-esni-00](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-00).
    EncryptedServerName {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Recognized TLS cipher-suite name, or `Unknown`.
        ciphersuite: Box<str>,

        /// Named group used for the key share.
        group: NamedGroup,

        /// Key share bytes encoded as lowercase hexadecimal.
        key_share: Box<str>,

        /// ESNIKeys record digest encoded as lowercase hexadecimal.
        record_digest: Box<str>,

        /// Encrypted server-name bytes encoded as lowercase hexadecimal.
        encrypted_sni: Box<str>,
    },

    /// Filters applied to certificate extension object identifiers.
    ///
    /// See [RFC 9846, Section 4.3.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.5).
    OidFilters {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Requested certificate extension filters.
        data: Vec<OidFilter>,
    },

    /// A reserved GREASE extension used to exercise protocol extensibility.
    ///
    /// See [RFC 8701, Section 3](https://www.rfc-editor.org/rfc/rfc8701.html#section-3).
    Grease {
        /// GREASE extension type as observed on the wire.
        value: u16,
    },

    /// An extension that is valid to preserve but is not decoded into a dedicated variant.
    Opaque {
        /// Numeric extension type as observed on the wire.
        value: u16,

        /// Raw payload encoded as lowercase hexadecimal, or `None` for an empty payload.
        data: Option<Box<str>>,
    },
}

impl TlsExtension {
    /// Returns the numeric `ExtensionType` observed on the wire.
    pub fn value(&self) -> u16 {
        match self {
            TlsExtension::ServerName { value, .. }
            | TlsExtension::SupportedGroups { value, .. }
            | TlsExtension::EcPointFormats { value, .. }
            | TlsExtension::SignatureAlgorithms { value, .. }
            | TlsExtension::StatusRequest { value, .. }
            | TlsExtension::ApplicationLayerProtocolNegotiation { value, .. }
            | TlsExtension::ApplicationSettingsOld { value, .. }
            | TlsExtension::ApplicationSettings { value, .. }
            | TlsExtension::SupportedVersions { value, .. }
            | TlsExtension::SessionTicket { value, .. }
            | TlsExtension::CertificateCompression { value, .. }
            | TlsExtension::RecordSizeLimit { value, .. }
            | TlsExtension::DelegatedCredentials { value, .. }
            | TlsExtension::EncryptedClientHello { value, .. }
            | TlsExtension::SignedCertificateTimestamp { value, .. }
            | TlsExtension::RenegotiationInfo { value }
            | TlsExtension::ExtendedMasterSecret { value }
            | TlsExtension::Padding { value, .. }
            | TlsExtension::KeyShare { value, .. }
            | TlsExtension::PskKeyExchangeModes { value, .. }
            | TlsExtension::PreSharedKey { value, .. }
            | TlsExtension::EncryptedServerName { value, .. }
            | TlsExtension::OidFilters { value, .. }
            | TlsExtension::Grease { value }
            | TlsExtension::Opaque { value, .. } => *value,
        }
    }

    /// Returns whether this extension uses an RFC 8701 GREASE type.
    ///
    /// See [RFC 8701, Section 3](https://www.rfc-editor.org/rfc/rfc8701.html#section-3).
    pub fn is_grease(&self) -> bool {
        is_grease_value(self.value())
    }
}

/// The OCSP parameters carried by a ClientHello `status_request` extension.
///
/// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct StatusRequest {
    /// The certificate status protocol requested by the client.
    pub certificate_status_type: CertificateStatusType,

    /// Declared byte length of the OCSP responder ID list.
    pub responder_id_list: u16,

    /// Declared byte length of the OCSP request extensions.
    pub request_extensions: u16,
}

/// The outer or inner form of an Encrypted ClientHello extension.
///
/// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ECHClientHello {
    /// The public ClientHelloOuter payload carrying the encrypted ClientHelloInner.
    Outer(ECHClientHelloOuter),
    /// The empty marker repeated inside ClientHelloInner.
    ///
    /// Including this marker permits the server to respond with ECH-related extensions after it
    /// discards ClientHelloOuter.
    Inner,
}

/// Encryption metadata and ciphertext carried by an ECH ClientHelloOuter.
///
/// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ECHClientHelloOuter {
    /// The HPKE KDF and AEAD pair used to encrypt ClientHelloInner.
    pub cipher_suite: HpkeSymmetricCipherSuite,

    /// The selected ECH configuration identifier.
    pub config_id: u8,

    /// The HPKE encapsulated key encoded as lowercase hexadecimal.
    ///
    /// This can be empty in a ClientHelloOuter sent after HelloRetryRequest.
    pub enc: String,

    /// The encrypted EncodedClientHelloInner bytes encoded as lowercase hexadecimal.
    ///
    /// Its decoded byte length is recorded in `payload_length`.
    pub payload: String,

    /// The encoded `uint16` length of the encrypted payload in bytes.
    ///
    /// This is retained explicitly because `payload` is exposed as hexadecimal text.
    pub payload_length: u16,
}

/// The HPKE KDF and AEAD pair selected for ECH encryption.
///
/// See [RFC 9849, Section 4](https://www.rfc-editor.org/rfc/rfc9849.html#section-4) and
/// [RFC 9180, Section 7.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct HpkeSymmetricCipherSuite {
    /// The HPKE key derivation function identifier.
    pub kdf_id: KeyDerivationFunction,

    /// The HPKE authenticated-encryption algorithm identifier.
    pub aead_id: AuthenticatedEncryptionWithAssociatedData,
}

/// An ephemeral key share offered by the client.
///
/// Each item retains the named-group ID and name. Non-GREASE items serialize their opaque key
/// exchange bytes under `value`; GREASE items omit those arbitrary payload bytes.
///
/// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct KeyShare {
    /// The 16-bit named-group identifier observed on the wire.
    pub id: u16,

    /// The registered group name, `GREASE`, or `Unknown`.
    pub name: Box<str>,

    /// The opaque key exchange bytes encoded as lowercase hexadecimal.
    ///
    /// GREASE key exchange bytes can contain any value and are therefore omitted.
    /// See [RFC 8701, Section 3](https://www.rfc-editor.org/rfc/rfc8701.html#section-3).
    #[serde(rename = "value", skip_serializing_if = "Option::is_none")]
    pub key_exchange: Option<Box<str>>,
}

impl KeyShare {
    fn from_wire(id: u16, key_exchange: Vec<u8>) -> Self {
        let group = NamedGroup::from(id);
        let key_exchange = (!group.is_grease()).then(|| hex_encode(key_exchange).into_boxed_str());

        Self {
            id: group.id,
            name: group.name,
            key_exchange,
        }
    }
}

impl<'de> Deserialize<'de> for KeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = KeyShareRepr::deserialize(deserializer)?;
        let id = repr.id;
        let group = NamedGroup::from_serialized_parts(id, repr.name).map_err(|expected| {
            de::Error::custom(format_args!(
                "TLS key share group {id:#06x} has name {expected:?}, not the saved name",
            ))
        })?;

        match (group.is_grease(), repr.key_exchange) {
            (true, Some(_)) => Err(de::Error::custom(
                "GREASE key shares must omit key exchange bytes",
            )),
            (false, None) => Err(de::Error::custom(
                "non-GREASE key shares require key exchange bytes",
            )),
            (_, key_exchange) => Ok(Self {
                id: group.id,
                name: group.name,
                key_exchange,
            }),
        }
    }
}

/// Deserialization shape used to validate a saved key-share ID, name, and payload.
#[derive(Deserialize)]
struct KeyShareRepr {
    /// The numeric named-group identifier stored in JSON.
    id: u16,

    /// The human-readable group name stored alongside the identifier.
    name: Box<str>,

    /// The optional key exchange bytes stored under the public `value` key.
    #[serde(rename = "value")]
    key_exchange: Option<Box<str>>,
}

/// Pre-shared-key key exchange modes offered by the client.
///
/// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct PskKeyExchangeModes {
    /// Modes in client preference order.
    pub ke_modes: Vec<PskKeyExchangeMode>,
}

/// A certificate-extension filter from the ClientHello `oid_filters` extension.
///
/// See [RFC 9846, Section 4.3.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct OidFilter {
    /// The DER-encoded certificate extension OID, represented as lowercase hexadecimal.
    pub cert_ext_oid: String,

    /// The required certificate extension value, represented as lowercase hexadecimal.
    pub cert_ext_val: String,
}

/// The ClientHello layer at which binary parsing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientHelloParseStage {
    TlsRecord,
    RecordMessages,
    ClientHello,
    ExtensionBlock,
    Extensions,
    StatusRequest,
    DelegatedCredentials,
    CertificateCompression,
    EncryptedClientHello,
    KeyShare,
}

/// A structured TLS ClientHello parsing failure.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("failed to parse TLS ClientHello at {stage:?}")]
pub struct ClientHelloParseError {
    /// The layer or extension parser that rejected the input.
    pub stage: ClientHelloParseStage,

    /// The extension type involved in the failure, when applicable.
    pub extension_id: Option<u16>,

    /// The extension payload length observed on the wire, when applicable.
    pub payload_len: Option<usize>,
}

impl ClientHelloParseError {
    const fn new(stage: ClientHelloParseStage) -> Self {
        Self {
            stage,
            extension_id: None,
            payload_len: None,
        }
    }

    const fn extension(
        stage: ClientHelloParseStage,
        extension_id: u16,
        payload_len: usize,
    ) -> Self {
        Self {
            stage,
            extension_id: Some(extension_id),
            payload_len: Some(payload_len),
        }
    }
}

impl ClientHello {
    /// Records the protocol version selected after the handshake.
    ///
    /// Passing `None` clears a previously recorded negotiated version.
    pub fn set_tls_version_negotiated(&mut self, version: Option<TlsVersion>) {
        self.tls_version_negotiated = version;
    }

    /// Parses the first ClientHello from a complete TLS record.
    ///
    /// Unknown cipher-suite identifiers are retained for fingerprinting but omitted from the
    /// human-readable cipher list.
    pub fn parse(buf: &[u8]) -> Result<Self, ClientHelloParseError> {
        match Self::parse_inner(buf) {
            Ok(client_hello) => {
                tracing::debug!(
                    record_len = buf.len(),
                    legacy_version = %client_hello.tls_version,
                    cipher_count = client_hello.cipher_suites.len(),
                    extension_count = client_hello.extensions.len(),
                    "parsed TLS ClientHello",
                );
                Ok(client_hello)
            }
            Err(error) => {
                tracing::debug!(
                    record_len = buf.len(),
                    stage = ?error.stage,
                    extension_id = ?error.extension_id,
                    payload_len = ?error.payload_len,
                    "failed to parse TLS ClientHello",
                );
                Err(error)
            }
        }
    }

    fn parse_inner(buf: &[u8]) -> Result<Self, ClientHelloParseError> {
        let (_, r) = tls_parser::parse_tls_raw_record(buf)
            .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::TlsRecord))?;
        let (_, msg_list) = tls_parser::parse_tls_record_with_header(r.data, &r.hdr)
            .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::RecordMessages))?;

        let payload = msg_list
            .into_iter()
            .find_map(|msg| {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(payload)) = msg {
                    Some(payload)
                } else {
                    None
                }
            })
            .ok_or(ClientHelloParseError::new(
                ClientHelloParseStage::ClientHello,
            ))?;

        let cipher_suites = payload
            .ciphers
            .iter()
            .map(|cipher| TlsCipherSuite::from(cipher.0))
            .collect();

        let mut client_hello = ClientHello {
            tls_version: TlsVersion::from(payload.version.0),
            tls_version_negotiated: None,
            cipher_suites,
            client_random: hex_encode(payload.random),
            session_id: payload.session_id.map(hex_encode),
            compression_algorithms: payload
                .comp
                .iter()
                .map(|c| CompressionAlgorithm::from(c.0))
                .collect(),
            extensions: Vec::with_capacity(5),
        };

        let ext = payload.ext.ok_or(ClientHelloParseError::new(
            ClientHelloParseStage::ExtensionBlock,
        ))?;
        let (_, ext_list) = tls_parser::parse_tls_client_hello_extensions(ext)
            .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::Extensions))?;

        for ext in ext_list {
            let extension_id = TlsExtensionType::from(&ext).0;
            tracing::trace!(extension_id, "decoding TLS ClientHello extension");

            match ext {
                tls_parser::TlsExtension::SNI(name) => {
                    client_hello.extensions.push(TlsExtension::ServerName {
                        value: extension_id,
                        data: name
                            .into_iter()
                            .map(|n| n.1)
                            .map(|n| String::from_utf8_lossy(n).into_owned().into_boxed_str())
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::EllipticCurves(groups) => {
                    client_hello.extensions.push(TlsExtension::SupportedGroups {
                        value: extension_id,
                        data: groups
                            .into_iter()
                            .map(|group| NamedGroup::from(group.0))
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::SupportedVersions(versions) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SupportedVersions {
                            value: extension_id,
                            data: versions
                                .into_iter()
                                .map(|version| TlsVersion::from(version.0))
                                .collect(),
                        });
                }
                tls_parser::TlsExtension::SessionTicket(data) => {
                    client_hello.extensions.push(TlsExtension::SessionTicket {
                        value: extension_id,
                        data: hex_encode(data).into_boxed_str(),
                    });
                }
                tls_parser::TlsExtension::SignatureAlgorithms(algorithms) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SignatureAlgorithms {
                            value: extension_id,
                            data: algorithms
                                .into_iter()
                                .map(SignatureAlgorithm::from)
                                .collect(),
                        });
                }
                tls_parser::TlsExtension::StatusRequest(data) => {
                    if let Some((status, data)) = data {
                        let (_, (responder_id_list, request_extensions)) =
                            parser::parse_ocsp_status_request_lengths(data).map_err(|_| {
                                ClientHelloParseError::extension(
                                    ClientHelloParseStage::StatusRequest,
                                    extension_id,
                                    data.len(),
                                )
                            })?;
                        client_hello.extensions.push(TlsExtension::StatusRequest {
                            value: extension_id,
                            data: StatusRequest {
                                certificate_status_type: CertificateStatusType::from(status.0),
                                responder_id_list,
                                request_extensions,
                            },
                        });
                    }
                }
                tls_parser::TlsExtension::EcPointFormats(formats) => {
                    client_hello.extensions.push(TlsExtension::EcPointFormats {
                        value: extension_id,
                        data: formats.iter().map(|f| ECPointFormat::from(*f)).collect(),
                    });
                }
                tls_parser::TlsExtension::ALPN(protocols) => {
                    client_hello.extensions.push(
                        TlsExtension::ApplicationLayerProtocolNegotiation {
                            value: extension_id,
                            data: protocols
                                .into_iter()
                                .map(|protocol| {
                                    String::from_utf8_lossy(protocol)
                                        .into_owned()
                                        .into_boxed_str()
                                })
                                .collect(),
                        },
                    );
                }
                tls_parser::TlsExtension::SignedCertificateTimestamp(timestamps) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SignedCertificateTimestamp {
                            value: extension_id,
                            data: timestamps.map(|data| hex_encode(data).into_boxed_str()),
                        });
                }
                tls_parser::TlsExtension::RenegotiationInfo(_) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::RenegotiationInfo {
                            value: extension_id,
                        });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(34), algorithms) => {
                    let extension =
                        parser::parse_tls_extension_delegated_credentials(extension_id, algorithms)
                            .map_err(|_| {
                                ClientHelloParseError::extension(
                                    ClientHelloParseStage::DelegatedCredentials,
                                    extension_id,
                                    algorithms.len(),
                                )
                            })?
                            .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::RecordSizeLimit(limit) => {
                    client_hello.extensions.push(TlsExtension::RecordSizeLimit {
                        value: extension_id,
                        data: limit,
                    });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(27), data) => {
                    let extension =
                        parser::parse_tls_extension_certificate_compression(extension_id, data)
                            .map_err(|_| {
                                ClientHelloParseError::extension(
                                    ClientHelloParseStage::CertificateCompression,
                                    extension_id,
                                    data.len(),
                                )
                            })?
                            .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(65037), data) => {
                    let extension = parser::parse_tls_extension_ech(extension_id, data)
                        .map_err(|_| {
                            ClientHelloParseError::extension(
                                ClientHelloParseStage::EncryptedClientHello,
                                extension_id,
                                data.len(),
                            )
                        })?
                        .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::Padding(padding) => {
                    client_hello.extensions.push(TlsExtension::Padding {
                        value: extension_id,
                        data: hex_encode(padding).into_boxed_str(),
                    });
                }
                tls_parser::TlsExtension::KeyShare(data) => {
                    client_hello.extensions.push(TlsExtension::KeyShare {
                        value: extension_id,
                        data: parser::parse_key_share(data)
                            .ok_or(ClientHelloParseError::extension(
                                ClientHelloParseStage::KeyShare,
                                extension_id,
                                data.len(),
                            ))?
                            .into_iter()
                            .map(|(group, key_exchange)| KeyShare::from_wire(group, key_exchange))
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::PskExchangeModes(data) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::PskKeyExchangeModes {
                            value: extension_id,
                            data: PskKeyExchangeModes {
                                ke_modes: data.into_iter().map(PskKeyExchangeMode::from).collect(),
                            },
                        });
                }
                tls_parser::TlsExtension::PreSharedKey(data) => {
                    client_hello.extensions.push(TlsExtension::PreSharedKey {
                        value: extension_id,
                        data: hex_encode(data).into_boxed_str(),
                    });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(17513), protocols) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::ApplicationSettingsOld {
                            value: extension_id,
                            data: parser::parse_alps_packet(protocols),
                        });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(17613), protocols) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::ApplicationSettings {
                            value: extension_id,
                            data: parser::parse_alps_packet(protocols),
                        });
                }
                tls_parser::TlsExtension::ExtendedMasterSecret => {
                    client_hello
                        .extensions
                        .push(TlsExtension::ExtendedMasterSecret {
                            value: extension_id,
                        });
                }
                tls_parser::TlsExtension::Grease(..) => {
                    client_hello.extensions.push(TlsExtension::Grease {
                        value: extension_id,
                    });
                }

                tls_parser::TlsExtension::MaxFragmentLength(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data.to_be_bytes()).into_boxed_str()),
                    });
                }
                tls_parser::TlsExtension::KeyShareOld(items) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(items).into_boxed_str()),
                    });
                }
                tls_parser::TlsExtension::EarlyData(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: data.map(|d| hex_encode(d.to_be_bytes()).into_boxed_str()),
                    });
                }
                tls_parser::TlsExtension::Cookie(items) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(items).into_boxed_str()),
                    });
                }
                tls_parser::TlsExtension::Heartbeat(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data.to_be_bytes()).into_boxed_str()),
                    });
                }
                tls_parser::TlsExtension::EncryptThenMac => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::OidFilters(oid_filters) => {
                    client_hello.extensions.push(TlsExtension::OidFilters {
                        value: extension_id,
                        data: oid_filters
                            .into_iter()
                            .map(|f| OidFilter {
                                cert_ext_oid: hex_encode(f.cert_ext_oid),
                                cert_ext_val: hex_encode(f.cert_ext_val),
                            })
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::PostHandshakeAuth => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::NextProtocolNegotiation => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::EncryptedServerName {
                    ciphersuite,
                    group,
                    key_share,
                    record_digest,
                    encrypted_sni,
                } => {
                    client_hello
                        .extensions
                        .push(TlsExtension::EncryptedServerName {
                            value: extension_id,
                            ciphersuite: tls_parser::TlsCipherSuite::from_id(ciphersuite.0)
                                .map(|c| c.name)
                                .unwrap_or("Unknown")
                                .into(),
                            group: NamedGroup::from(group.0),
                            key_share: hex_encode(key_share).into_boxed_str(),
                            record_digest: hex_encode(record_digest).into_boxed_str(),
                            encrypted_sni: hex_encode(encrypted_sni).into_boxed_str(),
                        });
                }

                tls_parser::TlsExtension::Unknown(_, data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data).into_boxed_str()),
                    });
                }
            }
        }

        Ok(client_hello)
    }

    /// Calculates the JA4 fingerprint and its unhashed source form.
    pub fn ja4(&self) -> Ja4Fingerprint {
        Ja4Fingerprint::from(self)
    }

    /// Calculates the JA3 source string and MD5 digest.
    pub fn ja3(&self) -> Ja3Fingerprint {
        Ja3Fingerprint::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientHello, ClientHelloBuffer, ClientHelloParseStage, KeyShare, TlsCipherSuite,
        TlsExtension, MAX_TLS_RECORD_LEN,
    };
    use crate::proto::tls::{CompressionAlgorithm, NamedGroup, TlsVersion};

    #[test]
    fn tls_cipher_suite_resolves_and_validates_ids_and_names() {
        let known = TlsCipherSuite::from_id(0x1301);
        assert_eq!(known.id, 0x1301);
        assert_eq!(known.name.as_ref(), "TLS_AES_128_GCM_SHA256");
        assert!(!known.is_grease());

        assert_eq!(
            TlsCipherSuite::from_name("TLS_AES_128_GCM_SHA256"),
            Some(known)
        );
        assert!(TlsCipherSuite::from_name("GREASE").is_none());

        let grease = TlsCipherSuite::from_id(0x0a0a);
        assert_eq!(grease.name.as_ref(), "GREASE");
        assert!(grease.is_grease());

        let unknown = TlsCipherSuite::from_id(0xffff);
        assert_eq!(unknown.name.as_ref(), "Unknown");
        assert!(!unknown.is_grease());

        let error = serde_json::from_value::<TlsCipherSuite>(serde_json::json!({
            "id": 0x1301,
            "name": "TLS_AES_256_GCM_SHA384"
        }))
        .expect_err("mismatched cipher-suite name must fail");
        assert!(
            error
                .to_string()
                .contains("has name \"TLS_AES_128_GCM_SHA256\""),
            "{error}"
        );
    }

    #[test]
    fn key_shares_serialize_id_name_and_optional_exchange_bytes() {
        let grease = KeyShare::from_wire(0x3a3a, vec![0x00]);

        assert_eq!(grease.id, 0x3a3a);
        assert_eq!(grease.name.as_ref(), "GREASE");
        assert_eq!(grease.key_exchange, None);

        let grease_json = serde_json::to_value(&grease).expect("GREASE KeyShare serializes");
        assert_eq!(
            grease_json,
            serde_json::json!({
                "id": 0x3a3a,
                "name": "GREASE"
            })
        );

        let x25519 = KeyShare::from_wire(29, vec![0x01, 0x02]);
        let x25519_json = serde_json::to_value(&x25519).expect("x25519 KeyShare serializes");
        assert_eq!(
            x25519_json,
            serde_json::json!({
                "id": 29,
                "name": "x25519",
                "value": "0102"
            })
        );

        assert_eq!(
            serde_json::from_value::<KeyShare>(grease_json).expect("GREASE KeyShare deserializes"),
            grease
        );
        assert_eq!(
            serde_json::from_value::<KeyShare>(x25519_json).expect("x25519 KeyShare deserializes"),
            x25519
        );

        assert!(serde_json::from_value::<KeyShare>(serde_json::json!({
            "id": 29,
            "name": "x25519"
        }))
        .is_err());
        assert!(serde_json::from_value::<KeyShare>(serde_json::json!({
            "id": 0x3a3a,
            "name": "GREASE",
            "value": "00"
        }))
        .is_err());
    }

    #[test]
    fn malformed_client_hello_reports_parse_stages() {
        let Err(record_error) = ClientHello::parse(&[]) else {
            panic!("expected malformed TLS record to fail");
        };
        assert_eq!(record_error.stage, ClientHelloParseStage::TlsRecord);
        assert_eq!(record_error.extension_id, None);
        assert_eq!(record_error.payload_len, None);

        let Err(message_error) = ClientHello::parse(&[0; 5]) else {
            panic!("expected malformed TLS messages to fail");
        };
        assert_eq!(message_error.stage, ClientHelloParseStage::RecordMessages);
        assert_eq!(message_error.extension_id, None);
        assert_eq!(message_error.payload_len, None);
    }

    #[test]
    fn client_hello_buffer_uses_requested_initial_capacity() {
        let mut buffer = ClientHelloBuffer::with_capacity(64);

        assert!(buffer.is_empty());
        assert!(buffer.buf.capacity() >= 64);
        assert_eq!(buffer.extend(&[1, 2, 3]), 3);
        assert_eq!(buffer.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn client_hello_buffer_distinguishes_incomplete_and_malformed_records() {
        let mut buffer = ClientHelloBuffer::from(vec![0; 4]);

        assert!(buffer.try_parse().unwrap().is_none());
        buffer.extend(&[0]);

        let error = buffer.try_parse().unwrap_err();
        assert_eq!(error.stage, ClientHelloParseStage::RecordMessages);
        assert_eq!(buffer.as_bytes(), &[0; 5]);

        let borrowed = ClientHelloBuffer::from(&[1, 2, 3][..]);
        assert_eq!(borrowed.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn client_hello_buffer_enforces_the_tls_record_limit() {
        let mut buffer = ClientHelloBuffer::new();
        let input = vec![0; MAX_TLS_RECORD_LEN + 16];

        assert_eq!(buffer.extend(&input), MAX_TLS_RECORD_LEN);
        assert_eq!(buffer.len(), MAX_TLS_RECORD_LEN);
        assert!(buffer.is_max_record_len());
        assert_eq!(buffer.extend(&[1, 2, 3]), 0);

        let oversized = ClientHelloBuffer::from(&[0x16, 0x03, 0x03, 0x41, 0x01][..]);
        let error = oversized.try_parse().unwrap_err();
        assert_eq!(error.stage, ClientHelloParseStage::TlsRecord);
    }

    #[test]
    fn client_hello_json_roundtrip_preserves_fingerprints() {
        let client_hello = ClientHello {
            tls_version: TlsVersion::TLSv1_2,
            tls_version_negotiated: Some(TlsVersion::TLSv1_3),
            cipher_suites: vec![TlsCipherSuite::from(0x0a0a), TlsCipherSuite::from(0x1301)],
            client_random: "00".repeat(32),
            session_id: None,
            compression_algorithms: vec![CompressionAlgorithm::Null],
            extensions: vec![
                TlsExtension::SupportedVersions {
                    value: 0x002b,
                    data: vec![TlsVersion::from(0x2a2a), TlsVersion::TLSv1_3],
                },
                TlsExtension::SupportedGroups {
                    value: 0x000a,
                    data: vec![NamedGroup::from(29), NamedGroup::from(0x4a4a)],
                },
            ],
        };
        let ja3 = client_hello.ja3();
        let ja4 = client_hello.ja4();
        let json = serde_json::to_value(&client_hello).expect("ClientHello serializes");

        assert_eq!(
            json["cipher_suites"],
            serde_json::json!([
                {
                    "id": 2570,
                    "name": "GREASE"
                },
                {
                    "id": 4865,
                    "name": "TLS_AES_128_GCM_SHA256"
                }
            ])
        );
        assert!(json.get("cipher_values").is_none());
        assert!(json.get("ciphers").is_none());

        let mut legacy_json = json.clone();
        let legacy_object = legacy_json
            .as_object_mut()
            .expect("ClientHello serializes as an object");
        let cipher_suites = legacy_object
            .remove("cipher_suites")
            .expect("cipher_suites is present");
        legacy_object.insert("ciphers".to_owned(), cipher_suites);
        assert!(serde_json::from_value::<ClientHello>(legacy_json).is_err());

        let restored: ClientHello =
            serde_json::from_value(json.clone()).expect("ClientHello deserializes");
        assert_eq!(restored, client_hello);
        assert_eq!(restored.ja3(), ja3);
        assert_eq!(restored.ja4(), ja4);
        assert_eq!(
            serde_json::to_value(restored).expect("restored ClientHello serializes"),
            json
        );
    }
}
