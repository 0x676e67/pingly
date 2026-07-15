//! TLS ClientHello data captured from the wire.
//!
//! See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2)
//! for the ClientHello layout and [Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3)
//! for its extension block.

use serde::Serialize;
use tls_parser::{TlsCipherSuite, TlsExtensionType, TlsMessage, TlsMessageHandshake};
use tokio_rustls::rustls::ProtocolVersion;

use hex::encode as hex_encode;

use super::{
    enums::{
        is_grease_value, AuthenticatedEncryptionWithAssociatedData,
        CertificateCompressionAlgorithm, CertificateStatusType, CompressionAlgorithm,
        ECPointFormat, KeyDerivationFunction, NamesGroup, PskKeyExchangeMode, SignatureAlgorithm,
        TlsVersion,
    },
    ja3::Ja3Fingerprint,
    ja4::Ja4Fingerprint,
    parser,
};

/// Buffers raw TLS record bytes so the ClientHello can be parsed after the handshake.
///
/// Deferring parsing keeps fingerprint analysis out of the handshake path. The buffer may be filled
/// incrementally when the ClientHello spans multiple reads.
#[derive(Clone)]
pub struct LazyClientHello {
    buf: Vec<u8>,
}

impl LazyClientHello {
    /// Creates an empty ClientHello buffer with capacity for a typical browser handshake.
    pub fn new() -> LazyClientHello {
        LazyClientHello {
            // Buffer size is set to match typical ClientHello message sizes sent by most browsers.
            // This helps minimize memory reallocations and is sufficient for almost all real-world
            // cases. Adjust this value if larger ClientHello payloads are encountered.
            buf: Vec::with_capacity(2048),
        }
    }

    /// Consumes the buffer and attempts to parse its first complete TLS ClientHello record.
    ///
    /// Returns `None` when the record, handshake message, or extension block is incomplete or
    /// malformed, or when the buffered record does not contain a ClientHello.
    pub fn parse(self) -> Option<ClientHello> {
        ClientHello::parse(&self.buf)
    }

    /// Returns whether the buffer has reached the maximum record length accepted by `tls-parser`.
    ///
    /// Callers use this as a stop condition; [`Self::extend`] does not enforce the limit itself.
    pub fn is_max_record_len(&self) -> bool {
        self.buf.len() >= tls_parser::MAX_RECORD_LEN.into()
    }

    /// Appends the next bytes read from the TLS connection.
    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }
}

/// A decoded TLS ClientHello and the negotiated version observed after the handshake.
///
/// Client-advertised vectors retain their wire order because order is significant to TLS client
/// fingerprinting.
///
/// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
#[derive(Clone, Serialize)]
pub struct ClientHello {
    /// The wire `legacy_version` field.
    ///
    /// A TLS 1.3 client normally sends TLS 1.2 (`0x0303`) here and advertises its real preferences
    /// through the `supported_versions` extension.
    pub(super) tls_version: TlsVersion,
    /// The protocol version selected by the server, or `None` before negotiation completes.
    pub(super) tls_version_negotiated: Option<TlsVersion>,
    /// Raw cipher-suite identifiers in client-advertised order.
    ///
    /// This includes unknown and GREASE values and is omitted from JSON because it is retained for
    /// fingerprint calculations.
    #[serde(skip)]
    pub(super) cipher_values: Vec<u16>,
    /// The 32-byte ClientHello random value encoded as lowercase hexadecimal.
    pub(super) client_random: String,
    /// The legacy session identifier encoded as lowercase hexadecimal, when present.
    pub(super) session_id: Option<String>,
    /// Compression methods in client-advertised order.
    pub(super) compression_algorithms: Vec<CompressionAlgorithm>,
    /// Names of recognized cipher suites in client-advertised order.
    ///
    /// Unknown and GREASE identifiers remain available in `cipher_values` but have no entry here.
    pub(super) ciphers: Vec<&'static str>,
    /// Decoded extensions in the order sent by the client.
    pub(super) extensions: Vec<TlsExtension>,
}

/// A decoded or preserved extension from a [`ClientHello`].
///
/// Every `value` field is the numeric `ExtensionType` observed on the wire. Byte-oriented payloads
/// are serialized as lowercase hexadecimal unless a variant documents another representation.
///
/// See [RFC 9846, Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3).
#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsExtension {
    /// Server names advertised through Server Name Indication (SNI).
    ///
    /// See [RFC 6066, Section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
    ServerName {
        /// Numeric extension type as observed on the wire.
        value: u16,
        /// Advertised names decoded as UTF-8, replacing malformed byte sequences when necessary.
        data: Vec<String>,
    },

    /// Named groups supported for key establishment.
    ///
    /// See [RFC 9846, Section 4.3.7](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.7).
    SupportedGroups {
        /// Numeric extension type as observed on the wire.
        value: u16,
        /// Named groups in client preference order.
        data: Vec<NamesGroup>,
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
        data: Vec<String>,
    },

    /// Protocol names from the former `0x4469` Application Settings code point.
    ///
    /// ALPS remains an Internet-Draft; see
    /// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
    ApplicationSettingsOld {
        /// Numeric extension type as observed on the wire.
        value: u16,
        /// Application protocol names carried by the extension.
        data: Vec<String>,
    },

    /// Protocol names from the current `0x44cd` Application Settings code point.
    ///
    /// ALPS remains an Internet-Draft; see
    /// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
    ApplicationSettings {
        /// Numeric extension type as observed on the wire.
        value: u16,
        /// Application protocol names carried by the extension.
        data: Vec<String>,
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
        data: String,
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
        data: Option<String>,
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
        data: String,
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
        data: String,
    },

    /// A legacy experimental Encrypted Server Name Indication (ESNI) offer.
    ///
    /// ESNI was replaced by ECH; see
    /// [draft-ietf-tls-esni-00](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-00).
    EncryptedServerName {
        /// Numeric extension type as observed on the wire.
        value: u16,
        /// Recognized TLS cipher-suite name, or `Unknown`.
        ciphersuite: &'static str,
        /// Named group used for the key share.
        group: NamesGroup,
        /// Key share bytes encoded as lowercase hexadecimal.
        key_share: String,
        /// ESNIKeys record digest encoded as lowercase hexadecimal.
        record_digest: String,
        /// Encrypted server-name bytes encoded as lowercase hexadecimal.
        encrypted_sni: String,
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
        data: Option<String>,
    },
}

impl TlsExtension {
    /// Returns the numeric `ExtensionType` observed on the wire.
    pub(super) fn value(&self) -> u16 {
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
#[derive(Clone, Serialize, Hash)]
pub struct StatusRequest {
    /// The certificate status protocol requested by the client.
    certificate_status_type: CertificateStatusType,
    /// Declared byte length of the OCSP responder ID list.
    responder_id_list: u16,
    /// Declared byte length of the OCSP request extensions.
    request_extensions: u16,
}

/// The outer or inner form of an Encrypted ClientHello extension.
///
/// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
#[derive(Clone, Serialize, Hash)]
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
#[derive(Clone, Serialize, Hash)]
pub struct ECHClientHelloOuter {
    /// The HPKE KDF and AEAD pair used to encrypt ClientHelloInner.
    pub cipher_suite: HpkeSymmetricCipherSuite,
    /// The selected ECH configuration identifier.
    pub config_id: u8,
    /// The HPKE encapsulated key encoded as lowercase hexadecimal.
    ///
    /// This can be empty in a ClientHelloOuter sent after HelloRetryRequest.
    pub enc: String,
    /// The encoded `uint16` length of the encrypted payload in bytes.
    ///
    /// This is retained explicitly because `payload` is exposed as hexadecimal text.
    pub payload_length: u16,
    /// The encrypted EncodedClientHelloInner bytes encoded as lowercase hexadecimal.
    ///
    /// Its decoded byte length is recorded in `payload_length`.
    pub payload: String,
}

/// The HPKE KDF and AEAD pair selected for ECH encryption.
///
/// See [RFC 9849, Section 4](https://www.rfc-editor.org/rfc/rfc9849.html#section-4) and
/// [RFC 9180, Section 7.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2).
#[derive(Clone, Serialize, Hash)]
pub struct HpkeSymmetricCipherSuite {
    /// The HPKE key derivation function identifier.
    pub kdf_id: KeyDerivationFunction,
    /// The HPKE authenticated-encryption algorithm identifier.
    pub aead_id: AuthenticatedEncryptionWithAssociatedData,
}

/// An ephemeral key share offered by the client.
///
/// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
#[derive(Clone, Serialize, Hash)]
pub struct KeyShare {
    /// The named group for which the key was generated.
    pub name: NamesGroup,
    /// The opaque `key_exchange` bytes encoded as lowercase hexadecimal.
    pub value: String,
}

/// Pre-shared-key key exchange modes offered by the client.
///
/// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
#[derive(Clone, Serialize, Hash)]
pub struct PskKeyExchangeModes {
    /// Modes in client preference order.
    pub ke_modes: Vec<PskKeyExchangeMode>,
}

/// A certificate-extension filter from the ClientHello `oid_filters` extension.
///
/// See [RFC 9846, Section 4.3.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.5).
#[derive(Clone, Debug, PartialEq, Serialize, Hash)]
pub struct OidFilter {
    /// The DER-encoded certificate extension OID, represented as lowercase hexadecimal.
    pub cert_ext_oid: String,
    /// The required certificate extension value, represented as lowercase hexadecimal.
    pub cert_ext_val: String,
}

struct ClientHelloParseError {
    stage: &'static str,
    extension_id: Option<u16>,
    payload_len: Option<usize>,
}

impl ClientHelloParseError {
    const fn new(stage: &'static str) -> Self {
        Self {
            stage,
            extension_id: None,
            payload_len: None,
        }
    }

    const fn extension(stage: &'static str, extension_id: u16, payload_len: usize) -> Self {
        Self {
            stage,
            extension_id: Some(extension_id),
            payload_len: Some(payload_len),
        }
    }
}

impl ClientHello {
    /// Records the protocol version selected by rustls after the handshake.
    ///
    /// Passing `None` clears a previously recorded negotiated version.
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.tls_version_negotiated = version.map(u16::from).map(TlsVersion::from);
    }

    /// Parses the first ClientHello from a complete TLS record.
    ///
    /// Returns `None` if the record or handshake is malformed, no ClientHello is present, the
    /// extension block is absent, or a supported extension cannot be decoded. Unknown cipher-suite
    /// identifiers are retained for fingerprinting but omitted from the human-readable cipher list.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        match Self::try_parse(buf) {
            Ok(client_hello) => {
                tracing::debug!(
                    record_len = buf.len(),
                    legacy_version = %client_hello.tls_version,
                    cipher_count = client_hello.cipher_values.len(),
                    extension_count = client_hello.extensions.len(),
                    "parsed TLS ClientHello",
                );
                Some(client_hello)
            }
            Err(error) => {
                tracing::debug!(
                    record_len = buf.len(),
                    stage = error.stage,
                    extension_id = ?error.extension_id,
                    payload_len = ?error.payload_len,
                    "failed to parse TLS ClientHello",
                );
                None
            }
        }
    }

    fn try_parse(buf: &[u8]) -> Result<Self, ClientHelloParseError> {
        let (_, r) = tls_parser::parse_tls_raw_record(buf)
            .map_err(|_| ClientHelloParseError::new("tls_record"))?;
        let (_, msg_list) = tls_parser::parse_tls_record_with_header(r.data, &r.hdr)
            .map_err(|_| ClientHelloParseError::new("record_messages"))?;

        let payload = msg_list
            .into_iter()
            .find_map(|msg| {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(payload)) = msg {
                    Some(payload)
                } else {
                    None
                }
            })
            .ok_or(ClientHelloParseError::new("client_hello"))?;

        let mut cipher_values = Vec::with_capacity(payload.ciphers.len());
        let mut ciphers = Vec::with_capacity(payload.ciphers.len());
        for cipher in &payload.ciphers {
            cipher_values.push(cipher.0);
            if let Some(cipher) = TlsCipherSuite::from_id(cipher.0) {
                ciphers.push(cipher.name);
            }
        }

        let mut client_hello = ClientHello {
            tls_version: TlsVersion::from(payload.version.0),
            tls_version_negotiated: None,
            cipher_values,
            client_random: hex_encode(payload.random),
            session_id: payload.session_id.map(hex_encode),
            compression_algorithms: payload
                .comp
                .iter()
                .map(|c| CompressionAlgorithm::from(c.0))
                .collect(),
            ciphers,
            extensions: Vec::with_capacity(5),
        };

        let ext = payload
            .ext
            .ok_or(ClientHelloParseError::new("extension_block"))?;
        let (_, ext_list) = tls_parser::parse_tls_client_hello_extensions(ext)
            .map_err(|_| ClientHelloParseError::new("extensions"))?;

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
                            .map(|n| String::from_utf8_lossy(n).to_string())
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::EllipticCurves(groups) => {
                    client_hello.extensions.push(TlsExtension::SupportedGroups {
                        value: extension_id,
                        data: groups.into_iter().map(|g| NamesGroup::from(g.0)).collect(),
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
                        data: hex_encode(data),
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
                                    "status_request",
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
                                .map(|protocol| String::from_utf8_lossy(protocol).to_string())
                                .collect(),
                        },
                    );
                }
                tls_parser::TlsExtension::SignedCertificateTimestamp(timestamps) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SignedCertificateTimestamp {
                            value: extension_id,
                            data: timestamps.map(hex_encode),
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
                                    "delegated_credentials",
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
                                    "certificate_compression",
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
                                "encrypted_client_hello",
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
                        data: hex_encode(padding),
                    });
                }
                tls_parser::TlsExtension::KeyShare(data) => {
                    client_hello.extensions.push(TlsExtension::KeyShare {
                        value: extension_id,
                        data: parser::parse_key_share(data)
                            .ok_or(ClientHelloParseError::extension(
                                "key_share",
                                extension_id,
                                data.len(),
                            ))?
                            .into_iter()
                            .map(|data| KeyShare {
                                name: NamesGroup::from(data.0),
                                value: hex_encode(data.1),
                            })
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
                        data: hex_encode(data),
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
                        data: Some(hex_encode(data.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::KeyShareOld(items) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(items)),
                    });
                }
                tls_parser::TlsExtension::EarlyData(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: data.map(|d| hex_encode(d.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::Cookie(items) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(items)),
                    });
                }
                tls_parser::TlsExtension::Heartbeat(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data.to_be_bytes())),
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
                                .unwrap_or("Unknown"),
                            group: NamesGroup::from(group.0),
                            key_share: hex_encode(key_share),
                            record_digest: hex_encode(record_digest),
                            encrypted_sni: hex_encode(encrypted_sni),
                        });
                }

                tls_parser::TlsExtension::Unknown(_, data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data)),
                    });
                }
            }
        }

        Ok(client_hello)
    }

    /// Calculates the JA4 fingerprint and its unhashed source form.
    pub(crate) fn ja4_fingerprint(&self) -> (String, String) {
        let ja4 = Ja4Fingerprint::from_client_hello(self);
        (ja4.fingerprint, ja4.raw)
    }

    /// Calculates the JA3 source string and MD5 digest.
    pub(crate) fn ja3_fingerprint(&self) -> (String, String) {
        let ja3 = Ja3Fingerprint::from_client_hello(self);
        (ja3.raw, ja3.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::ClientHello;

    #[test]
    fn malformed_client_hello_reports_parse_stages() {
        let Err(record_error) = ClientHello::try_parse(&[]) else {
            panic!("expected malformed TLS record to fail");
        };
        assert_eq!(record_error.stage, "tls_record");
        assert_eq!(record_error.extension_id, None);
        assert_eq!(record_error.payload_len, None);

        let Err(message_error) = ClientHello::try_parse(&[0; 5]) else {
            panic!("expected malformed TLS messages to fail");
        };
        assert_eq!(message_error.stage, "record_messages");
        assert_eq!(message_error.extension_id, None);
        assert_eq!(message_error.payload_len, None);
    }
}
