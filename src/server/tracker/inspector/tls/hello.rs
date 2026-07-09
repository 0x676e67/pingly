//! See: <https://www.rfc-editor.org/rfc/rfc8446#section-4.2>

use std::fmt::Write;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tls_parser::{TlsCipherSuite, TlsExtensionType, TlsMessage, TlsMessageHandshake};
use tokio_rustls::rustls::ProtocolVersion;

use crate::encoding::hex_encode;

use super::{
    enums::{
        is_grease, AuthenticatedEncryptionWithAssociatedData, CertificateCompressionAlgorithm,
        CertificateStatusType, CompressionAlgorithm, ECPointFormat, KeyDerivationFunction,
        NamesGroup, PskKeyExchangeMode, SignatureAlgorithm, TlsVersion,
    },
    parser,
};

/// `LazyClientHello` is a buffer for accumulating raw TLS ClientHello data during the handshake
/// phase. It allows incremental appending of data and supports deferred (lazy) parsing into a
/// structured `ClientHello` only when needed, without interfering with the TLS handshake process.
#[derive(Clone)]
pub struct LazyClientHello {
    buf: Vec<u8>,
}

impl LazyClientHello {
    /// Creates a new, empty buffer for accumulating ClientHello data.
    pub fn new() -> LazyClientHello {
        LazyClientHello {
            // Buffer size is set to match typical ClientHello message sizes sent by most browsers.
            // This helps minimize memory reallocations and is sufficient for almost all real-world
            // cases. Adjust this value if larger ClientHello payloads are encountered.
            buf: Vec::with_capacity(2048),
        }
    }

    /// Attempts to parse a TLS ClientHello message from the buffered data.
    /// Returns `Some(ClientHello)` if parsing succeeds, otherwise `None`.
    pub fn parse(self) -> Option<ClientHello> {
        ClientHello::parse(&self.buf)
    }

    /// Returns `true` if the buffered data has reached the maximum TLS record length.
    /// This can be used to determine if further buffering is unnecessary.
    pub fn is_max_record_len(&self) -> bool {
        self.buf.len() >= tls_parser::MAX_RECORD_LEN.into()
    }

    /// Appends additional data to the internal buffer.
    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }
}

/// Represents a TLS Client Hello message.
#[derive(Clone, Serialize)]
pub struct ClientHello {
    /// TLS version of message
    tls_version: TlsVersion,
    /// The final TLS version negotiated during the handshake
    tls_version_negotiated: Option<TlsVersion>,
    #[serde(skip)]
    cipher_values: Vec<u16>,
    client_random: String,
    session_id: Option<String>,
    /// A list of compression methods supported by client
    compression_algorithms: Vec<CompressionAlgorithm>,
    /// A list of ciphers supported by client
    ciphers: Vec<&'static str>,
    /// A list of extensions supported by client
    extensions: Vec<TlsExtension>,
}

/// JA3 TLS client fingerprint and its MD5 hash.
struct Ja3Fingerprint {
    raw: String,
    hash: String,
}

/// JA4 TLS client fingerprint, plus the raw material used to produce the hash chunks.
struct Ja4Fingerprint {
    fingerprint: String,
    raw: String,
}

/// Extensions that can be set in a [`ClientHello`] message by a TLS client.
#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsExtension {
    /// Server Name Indication (SNI), used for virtual hosting.
    ServerName { value: u16, data: Vec<String> },

    /// Supported elliptic curve groups for key exchange.
    SupportedGroups { value: u16, data: Vec<NamesGroup> },

    /// Supported EC point formats for key exchange.
    EcPointFormats {
        value: u16,
        data: Vec<ECPointFormat>,
    },

    /// Supported signature algorithms for authentication.
    SignatureAlgorithms {
        value: u16,
        data: Vec<SignatureAlgorithm>,
    },

    /// OCSP stapling support (status request).
    StatusRequest { value: u16, data: StatusRequest },

    /// Application-Layer Protocol Negotiation (ALPN), e.g., for HTTP/2.
    ApplicationLayerProtocolNegotiation { value: u16, data: Vec<String> },

    /// Old Application Settings extension (non-standard).
    ApplicationSettingsOld { value: u16, data: Vec<String> },

    /// Application Settings extension (used for ALPS in HTTP/2/3).
    ApplicationSettings { value: u16, data: Vec<String> },

    /// Supported TLS protocol versions.
    SupportedVersions { value: u16, data: Vec<TlsVersion> },

    /// Session ticket for session resumption.
    SessionTicket { value: u16, data: String },

    /// Supported certificate compression algorithms.
    CertificateCompression {
        value: u16,
        data: Vec<CertificateCompressionAlgorithm>,
    },

    /// Record size limit for TLS records.
    RecordSizeLimit { value: u16, data: u16 },

    /// Delegated credentials for authentication.
    DelegatedCredentials {
        value: u16,
        data: Vec<SignatureAlgorithm>,
    },

    /// Encrypted ClientHello (ECH) extension.
    EncryptedClientHello { value: u16, data: ECHClientHello },

    /// Signed Certificate Timestamp (SCT) for certificate transparency.
    SignedCertificateTimestamp {
        value: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
    },

    /// Renegotiation info for secure renegotiation.
    RenegotiationInfo { value: u16 },

    /// Extended Master Secret extension for improved security.
    ExtendedMasterSecret { value: u16 },

    /// Padding extension to obscure ClientHello length.
    Padding { value: u16, data: String },

    /// Key share entries for key exchange (TLS 1.3).
    KeyShare { value: u16, data: Vec<KeyShare> },

    /// PSK key exchange modes (TLS 1.3).
    PskKeyExchangeModes {
        value: u16,
        data: PskKeyExchangeModes,
    },

    /// Pre-shared key for session resumption or 0-RTT.
    PreSharedKey { value: u16, data: String },

    /// Encrypted Server Name Indication (ESNI) extension.
    EncryptedServerName {
        value: u16,
        ciphersuite: &'static str,
        group: NamesGroup,
        key_share: String,
        record_digest: String,
        encrypted_sni: String,
    },

    /// Oid filters for certificate extensions.
    OidFilters { value: u16, data: Vec<OidFilter> },

    /// GREASE value for protocol extensibility testing.
    Grease { value: u16 },

    /// Any unknown or unsupported extension.
    Opaque { value: u16, data: Option<String> },
}

impl TlsExtension {
    fn value(&self) -> u16 {
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
}

/// StatusRequest extension data
///
/// See: <https://www.rfc-editor.org/rfc/rfc6066#section-8>
#[derive(Clone, Serialize, Hash)]
pub struct StatusRequest {
    certificate_status_type: CertificateStatusType,
    responder_id_list: u16,
    request_extensions: u16,
}

/// Client Hello contents send by ECH
#[derive(Clone, Serialize, Hash)]
pub enum ECHClientHello {
    /// Send when message is in the outer (unencrypted) part of client hello. It contains
    /// encryption data and the encrypted client hello.
    Outer(ECHClientHelloOuter),
    /// The inner extension has an empty payload, which is included because TLS servers are
    /// not allowed to provide extensions in ServerHello which were not included in ClientHello.
    /// And when using encrypted client hello the server will discard the outer unencrypted one,
    /// and only look at the encrypted client hello. So we have to add this extension again there
    /// so the server knows ECH is supported by the client.
    Inner,
}

/// Data send by ech hello message when it is in the outer part
#[derive(Clone, Serialize, Hash)]
pub struct ECHClientHelloOuter {
    pub cipher_suite: HpkeSymmetricCipherSuite,
    pub config_id: u8,
    pub enc: String,
    pub payload: String,
}

/// HPKE KDF and AEAD pair used to encrypt ClientHello
#[derive(Clone, Serialize, Hash)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: KeyDerivationFunction,
    pub aead_id: AuthenticatedEncryptionWithAssociatedData,
}

/// Key shares used in ClientHello
///
/// See: <https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8>
#[derive(Clone, Serialize, Hash)]
pub struct KeyShare {
    pub name: NamesGroup,
    pub value: String,
}

/// PSK Key Exchange Modes
#[derive(Clone, Serialize, Hash)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode>,
}

/// Represents a filter for OID extensions in certificates.
#[derive(Clone, Debug, PartialEq, Serialize, Hash)]
pub struct OidFilter {
    pub cert_ext_oid: String,
    pub cert_ext_val: String,
}

impl ClientHello {
    /// Sets the negotiated TLS version for this `ClientHello`.
    ///
    /// # Parameters
    /// - `version`: An `Option<ProtocolVersion>` representing the negotiated TLS version. If
    ///   `Some`, the version is set; if `None`, no version was negotiated.
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.tls_version_negotiated = version.map(u16::from).map(TlsVersion::from);
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        let (_, r) = tls_parser::parse_tls_raw_record(buf).ok()?;
        let (_, msg_list) = tls_parser::parse_tls_record_with_header(r.data, &r.hdr).ok()?;

        let payload = msg_list.into_iter().find_map(|msg| {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(payload)) = msg {
                Some(payload)
            } else {
                None
            }
        })?;

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

        let ext = payload.ext?;
        let (_, ext_list) = tls_parser::parse_tls_client_hello_extensions(ext).ok()?;

        for ext in ext_list {
            let extension_id = TlsExtensionType::from(&ext).0;

            match ext {
                tls_parser::TlsExtension::SNI(name) => {
                    tracing::debug!("ClientHello: SNI extension: {name:?}");

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
                    tracing::debug!("ClientHello: EllipticCurves extension: {groups:?}");

                    client_hello.extensions.push(TlsExtension::SupportedGroups {
                        value: extension_id,
                        data: groups.into_iter().map(|g| NamesGroup::from(g.0)).collect(),
                    });
                }
                tls_parser::TlsExtension::SupportedVersions(versions) => {
                    tracing::debug!("ClientHello: SupportedVersions extension: {versions:?}");

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
                    tracing::debug!("ClientHello: SessionTicket extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::SessionTicket {
                        value: extension_id,
                        data: hex_encode(data),
                    });
                }
                tls_parser::TlsExtension::SignatureAlgorithms(algorithms) => {
                    tracing::debug!("ClientHello: SignatureAlgorithms extension: {algorithms:?}");

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
                    tracing::debug!("ClientHello: StatusRequest extension: {data:?}");

                    if let Some((status, data)) = data {
                        let (_, (responder_id_list, request_extensions)) =
                            parser::parse_ocsp_status_request_lengths(data).ok()?;
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
                    tracing::debug!("ClientHello: ECPointFormats extension: {formats:?}");

                    client_hello.extensions.push(TlsExtension::EcPointFormats {
                        value: extension_id,
                        data: formats.iter().map(|f| ECPointFormat::from(*f)).collect(),
                    });
                }
                tls_parser::TlsExtension::ALPN(protocols) => {
                    tracing::debug!("ClientHello: ALPN extension: {protocols:?}");

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
                    tracing::debug!("ClientHello: SCT extension: {timestamps:?}");

                    client_hello
                        .extensions
                        .push(TlsExtension::SignedCertificateTimestamp {
                            value: extension_id,
                            data: timestamps.map(hex_encode),
                        });
                }
                tls_parser::TlsExtension::RenegotiationInfo(data) => {
                    tracing::debug!("ClientHello: RenegotiationInfo extension: {data:?}");

                    client_hello
                        .extensions
                        .push(TlsExtension::RenegotiationInfo {
                            value: extension_id,
                        });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(34), algorithms) => {
                    tracing::debug!("ClientHello: DelegatedCredentials extension: {algorithms:?}");

                    let extension =
                        parser::parse_tls_extension_delegated_credentials(extension_id, algorithms)
                            .ok()?
                            .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::RecordSizeLimit(limit) => {
                    tracing::debug!("ClientHello: RecordSizeLimit extension: {limit:?}");

                    client_hello.extensions.push(TlsExtension::RecordSizeLimit {
                        value: extension_id,
                        data: limit,
                    });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(27), data) => {
                    tracing::debug!("ClientHello: CertificateCompression extension: {data:?}");

                    let extension =
                        parser::parse_tls_extension_certificate_compression(extension_id, data)
                            .ok()?
                            .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(65037), data) => {
                    tracing::debug!("ClientHello: EncryptedClientHello extension: {data:?}");

                    let extension = parser::parse_tls_extension_ech(extension_id, data).ok()?.1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::Padding(padding) => {
                    tracing::debug!("ClientHello: Padding extension");

                    client_hello.extensions.push(TlsExtension::Padding {
                        value: extension_id,
                        data: hex_encode(padding),
                    });
                }
                tls_parser::TlsExtension::KeyShare(data) => {
                    tracing::debug!("ClientHello: KeyShare extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::KeyShare {
                        value: extension_id,
                        data: parser::parse_key_share(data)?
                            .into_iter()
                            .map(|data| KeyShare {
                                name: NamesGroup::from(data.0),
                                value: hex_encode(data.1),
                            })
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::PskExchangeModes(data) => {
                    tracing::debug!("ClientHello: PskExchangeModes extension: {data:?}");

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
                    tracing::debug!("ClientHello: PreSharedKey extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::PreSharedKey {
                        value: extension_id,
                        data: hex_encode(data),
                    });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(17513), protocols) => {
                    tracing::debug!(
                        "ClientHello: Old Application Settings extension: {protocols:?}"
                    );

                    client_hello
                        .extensions
                        .push(TlsExtension::ApplicationSettingsOld {
                            value: extension_id,
                            data: parser::parse_alps_packet(protocols),
                        });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(17613), protocols) => {
                    tracing::debug!("ClientHello: Application Settings extension: {protocols:?}");

                    client_hello
                        .extensions
                        .push(TlsExtension::ApplicationSettings {
                            value: extension_id,
                            data: parser::parse_alps_packet(protocols),
                        });
                }
                tls_parser::TlsExtension::ExtendedMasterSecret => {
                    tracing::debug!("ClientHello: ExtendedMasterSecret extension");

                    client_hello
                        .extensions
                        .push(TlsExtension::ExtendedMasterSecret {
                            value: extension_id,
                        });
                }
                tls_parser::TlsExtension::Grease(id, data) => {
                    tracing::debug!("ClientHello: Grease extension: {id:?}, {data:?}");

                    client_hello.extensions.push(TlsExtension::Grease {
                        value: extension_id,
                    });
                }

                tls_parser::TlsExtension::MaxFragmentLength(data) => {
                    tracing::debug!("ClientHello: MaxFragmentLength extension");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::KeyShareOld(items) => {
                    tracing::debug!("ClientHello: KeyShareOld extension: {items:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(items)),
                    });
                }
                tls_parser::TlsExtension::EarlyData(data) => {
                    tracing::debug!("ClientHello: EarlyData extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: data.map(|d| hex_encode(d.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::Cookie(items) => {
                    tracing::debug!("ClientHello: Cookie extension: {items:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(items)),
                    });
                }
                tls_parser::TlsExtension::Heartbeat(data) => {
                    tracing::debug!("ClientHello: Heartbeat extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::EncryptThenMac => {
                    tracing::debug!("ClientHello: EncryptThenMac extension");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::OidFilters(oid_filters) => {
                    tracing::debug!("ClientHello: OidFilters extension: {oid_filters:?}");

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
                    tracing::debug!("ClientHello: PostHandshakeAuth extension");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::NextProtocolNegotiation => {
                    tracing::debug!("ClientHello: NextProtocolNegotiation extension");

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
                    tracing::debug!("ClientHello: EncryptedServerName extension");

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

                tls_parser::TlsExtension::Unknown(id, data) => {
                    tracing::debug!("ClientHello: Unknown extension: {id:?}, {data:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex_encode(data)),
                    });
                }
            }
        }

        Some(client_hello)
    }

    pub(crate) fn ja4_fingerprint(&self) -> (String, String) {
        let ja4 = Ja4Fingerprint::from_client_hello(self);
        (ja4.fingerprint, ja4.raw)
    }

    pub(crate) fn ja3_fingerprint(&self) -> (String, String) {
        let ja3 = Ja3Fingerprint::from_client_hello(self);
        (ja3.raw, ja3.hash)
    }
}

impl Ja3Fingerprint {
    fn from_client_hello(client_hello: &ClientHello) -> Self {
        let mut cipher_list = String::new();
        push_dec_list(
            &mut cipher_list,
            client_hello
                .cipher_values
                .iter()
                .copied()
                .filter(|value| !is_grease(*value)),
        );

        let mut extension_list = String::new();
        let mut supported_group_list = String::new();
        let mut point_format_list = String::new();

        for extension in &client_hello.extensions {
            let value = extension.value();
            if is_grease(value) {
                continue;
            }

            push_dec_list(&mut extension_list, [value]);

            match extension {
                TlsExtension::SupportedGroups { data, .. } => {
                    push_dec_list(
                        &mut supported_group_list,
                        data.iter()
                            .map(|group| group.value())
                            .filter(|value| !is_grease(*value)),
                    );
                }
                TlsExtension::EcPointFormats { data, .. } => {
                    push_dec_list(
                        &mut point_format_list,
                        data.iter().map(|format| u16::from(format.value())),
                    );
                }
                _ => {}
            }
        }

        let raw = format!(
            "{},{},{},{},{}",
            client_hello.tls_version.value(),
            cipher_list,
            extension_list,
            supported_group_list,
            point_format_list
        );
        let hash = md5_hex(&raw);

        Self { raw, hash }
    }
}

impl Ja4Fingerprint {
    const TLS_EXT_SERVER_NAME: u16 = 0;
    const TLS_EXT_ALPN: u16 = 16;
    const TLS_EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 57;

    fn from_client_hello(client_hello: &ClientHello) -> Self {
        let mut ciphers = client_hello.cipher_values.clone();
        ciphers.retain(|value| !is_grease(*value));

        let mut extensions = Vec::with_capacity(client_hello.extensions.len());
        let mut supported_versions = Vec::new();
        let mut signature_algorithms = Vec::new();
        let mut alpn = (None, None);
        let mut extension_count = 0usize;
        let mut has_server_name = false;
        let mut has_quic_transport_parameters = false;

        for extension in &client_hello.extensions {
            let value = extension.value();
            if is_grease(value) {
                continue;
            }

            extension_count += 1;
            has_server_name |= value == Self::TLS_EXT_SERVER_NAME;
            has_quic_transport_parameters |= value == Self::TLS_EXT_QUIC_TRANSPORT_PARAMETERS;

            match extension {
                TlsExtension::SupportedVersions { data, .. } => {
                    supported_versions.extend(data.iter().map(|version| version.value()));
                }
                TlsExtension::SignatureAlgorithms { data, .. } => {
                    signature_algorithms.extend(data.iter().map(|algorithm| algorithm.value()));
                }
                TlsExtension::ApplicationLayerProtocolNegotiation { data, .. }
                    if alpn.0.is_none() =>
                {
                    if let Some(protocol) = data.first() {
                        alpn = first_last(protocol);
                    }
                }
                _ => {}
            }

            if !matches!(value, Self::TLS_EXT_SERVER_NAME | Self::TLS_EXT_ALPN) {
                extensions.push(value);
            }
        }

        let cipher_count = ciphers.len().min(99);
        let extension_count = extension_count.min(99);

        ciphers.sort_unstable();
        extensions.sort_unstable();

        let mut cipher_list = String::new();
        push_hex_list(&mut cipher_list, ciphers);

        let mut extension_signature_list = String::new();
        push_hex_list(&mut extension_signature_list, extensions);
        if !signature_algorithms.is_empty() {
            extension_signature_list.push('_');
            push_hex_list(&mut extension_signature_list, signature_algorithms);
        }

        let first_chunk = format!(
            "{transport}{version}{sni}{cipher_count:02}{extension_count:02}{alpn_first}{alpn_last}",
            transport = if has_quic_transport_parameters {
                'q'
            } else {
                't'
            },
            version = TlsVersion::ja4_code_from_client_hello(
                client_hello.tls_version.value(),
                supported_versions
            ),
            sni = if has_server_name { 'd' } else { 'i' },
            cipher_count = cipher_count,
            extension_count = extension_count,
            alpn_first = alpn.0.unwrap_or('0'),
            alpn_last = alpn.1.unwrap_or('0'),
        );

        let fingerprint = format!(
            "{first_chunk}_{cipher_hash}_{extension_signature_hash}",
            cipher_hash = hash12(&cipher_list),
            extension_signature_hash = hash12(&extension_signature_list),
        );
        let raw = format!("{first_chunk}_{cipher_list}_{extension_signature_list}");

        Self { fingerprint, raw }
    }
}

fn push_hex_list(out: &mut String, values: impl IntoIterator<Item = u16>) {
    for value in values {
        if !out.is_empty() && !out.ends_with('_') {
            out.push(',');
        }
        let _ = write!(out, "{value:04x}");
    }
}

fn push_dec_list(out: &mut String, values: impl IntoIterator<Item = u16>) {
    for value in values {
        if !out.is_empty() {
            out.push('-');
        }
        let _ = write!(out, "{value}");
    }
}

fn md5_hex(input: &str) -> String {
    let hash = md5::compute(input);
    hex_encode(hash.as_slice())
}

fn hash12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_owned();
    }

    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn first_last(value: &str) -> (Option<char>, Option<char>) {
    let mut chars = value
        .chars()
        .map(|value| if value.is_ascii() { value } else { '9' });

    let first = chars.next();
    let last = chars.next_back();
    (first, last)
}

#[cfg(test)]
mod tests {
    use super::{hash12, ClientHello, Ja3Fingerprint, Ja4Fingerprint, TlsExtension};
    use crate::server::tracker::inspector::tls::enums::{
        is_grease, ECPointFormat, NamesGroup, SignatureAlgorithm, TlsVersion,
    };

    #[test]
    fn ja4_matches_foxio_reference_vector() {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let signature_algorithms = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];

        let client_hello = client_hello_for_ja4(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &signature_algorithms,
        );
        let fingerprint = Ja4Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.fingerprint,
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
        assert_eq!(
            fingerprint.raw,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn ja3_matches_reference_vector() {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let client_hello = client_hello_for_fingerprints(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &[],
            &[0x001d, 0x0017, 0x0018],
            &[0],
        );
        let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.raw,
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-0-51-16-17513-23-45-13-5-35-18-43-65281-11-10-21,29-23-24,0"
        );
        assert_eq!(fingerprint.hash, "c000e2caf3a25423f9de6c8a4b12a975");
    }

    #[test]
    fn chrome_browser_sample_matches_observed_fingerprints() {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x44cd, 0x002b, 0x002d, 0x000b, 0x000d, 0x0005, 0x0023, 0xff01, 0x0010, 0x0033, 0x0000,
            0x0012, 0x001b, 0xfe0d, 0x000a, 0x0017,
        ];
        let signature_algorithms = [
            0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let client_hello = client_hello_for_fingerprints(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &signature_algorithms,
            &[0x11ec, 0x001d, 0x0017, 0x0018],
            &[0],
        );

        assert_fingerprints(
            &client_hello,
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17613-43-45-11-13-5-35-65281-16-51-0-18-27-65037-10-23,4588-29-23-24,0",
            "d58a2a07a227719c6c34bd6f2dbd44de",
            "t13d1516h2_8daaf6152771_806a8c22fdea",
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601",
        );
    }

    #[test]
    fn firefox_browser_sample_matches_observed_fingerprints() {
        let ciphers = [
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b,
            0x000d, 0x002d, 0x001c, 0x001b, 0xfe0d, 0x0029,
        ];
        let signature_algorithms = [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ];
        let client_hello = client_hello_for_fingerprints(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &signature_algorithms,
            &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
            &[0],
        );

        assert_fingerprints(
            &client_hello,
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0",
            "f19d54c853fffdd9eeab77ae607448e9",
            "t13d1617h2_86a278354501_e6dcd7ae0a9e",
            "t13d1617h2_002f,0035,009c,009d,1301,1302,1303,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
        );
    }

    #[test]
    fn ja3_filters_grease_values() {
        let client_hello = client_hello_for_fingerprints(
            &[0x0a0a, 0x1301],
            &[0x0a0a, 0x0000, 0x0010, 0x000a, 0x000b, 0x000d],
            &[],
            &[],
            &[0x0a0a, 0x001d],
            &[0],
        );
        let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello);

        assert_eq!(fingerprint.raw, "771,4865,0-16-10-11-13,29,0");
        assert_eq!(fingerprint.hash, "8b24de13bfb91159e7fc8865273b000d");
    }

    #[test]
    fn ja4_filters_grease_before_counting_and_hashing() {
        let client_hello = client_hello_for_ja4(
            &[0x0a0a, 0x1301],
            &[0x0a0a, 0x0000, 0x0010, 0x000d],
            &[0x2a2a, 0x0304],
            &[],
        );
        let fingerprint = Ja4Fingerprint::from_client_hello(&client_hello);

        assert!(is_grease(0x0a0a));
        assert!(!is_grease(0x0a0b));
        assert_eq!(fingerprint.raw, "t12d0103h2_1301_000d");
    }

    #[test]
    fn hash12_uses_zeros_for_empty_input() {
        assert_eq!(hash12("551d0f,551d25,551d11"), "aae71e8db6d7");
        assert_eq!(hash12(""), "000000000000");
    }

    fn assert_fingerprints(
        client_hello: &ClientHello,
        expected_ja3: &str,
        expected_ja3_hash: &str,
        expected_ja4: &str,
        expected_ja4_raw: &str,
    ) {
        let ja3 = Ja3Fingerprint::from_client_hello(client_hello);
        assert_eq!(ja3.raw, expected_ja3);
        assert_eq!(ja3.hash, expected_ja3_hash);

        let ja4 = Ja4Fingerprint::from_client_hello(client_hello);
        assert_eq!(ja4.fingerprint, expected_ja4);
        assert_eq!(ja4.raw, expected_ja4_raw);
    }

    fn client_hello_for_ja4(
        ciphers: &[u16],
        extensions: &[u16],
        supported_versions: &[u16],
        signature_algorithms: &[u16],
    ) -> ClientHello {
        client_hello_for_fingerprints(
            ciphers,
            extensions,
            supported_versions,
            signature_algorithms,
            &[],
            &[],
        )
    }

    fn client_hello_for_fingerprints(
        ciphers: &[u16],
        extensions: &[u16],
        supported_versions: &[u16],
        signature_algorithms: &[u16],
        supported_groups: &[u16],
        point_formats: &[u8],
    ) -> ClientHello {
        ClientHello {
            tls_version: TlsVersion::TLSv1_2,
            tls_version_negotiated: None,
            cipher_values: ciphers.to_vec(),
            client_random: String::new(),
            session_id: None,
            compression_algorithms: Vec::new(),
            ciphers: Vec::new(),
            extensions: extensions
                .iter()
                .map(|value| match *value {
                    Ja4Fingerprint::TLS_EXT_SERVER_NAME => TlsExtension::ServerName {
                        value: *value,
                        data: Vec::new(),
                    },
                    Ja4Fingerprint::TLS_EXT_ALPN => {
                        TlsExtension::ApplicationLayerProtocolNegotiation {
                            value: *value,
                            data: vec!["h2".to_owned()],
                        }
                    }
                    0x002b => TlsExtension::SupportedVersions {
                        value: *value,
                        data: supported_versions
                            .iter()
                            .map(|version| TlsVersion::from(*version))
                            .collect(),
                    },
                    0x000d => TlsExtension::SignatureAlgorithms {
                        value: *value,
                        data: signature_algorithms
                            .iter()
                            .map(|algorithm| SignatureAlgorithm::from(*algorithm))
                            .collect(),
                    },
                    0x000a => TlsExtension::SupportedGroups {
                        value: *value,
                        data: supported_groups
                            .iter()
                            .map(|group| NamesGroup::from(*group))
                            .collect(),
                    },
                    0x000b => TlsExtension::EcPointFormats {
                        value: *value,
                        data: point_formats
                            .iter()
                            .map(|format| ECPointFormat::from(*format))
                            .collect(),
                    },
                    _ => TlsExtension::Opaque {
                        value: *value,
                        data: None,
                    },
                })
                .collect(),
        }
    }
}
