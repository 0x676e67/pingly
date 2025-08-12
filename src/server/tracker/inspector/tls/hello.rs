//! See: <https://www.rfc-editor.org/rfc/rfc8446#section-4.2>

use serde::Serialize;
use tls_parser::{TlsCipherSuite, TlsExtensionType, TlsMessage, TlsMessageHandshake};
use tokio_rustls::rustls::ProtocolVersion;

use super::{
    enums::{
        AuthenticatedEncryptionWithAssociatedData, CertificateCompressionAlgorithm,
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
    client_random: String,
    session_id: Option<String>,
    /// A list of compression methods supported by client
    compression_algorithms: Vec<CompressionAlgorithm>,
    /// A list of ciphers supported by client
    ciphers: Vec<&'static str>,
    /// A list of extensions supported by client
    extensions: Vec<TlsExtension>,
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
    /// - `version`: An `Option<ProtocolVersion>` representing the negotiated TLS version.
    ///   If `Some`, the version is set; if `None`, no version was negotiated.
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

        let mut client_hello = ClientHello {
            tls_version: TlsVersion::from(payload.version.0),
            tls_version_negotiated: None,
            client_random: hex::encode(payload.random),
            session_id: payload.session_id.map(hex::encode),
            compression_algorithms: payload
                .comp
                .iter()
                .map(|c| CompressionAlgorithm::from(c.0))
                .collect(),
            ciphers: payload
                .ciphers
                .iter()
                .flat_map(|v| TlsCipherSuite::from_id(v.0).map(|v| v.name))
                .collect(),
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
                                .map(|v| TlsVersion::from(v.0))
                                .collect(),
                        });
                }
                tls_parser::TlsExtension::SessionTicket(data) => {
                    tracing::debug!("ClientHello: SessionTicket extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::SessionTicket {
                        value: extension_id,
                        data: hex::encode(data),
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
                                .map(|p| String::from_utf8_lossy(p).to_string())
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
                            data: timestamps.map(hex::encode),
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
                        data: hex::encode(padding),
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
                                value: hex::encode(data.1),
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
                        data: hex::encode(data),
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
                        data: Some(hex::encode(data.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::KeyShareOld(items) => {
                    tracing::debug!("ClientHello: KeyShareOld extension: {items:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex::encode(items)),
                    });
                }
                tls_parser::TlsExtension::EarlyData(data) => {
                    tracing::debug!("ClientHello: EarlyData extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: data.map(|d| hex::encode(d.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::Cookie(items) => {
                    tracing::debug!("ClientHello: Cookie extension: {items:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex::encode(items)),
                    });
                }
                tls_parser::TlsExtension::Heartbeat(data) => {
                    tracing::debug!("ClientHello: Heartbeat extension: {data:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex::encode(data.to_be_bytes())),
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
                                cert_ext_oid: hex::encode(f.cert_ext_oid),
                                cert_ext_val: hex::encode(f.cert_ext_val),
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
                            key_share: hex::encode(key_share),
                            record_digest: hex::encode(record_digest),
                            encrypted_sni: hex::encode(encrypted_sni),
                        });
                }

                tls_parser::TlsExtension::Unknown(id, data) => {
                    tracing::debug!("ClientHello: Unknown extension: {id:?}, {data:?}");

                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(hex::encode(data)),
                    });
                }
            }
        }

        Some(client_hello)
    }
}
