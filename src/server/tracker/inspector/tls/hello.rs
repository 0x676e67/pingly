//! See: <https://www.rfc-editor.org/rfc/rfc8446#section-4.2>

use serde::Serialize;
use tls_parser::{TlsCipherSuite, TlsExtension, TlsExtensionType, TlsMessage, TlsMessageHandshake};

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
    client_random: String,
    session_id: Option<String>,
    /// A list of compression methods supported by client
    compression_algorithms: Vec<CompressionAlgorithm>,
    /// A list of ciphers supported by client
    ciphers: Vec<&'static str>,
    /// A list of extensions supported by client
    extensions: Vec<ClientHelloExtension>,
}

/// Extensions that can be set in a [`ClientHello`] message by a TLS client.
#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientHelloExtension {
    ServerName {
        value: u16,
        data: Vec<String>,
    },

    SupportedGroups {
        value: u16,
        data: Vec<NamesGroup>,
    },

    EcPointFormats {
        value: u16,
        data: Vec<ECPointFormat>,
    },

    SignatureAlgorithms {
        value: u16,
        data: Vec<SignatureAlgorithm>,
    },

    StatusRequest {
        value: u16,
        data: StatusRequest,
    },

    ApplicationLayerProtocolNegotiation {
        value: u16,
        data: Vec<String>,
    },

    ApplicationSettings {
        value: u16,
        data: Vec<String>,
    },

    SupportedVersions {
        value: u16,
        data: Vec<TlsVersion>,
    },

    SessionTicket {
        value: u16,
        data: String,
    },

    CertificateCompression {
        value: u16,
        data: Vec<CertificateCompressionAlgorithm>,
    },

    RecordSizeLimit {
        value: u16,
        data: u16,
    },

    DelegatedCredentials {
        value: u16,
        data: Vec<SignatureAlgorithm>,
    },

    EncryptedClientHello {
        value: u16,
        data: ECHClientHello,
    },

    SignedCertificateTimestamp {
        value: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
    },

    RenegotiationInfo {
        value: u16,
        data: String,
    },

    ExtendedMasterSecret {
        value: u16,
    },

    Padding {
        value: u16,
        data: String,
    },

    KeyShare {
        value: u16,
        data: Vec<KeyShare>,
    },

    PskKeyExchangeModes {
        value: u16,
        data: PskKeyExchangeModes,
    },

    PreSharedKey {
        value: u16,
        data: String,
    },

    Grease {
        value: u16,
    },

    /// Any extension not supported.
    /// as it is still to be done or considered out of scope.
    Opaque {
        value: u16,
        data: String,
    },
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

impl ClientHello {
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
        let mut grease_list = Vec::new();

        for ext in ext_list {
            let extension_id = TlsExtensionType::from(&ext).0;
            match ext {
                TlsExtension::SNI(name) => {
                    tracing::debug!("ClientHello: SNI extension: {name:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::ServerName {
                            value: extension_id,
                            data: name
                                .into_iter()
                                .map(|n| n.1)
                                .map(|n| String::from_utf8_lossy(n).to_string())
                                .collect(),
                        });
                }
                TlsExtension::EllipticCurves(groups) => {
                    tracing::debug!("ClientHello: EllipticCurves extension: {groups:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::SupportedGroups {
                            value: extension_id,
                            data: groups.into_iter().map(|g| NamesGroup::from(g.0)).collect(),
                        });
                }
                TlsExtension::SupportedVersions(versions) => {
                    tracing::debug!("ClientHello: SupportedVersions extension: {versions:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::SupportedVersions {
                            value: extension_id,
                            data: versions
                                .into_iter()
                                .map(|v| TlsVersion::from(v.0))
                                .collect(),
                        });
                }
                TlsExtension::SessionTicket(data) => {
                    tracing::debug!("ClientHello: SessionTicket extension: {data:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::SessionTicket {
                            value: extension_id,
                            data: hex::encode(data),
                        });
                }
                TlsExtension::SignatureAlgorithms(algorithms) => {
                    tracing::debug!("ClientHello: SignatureAlgorithms extension: {algorithms:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::SignatureAlgorithms {
                            value: extension_id,
                            data: algorithms
                                .into_iter()
                                .map(SignatureAlgorithm::from)
                                .collect(),
                        });
                }
                TlsExtension::StatusRequest(data) => {
                    tracing::debug!("ClientHello: StatusRequest extension: {data:?}");

                    if let Some((status, data)) = data {
                        let (_, (responder_id_list, request_extensions)) =
                            parser::parse_ocsp_status_request_lengths(data).ok()?;
                        client_hello
                            .extensions
                            .push(ClientHelloExtension::StatusRequest {
                                value: extension_id,
                                data: StatusRequest {
                                    certificate_status_type: CertificateStatusType::from(status.0),
                                    responder_id_list,
                                    request_extensions,
                                },
                            });
                    }
                }
                TlsExtension::EcPointFormats(formats) => {
                    tracing::debug!("ClientHello: ECPointFormats extension: {formats:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::EcPointFormats {
                            value: extension_id,
                            data: formats.iter().map(|f| ECPointFormat::from(*f)).collect(),
                        });
                }
                TlsExtension::ALPN(protocols) => {
                    tracing::debug!("ClientHello: ALPN extension: {protocols:?}");

                    client_hello.extensions.push(
                        ClientHelloExtension::ApplicationLayerProtocolNegotiation {
                            value: extension_id,
                            data: protocols
                                .into_iter()
                                .map(|p| String::from_utf8_lossy(p).to_string())
                                .collect(),
                        },
                    );
                }
                TlsExtension::SignedCertificateTimestamp(timestamps) => {
                    tracing::debug!("ClientHello: SCT extension: {timestamps:?}");

                    client_hello.extensions.push(
                        ClientHelloExtension::SignedCertificateTimestamp {
                            value: extension_id,
                            data: timestamps.map(hex::encode),
                        },
                    );
                }
                TlsExtension::RenegotiationInfo(data) => {
                    tracing::debug!("ClientHello: RenegotiationInfo extension: {data:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::RenegotiationInfo {
                            value: extension_id,
                            data: hex::encode(data),
                        });
                }
                TlsExtension::Unknown(TlsExtensionType(34), algorithms) => {
                    tracing::debug!("ClientHello: DelegatedCredentials extension: {algorithms:?}");

                    let extension =
                        parser::parse_tls_extension_delegated_credentials(extension_id, algorithms)
                            .ok()?
                            .1;
                    client_hello.extensions.push(extension);
                }
                TlsExtension::RecordSizeLimit(limit) => {
                    tracing::debug!("ClientHello: RecordSizeLimit extension: {limit:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::RecordSizeLimit {
                            value: extension_id,
                            data: limit,
                        });
                }
                TlsExtension::Unknown(TlsExtensionType(27), data) => {
                    tracing::debug!("ClientHello: CertificateCompression extension: {data:?}");

                    let extension =
                        parser::parse_tls_extension_certificate_compression(extension_id, data)
                            .ok()?
                            .1;
                    client_hello.extensions.push(extension);
                }
                TlsExtension::Unknown(TlsExtensionType(65037), data) => {
                    tracing::debug!("ClientHello: EncryptedClientHello extension: {data:?}");

                    let extension = parser::parse_tls_extension_ech(extension_id, data).ok()?.1;
                    client_hello.extensions.push(extension);
                }
                TlsExtension::Padding(padding) => {
                    tracing::debug!("ClientHello: Padding extension");

                    client_hello.extensions.push(ClientHelloExtension::Padding {
                        value: extension_id,
                        data: hex::encode(padding),
                    });
                }
                TlsExtension::KeyShare(data) => {
                    tracing::debug!("ClientHello: KeyShare extension: {data:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::KeyShare {
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
                TlsExtension::PskExchangeModes(data) => {
                    tracing::debug!("ClientHello: PskExchangeModes extension: {data:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::PskKeyExchangeModes {
                            value: extension_id,
                            data: PskKeyExchangeModes {
                                ke_modes: data.into_iter().map(PskKeyExchangeMode::from).collect(),
                            },
                        });
                }
                TlsExtension::PreSharedKey(data) => {
                    tracing::debug!("ClientHello: PreSharedKey extension: {data:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::PreSharedKey {
                            value: extension_id,
                            data: hex::encode(data),
                        });
                }
                TlsExtension::Unknown(TlsExtensionType(17513), protocols) => {
                    tracing::debug!(
                        "ClientHello: Old Application Settings extension: {protocols:?}"
                    );

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::ApplicationSettings {
                            value: extension_id,
                            data: parser::parse_alps_packet(protocols),
                        });
                }
                TlsExtension::Unknown(TlsExtensionType(17613), protocols) => {
                    tracing::debug!("ClientHello: Application Settings extension: {protocols:?}");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::ApplicationSettings {
                            value: extension_id,
                            data: parser::parse_alps_packet(protocols),
                        });
                }
                TlsExtension::ExtendedMasterSecret => {
                    tracing::debug!("ClientHello: ExtendedMasterSecret extension");

                    client_hello
                        .extensions
                        .push(ClientHelloExtension::ExtendedMasterSecret {
                            value: extension_id,
                        });
                }
                TlsExtension::Grease(id, _) => {
                    tracing::debug!("ClientHello: Grease extension: {id:?}");

                    grease_list.push(ClientHelloExtension::Grease {
                        value: extension_id,
                    });
                }
                TlsExtension::Unknown(_, data) => {
                    tracing::debug!("ClientHello: Unknown extension: {extension_id:?}");

                    client_hello.extensions.push(ClientHelloExtension::Opaque {
                        value: extension_id,
                        data: hex::encode(data),
                    });
                }
                _ => {
                    tracing::debug!("ClientHello: Unhandled extension: {extension_id:?}");
                }
            }
        }

        Some(client_hello)
    }
}
