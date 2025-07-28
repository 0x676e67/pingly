use serde::{Deserialize, Serialize};
use tls_parser::{TlsMessage, TlsMessageHandshake};

use super::enums::{
    ApplicationProtocol, AuthenticatedEncryptionWithAssociatedData,
    CertificateCompressionAlgorithm, Cipher, CompressionAlgorithm, ECPointFormat, ExtensionId,
    KeyDerivationFunction, SignatureAlgorithm, SupportedGroup, TlsVersion,
};

/// When a client first connects to a server, it is required to send
/// the ClientHello as its first message.
///
/// The ClientHello contains random data, cipher suites,
/// legacy content from <= TLS.12 and extensions.
///
/// For Rama however we only focus on the parts which
/// a user might want to inspect and/or set.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct ClientHello {
    pub(super) tls_version: TlsVersion,
    pub(super) ciphers: Vec<Cipher>,
    pub(super) compression_algorithms: Vec<CompressionAlgorithm>,
    pub(super) extensions: Vec<ClientHelloExtension>,
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
            ciphers: payload.ciphers.iter().map(|c| Cipher::from(c.0)).collect(),
            compression_algorithms: payload
                .comp
                .iter()
                .map(|c| CompressionAlgorithm::from(c.0))
                .collect(),
            extensions: Vec::with_capacity(5),
        };

        let mut ext = payload.ext?;

        while !ext.is_empty() {
            match super::parser::parse_tls_client_hello_extension(ext) {
                Ok((new_ext, ch_ext)) => {
                    client_hello.extensions.push(ch_ext);
                    ext = new_ext;
                }
                Err(err) => {
                    tracing::info!("Failed to parse TLS client hello extension: {err}");
                    break;
                }
            }
        }

        Some(client_hello)
    }
}

/// Extensions that can be set in a [`ClientHello`] message by a TLS client.
///
/// While its name may infer that an extension is by definition optional,
/// you would be wrong to think so. These extensions are also used
/// to fill historical gaps in the TLS specifications and as a consequence
/// there are a couple of extensions that are pretty much in any [`ClientHello`] message.
///
/// Most of the defined variants of this _enum_ are examples of such "required" extensions.
/// Extensions like [`ClientHelloExtension::ApplicationLayerProtocolNegotiation`]
/// are not required but due to benefits it offers it also is pretty much always present,
/// as it helps save application negotiation roundtrips;
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum ClientHelloExtension {
    /// name of the server the client intends to connect to
    ///
    /// TLS does not provide a mechanism for a client to tell a server the
    /// name of the server it is contacting. It may be desirable for clients
    /// to provide this information to facilitate secure connections to
    /// servers that host multiple 'virtual' servers at a single underlying
    /// network address.
    ///
    /// In order to provide any of the server names, clients MAY include an
    /// extension of type "server_name" in the (extended) client hello.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc6066>
    /// - <https://www.iana.org/go/rfc9261>
    ServerName(Option<String>),
    /// indicates which elliptic curves the client supports
    ///
    /// This extension is required... despite being an extension.
    ///
    /// Renamed from EllipticCurves, which some material might still reference it as.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8422>
    /// - <https://www.iana.org/go/rfc7919>
    SupportedGroups(Vec<SupportedGroup>),
    /// indicates the set of point formats that the client can parse
    ///
    /// For this extension, the opaque extension_data field contains ECPointFormatList.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8422>
    ECPointFormats(Vec<ECPointFormat>),
    /// Algorithms supported by the client for signing certificates.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    /// Application Layer Protocol Negotiation, often referred to as ALPN.
    ///
    /// Used to indicate the application layer protocols the client supports,
    /// e.g. h2 or h3. Allowing the server to immediately serve content
    /// using one of the supported protocols avoiding otherwise
    /// wasteful upgrade roundtrips.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc7301>
    ApplicationLayerProtocolNegotiation(Vec<ApplicationProtocol>),
    /// Used by the client for negotiating application-layer protocol settings (ALPS)
    /// within the TLS handshake.
    /// Through doing that, the settings can be made available to the application
    /// as soon as the handshake completes, and can be associated with TLS session
    /// tickets automatically at the TLS layer.
    ///
    /// # Reference
    ///
    /// - <https://www.ietf.org/archive/id/draft-vvv-tls-alps-01.html>
    ApplicationSettings(Vec<ApplicationProtocol>),
    /// used by the client to indicate which versions of TLS it supports
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SupportedVersions(Vec<TlsVersion>),
    /// The algorithm used to compress the certificate.
    ///
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/rfc8879>
    CertificateCompression(Vec<CertificateCompressionAlgorithm>),
    /// The maximum size of a record.
    ///
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/rfc8449>
    RecordSizeLimit(u16),
    /// Delegated credentials
    ///
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/rfc9345>
    DelegatedCredentials(Vec<SignatureAlgorithm>),
    /// Encrypted hello send by the client
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/>
    EncryptedClientHello(ECHClientHello),
    /// Any extension not supported by Rama,
    /// as it is still to be done or considered out of scope.
    Opaque {
        /// extension id
        id: ExtensionId,
        /// extension data
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// Client Hello contents send by ech
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

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// Data send by ech hello message when it is in the outer part
pub struct ECHClientHelloOuter {
    pub cipher_suite: HpkeSymmetricCipherSuite,
    pub config_id: u8,
    pub enc: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// HPKE KDF and AEAD pair used to encrypt ClientHello
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: KeyDerivationFunction,
    pub aead_id: AuthenticatedEncryptionWithAssociatedData,
}

impl std::fmt::Display for HpkeSymmetricCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.kdf_id, self.aead_id)
    }
}
