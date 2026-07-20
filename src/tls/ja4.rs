use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_parser::TlsExtensionType;

use super::{
    enums::TlsVersion,
    hello::{ClientHello, ProtocolName, TlsExtension},
};

/// JA4 TLS client fingerprint, plus the raw material used to produce the hash chunks.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    /// The final three-chunk JA4 fingerprint.
    pub fingerprint: Box<str>,

    /// The unhashed JA4 form used to inspect each chunk's source material.
    pub raw: Box<str>,
}

impl Ja4Fingerprint {
    /// Builds a JA4 fingerprint from client-advertised ClientHello fields.
    pub fn from_client_hello(client_hello: &ClientHello) -> Self {
        let mut ciphers = client_hello
            .cipher_suites
            .iter()
            .filter(|cipher| !cipher.is_grease())
            .map(|cipher| cipher.id)
            .collect::<Vec<_>>();

        let mut extensions = Vec::with_capacity(client_hello.extensions.len());
        let mut supported_versions = Vec::new();
        let mut signature_algorithms = Vec::new();
        let mut alpn = (None, None);
        let mut extension_count = 0usize;
        let mut has_server_name = false;
        let mut has_quic_transport_parameters = false;

        for extension in &client_hello.extensions {
            if extension.is_grease() {
                continue;
            }
            let value = extension.value();

            let extension_type = TlsExtensionType::from_u16(value);
            extension_count += 1;
            has_server_name |= matches!(extension_type, TlsExtensionType::ServerName);

            match extension {
                TlsExtension::SupportedVersions { data, .. } => {
                    supported_versions
                        .extend(data.versions.iter().map(|version| version.tls_version()));
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
                TlsExtension::QuicTransportParameters { .. } => {
                    has_quic_transport_parameters = true;
                }
                _ => {}
            }

            if !matches!(
                extension_type,
                TlsExtensionType::ServerName
                    | TlsExtensionType::ApplicationLayerProtocolNegotiation
            ) {
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
                client_hello.tls_version,
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

        Self {
            fingerprint: fingerprint.into_boxed_str(),
            raw: raw.into_boxed_str(),
        }
    }
}

impl From<&ClientHello> for Ja4Fingerprint {
    fn from(client_hello: &ClientHello) -> Self {
        Self::from_client_hello(client_hello)
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

fn first_last(value: &ProtocolName) -> (Option<char>, Option<char>) {
    fn ja4_character(byte: u8) -> char {
        if byte.is_ascii() {
            char::from(byte)
        } else {
            '9'
        }
    }

    let mut bytes = value.as_bytes().iter().copied();
    (
        bytes.next().map(ja4_character),
        bytes.next_back().map(ja4_character),
    )
}

#[cfg(test)]
mod tests {
    use tls_parser::TlsExtensionType;

    use super::{first_last, hash12, Ja4Fingerprint};
    use crate::tls::{
        enums::{ECPointFormat, SignatureAlgorithm, TlsVersion},
        hello::{ClientHello, HexBytes, ProtocolName, TlsCipherSuite, TlsExtension},
        SupportedVersions,
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
            fingerprint.fingerprint.as_ref(),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
        assert_eq!(
            fingerprint.raw.as_ref(),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn chrome_browser_sample_matches_observed_ja4() {
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
        let client_hello = client_hello_for_ja4(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &signature_algorithms,
        );
        let fingerprint = Ja4Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.fingerprint.as_ref(),
            "t13d1516h2_8daaf6152771_806a8c22fdea"
        );
        assert_eq!(
            fingerprint.raw.as_ref(),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn firefox_browser_sample_matches_observed_ja4() {
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
        let client_hello = client_hello_for_ja4(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &signature_algorithms,
        );
        let fingerprint = Ja4Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.fingerprint.as_ref(),
            "t13d1617h2_86a278354501_e6dcd7ae0a9e"
        );
        assert_eq!(
            fingerprint.raw.as_ref(),
            "t13d1617h2_002f,0035,009c,009d,1301,1302,1303,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201"
        );
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

        assert!(client_hello
            .extensions
            .first()
            .is_some_and(TlsExtension::is_grease));
        assert_eq!(fingerprint.raw.as_ref(), "t12d0103h2_1301_000d");
    }

    #[test]
    fn quic_ja4_uses_the_transport_marker_and_extension_id() {
        let mut client_hello = client_hello_for_ja4(&[0x1301], &[0x0010], &[], &[]);
        client_hello
            .extensions
            .push(TlsExtension::QuicTransportParameters {
                value: crate::quic::TRANSPORT_PARAMETERS_EXTENSION_ID,
                data: Vec::new(),
            });

        let fingerprint = Ja4Fingerprint::from_client_hello(&client_hello);

        assert!(fingerprint.fingerprint.starts_with('q'));
        assert_eq!(fingerprint.raw.as_ref(), "q12i0102h2_1301_0039");
    }

    #[test]
    fn hash12_uses_zeros_for_empty_input() {
        assert_eq!(hash12("551d0f,551d25,551d11"), "aae71e8db6d7");
        assert_eq!(hash12(""), "000000000000");
    }

    #[test]
    fn ja4_alpn_characters_match_the_reference_behavior() {
        let one_byte = ProtocolName::try_from("h").unwrap();
        assert_eq!(first_last(&one_byte), (Some('h'), None));

        let opaque = ProtocolName::try_from(&[0xff, b'2'][..]).unwrap();
        assert_eq!(first_last(&opaque), (Some('9'), Some('2')));
    }

    fn client_hello_for_ja4(
        ciphers: &[u16],
        extensions: &[u16],
        supported_versions: &[u16],
        signature_algorithms: &[u16],
    ) -> ClientHello {
        ClientHello {
            tls_version: TlsVersion::TLSv1_2,
            tls_version_negotiated: None,
            cipher_suites: ciphers.iter().copied().map(TlsCipherSuite::from).collect(),
            client_random: HexBytes::from([0; 32]),
            session_id: None,
            compression_algorithms: Vec::new(),
            extensions: extensions
                .iter()
                .map(|value| match TlsExtensionType::from_u16(*value) {
                    TlsExtensionType::ServerName => TlsExtension::ServerName {
                        value: *value,
                        data: Vec::new(),
                    },
                    TlsExtensionType::ApplicationLayerProtocolNegotiation => {
                        TlsExtension::ApplicationLayerProtocolNegotiation {
                            value: *value,
                            data: vec![ProtocolName::try_from("h2").unwrap()],
                        }
                    }
                    TlsExtensionType::SupportedVersions => TlsExtension::SupportedVersions {
                        value: *value,
                        data: SupportedVersions::from_ids(supported_versions.iter().copied()),
                    },
                    TlsExtensionType::SignatureAlgorithms => TlsExtension::SignatureAlgorithms {
                        value: *value,
                        data: signature_algorithms
                            .iter()
                            .map(|algorithm| SignatureAlgorithm::from(*algorithm))
                            .collect(),
                    },
                    TlsExtensionType::SupportedGroups => TlsExtension::SupportedGroups {
                        value: *value,
                        data: Vec::new(),
                    },
                    TlsExtensionType::EcPointFormats => TlsExtension::EcPointFormats {
                        value: *value,
                        data: Vec::<ECPointFormat>::new(),
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
