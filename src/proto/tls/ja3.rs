use std::fmt::Write;

use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};

use super::hello::{ClientHello, TlsExtension};

/// JA3 TLS client fingerprint and its MD5 hash.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    /// The comma-delimited JA3 source string.
    pub raw: Box<str>,

    /// The lowercase MD5 digest of `raw`.
    pub hash: Box<str>,
}

impl Ja3Fingerprint {
    /// Builds a JA3 fingerprint from client-advertised ClientHello fields.
    pub fn from_client_hello(client_hello: &ClientHello) -> Self {
        let mut cipher_list = String::new();
        push_dec_list(
            &mut cipher_list,
            client_hello
                .cipher_suites
                .iter()
                .filter(|cipher| !cipher.is_grease())
                .map(|cipher| cipher.id),
        );

        let mut extension_list = String::new();
        let mut supported_group_list = String::new();
        let mut point_format_list = String::new();

        for extension in &client_hello.extensions {
            if extension.is_grease() {
                continue;
            }
            let value = extension.value();

            push_dec_list(&mut extension_list, [value]);

            match extension {
                TlsExtension::SupportedGroups { data, .. } => {
                    push_dec_list(
                        &mut supported_group_list,
                        data.iter()
                            .filter(|group| !group.is_grease())
                            .map(|group| group.id),
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

        Self {
            raw: raw.into_boxed_str(),
            hash,
        }
    }
}

impl From<&ClientHello> for Ja3Fingerprint {
    fn from(client_hello: &ClientHello) -> Self {
        Self::from_client_hello(client_hello)
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

fn md5_hex(input: &str) -> Box<str> {
    let hash = md5::compute(input);
    hex_encode(hash.as_slice()).into_boxed_str()
}

#[cfg(test)]
mod tests {
    use super::Ja3Fingerprint;
    use crate::proto::tls::{
        enums::{ECPointFormat, SignatureAlgorithm, TlsVersion},
        hello::{ClientHello, HexBytes, ProtocolName, TlsCipherSuite, TlsExtension},
        NamedGroup,
    };
    use tls_parser::TlsExtensionType;

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
        let client_hello = client_hello_for_ja3(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &[],
            &[0x001d, 0x0017, 0x0018],
            &[0],
        );
        let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.raw.as_ref(),
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-0-51-16-17513-23-45-13-5-35-18-43-65281-11-10-21,29-23-24,0"
        );
        assert_eq!(
            fingerprint.hash.as_ref(),
            "c000e2caf3a25423f9de6c8a4b12a975"
        );
    }

    #[test]
    fn chrome_browser_sample_matches_observed_ja3() {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x44cd, 0x002b, 0x002d, 0x000b, 0x000d, 0x0005, 0x0023, 0xff01, 0x0010, 0x0033, 0x0000,
            0x0012, 0x001b, 0xfe0d, 0x000a, 0x0017,
        ];
        let client_hello = client_hello_for_ja3(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &[],
            &[0x11ec, 0x001d, 0x0017, 0x0018],
            &[0],
        );
        let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.raw.as_ref(),
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17613-43-45-11-13-5-35-65281-16-51-0-18-27-65037-10-23,4588-29-23-24,0"
        );
        assert_eq!(
            fingerprint.hash.as_ref(),
            "d58a2a07a227719c6c34bd6f2dbd44de"
        );
    }

    #[test]
    fn firefox_browser_sample_matches_observed_ja3() {
        let ciphers = [
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b,
            0x000d, 0x002d, 0x001c, 0x001b, 0xfe0d, 0x0029,
        ];
        let client_hello = client_hello_for_ja3(
            &ciphers,
            &extensions,
            &[0x0304, 0x0303],
            &[],
            &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
            &[0],
        );
        let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello);

        assert_eq!(
            fingerprint.raw.as_ref(),
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0"
        );
        assert_eq!(
            fingerprint.hash.as_ref(),
            "f19d54c853fffdd9eeab77ae607448e9"
        );
    }

    #[test]
    fn ja3_filters_grease_values() {
        let client_hello = client_hello_for_ja3(
            &[0x0a0a, 0x1301],
            &[0x0a0a, 0x0000, 0x0010, 0x000a, 0x000b, 0x000d],
            &[],
            &[],
            &[0x0a0a, 0x001d],
            &[0],
        );
        let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello);

        assert_eq!(fingerprint.raw.as_ref(), "771,4865,0-16-10-11-13,29,0");
        assert_eq!(
            fingerprint.hash.as_ref(),
            "8b24de13bfb91159e7fc8865273b000d"
        );
    }

    fn client_hello_for_ja3(
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
                        data: supported_versions
                            .iter()
                            .map(|version| TlsVersion::from(*version))
                            .collect(),
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
                        data: supported_groups
                            .iter()
                            .map(|group| NamedGroup::from(*group))
                            .collect(),
                    },
                    TlsExtensionType::EcPointFormats => TlsExtension::EcPointFormats {
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
