#![allow(non_camel_case_types)]

enum_builder! {
    /// A TLS or DTLS protocol version identifier.
    ///
    /// Unrecognized wire values are retained in `Unknown`.
    ///
    /// See [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html) and
    /// [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.html).
    @U16 STANDARD_GREASE
    pub enum TlsVersion {
        SSLv2 => 0x0200,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

impl TlsVersion {
    /// Returns whether this version is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(self) -> bool {
        is_grease_value(self.value())
    }

    /// Returns the two-character TLS version code used by JA4.
    pub(crate) fn ja4_code(self) -> &'static str {
        match self {
            TlsVersion::TLSv1_3 => "13",
            TlsVersion::TLSv1_2 => "12",
            TlsVersion::TLSv1_1 => "11",
            TlsVersion::TLSv1_0 => "10",
            TlsVersion::SSLv3 => "s3",
            TlsVersion::SSLv2 => "s2",
            _ => "00",
        }
    }

    /// Selects the highest non-GREASE advertised version and returns its JA4 code.
    pub(crate) fn ja4_code_from_client_hello(
        legacy_version: Self,
        supported_versions: impl IntoIterator<Item = Self>,
    ) -> &'static str {
        supported_versions
            .into_iter()
            .filter(|version| !version.is_grease())
            .max_by_key(|version| version.value())
            .unwrap_or(legacy_version)
            .ja4_code()
    }
}

enum_builder! {
    /// A TLS signature scheme identifier advertised by the client.
    ///
    /// Unrecognized wire values are retained in `Unknown`.
    /// See [RFC 9846, Section 4.3.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.3).
    @U16 STANDARD_GREASE
    pub enum SignatureAlgorithm {
        rsa_pkcs1_sha1 => 513,
        ecdsa_sha1 => 515,
        rsa_pkcs1_sha256 => 1025,
        ecdsa_secp256r1_sha256 => 1027,
        rsa_pkcs1_sha256_legacy => 1056,
        rsa_pkcs1_sha384 => 1281,
        ecdsa_secp384r1_sha384 => 1283,
        rsa_pkcs1_sha384_legacy => 1312,
        rsa_pkcs1_sha512 => 1537,
        ecdsa_secp521r1_sha512 => 1539,
        rsa_pkcs1_sha512_legacy => 1568,
        eccsi_sha256 => 1796,
        iso_ibs1 => 1797,
        iso_ibs2 => 1798,
        iso_chinese_ibs => 1799,
        sm2sig_sm3 => 1800,
        gostr34102012_256a => 1801,
        gostr34102012_256b => 1802,
        gostr34102012_256c => 1803,
        gostr34102012_256d => 1804,
        gostr34102012_512a => 1805,
        gostr34102012_512b => 1806,
        gostr34102012_512c => 1807,
        rsa_pss_rsae_sha256 => 2052,
        rsa_pss_rsae_sha384 => 2053,
        rsa_pss_rsae_sha512 => 2054,
        ed25519 => 2055,
        ed448 => 2056,
        rsa_pss_pss_sha256 => 2057,
        rsa_pss_pss_sha384 => 2058,
        rsa_pss_pss_sha512 => 2059,
        ecdsa_brainpoolp256r1tls13_sha256 => 2074,
        ecdsa_brainpoolp384r1tls13_sha384 => 2075,
        ecdsa_brainpoolp512r1tls13_sha512 => 2076,
        mldsa44 =>2308,
        mldsa65 => 2309,
        mldsa87 => 2310,
    }
}

impl SignatureAlgorithm {
    /// Returns whether this signature algorithm is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(self) -> bool {
        is_grease_value(self.value())
    }
}

enum_builder! {
    /// A legacy ClientHello compression-method identifier.
    ///
    /// TLS 1.3 clients must offer only `Null`.
    /// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
    @U8 NO_GREASE
    pub enum CompressionAlgorithm {
        Null => 0x00,
        Deflate => 0x01,
    }
}

enum_builder! {
    /// An elliptic-curve point format advertised by a pre-TLS 1.3 client.
    ///
    /// Unrecognized wire values are retained in `Unknown`.
    /// See [RFC 8422, Section 5.1.2](https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2).
    @U8 NO_GREASE
    pub enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

enum_builder! {
    /// An HPKE key derivation function identifier.
    ///
    /// See [RFC 9180, Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.2).
    @U16 NO_GREASE
    pub enum KeyDerivationFunction {
        HKDF_SHA256 => 0x0001,
        HKDF_SHA384 => 0x0002,
        HKDF_SHA512 => 0x0003,
    }
}

enum_builder! {
    /// An HPKE authenticated-encryption algorithm identifier.
    ///
    /// See [RFC 9180, Section 7.2.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.3).
    @U16 NO_GREASE
    pub enum AuthenticatedEncryptionWithAssociatedData {
        AES_128_GCM => 0x0001,
        AES_256_GCM => 0x0002,
        ChaCha20Poly1305 => 0x0003,
        ExportOnly => 0xffff,
    }
}

enum_builder! {
    /// A certificate compression algorithm advertised by the client.
    ///
    /// See [RFC 8879, Section 3](https://www.rfc-editor.org/rfc/rfc8879.html#section-3).
    @U16 NO_GREASE
    pub enum CertificateCompressionAlgorithm {
        Zlib => 0x0001,
        Brotli => 0x0002,
        Zstd => 0x0003,
    }
}

enum_builder! {
    /// A certificate status protocol requested through `status_request`.
    ///
    /// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
    #[allow(clippy::upper_case_acronyms)]
    @U8 NO_GREASE
    pub enum CertificateStatusType {
        OCSP => 0x01,
    }
}

enum_builder! {
    /// A pre-shared-key key exchange mode advertised by the client.
    ///
    /// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
    @U8 PSK_GREASE
    pub enum PskKeyExchangeMode {
        /// Authentication based only on the pre-shared key.
        psk_ke => 0,
        /// Authentication based on the pre-shared key with ephemeral Diffie-Hellman.
        psk_dhe_ke => 1
    }
}

impl PskKeyExchangeMode {
    /// Returns whether this PSK key exchange mode is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(self) -> bool {
        is_psk_key_exchange_mode_grease(u16::from(self.value()))
    }
}

const fn is_psk_key_exchange_mode_grease(value: u16) -> bool {
    matches!(value, 0x0b | 0x2a | 0x49 | 0x68 | 0x87 | 0xa6 | 0xc5 | 0xe4)
}

fn parse_serialized_identifier(value: &str) -> Option<(u16, bool)> {
    let (hex, requires_grease) = if let Some(hex) = value
        .strip_prefix("GREASE (0x")
        .and_then(|value| value.strip_suffix(')'))
    {
        (hex, true)
    } else {
        (
            value
                .strip_prefix("Unknown (0x")
                .and_then(|value| value.strip_suffix(')'))?,
            false,
        )
    };

    if hex.len() != 4
        || hex
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }

    let value = u16::from_str_radix(hex, 16).ok()?;
    Some((value, requires_grease))
}

/// RFC 8701 reserves these patterned values so clients can keep TLS extension points flexible.
///
/// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
pub(super) const fn is_grease_value(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticatedEncryptionWithAssociatedData, CertificateCompressionAlgorithm,
        CompressionAlgorithm, KeyDerivationFunction, PskKeyExchangeMode, SignatureAlgorithm,
        TlsVersion,
    };

    #[test]
    fn tls_identifiers_roundtrip_through_their_json_names() {
        let version = TlsVersion::from(0x0a0a);
        let version_json = serde_json::to_string(&version).unwrap();
        assert_eq!(version_json, r#""GREASE (0x0a0a)""#);
        assert_eq!(
            serde_json::from_str::<TlsVersion>(&version_json).unwrap(),
            version
        );

        let mode = PskKeyExchangeMode::from(0x0b);
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, r#""GREASE (0x000b)""#);
        assert_eq!(
            serde_json::from_str::<PskKeyExchangeMode>(&json).unwrap(),
            mode
        );
        assert!(serde_json::from_str::<PskKeyExchangeMode>(r#""Unknown (0x000b)""#).is_err());
        assert!(serde_json::from_str::<TlsVersion>(r#""Unknown (0x0a0a)""#).is_err());
    }

    #[test]
    fn known_identifiers_cannot_use_unknown_labels() {
        assert!(serde_json::from_str::<TlsVersion>(r#""Unknown (0x0304)""#).is_err());
        assert!(serde_json::from_str::<CompressionAlgorithm>(r#""Unknown (0x0000)""#).is_err());
    }

    #[test]
    fn dynamic_identifier_labels_require_canonical_hexadecimal() {
        let version = TlsVersion::from(0x0305);

        assert_eq!(
            serde_json::from_str::<TlsVersion>(r#""Unknown (0x0305)""#).unwrap(),
            version
        );
        assert!(serde_json::from_str::<TlsVersion>(r#""Unknown (0x305)""#).is_err());
        assert!(serde_json::from_str::<TlsVersion>(r#""Unknown (0xABCD)""#).is_err());
    }

    #[test]
    fn grease_labels_are_scoped_to_their_registered_code_points() {
        macro_rules! assert_plain_unknown {
            ($type:ty) => {{
                let value = <$type>::from(0x0a0a);
                let json = serde_json::to_string(&value).unwrap();

                assert_eq!(json, r#""Unknown (0x0a0a)""#);
                assert_eq!(serde_json::from_str::<$type>(&json).unwrap(), value);
                assert!(serde_json::from_str::<$type>(r#""GREASE (0x0a0a)""#).is_err());
            }};
        }

        assert_plain_unknown!(KeyDerivationFunction);
        assert_plain_unknown!(AuthenticatedEncryptionWithAssociatedData);
        assert_plain_unknown!(CertificateCompressionAlgorithm);
        assert!(serde_json::from_str::<TlsVersion>(r#""GREASE (0x0a0b)""#).is_err());
    }

    #[test]
    fn grease_detection_is_available_on_tls_identifier_types() {
        assert!(TlsVersion::from(0x0a0a).is_grease());
        assert!(SignatureAlgorithm::from(0xfafa).is_grease());
        assert!(PskKeyExchangeMode::from(0x0b).is_grease());
        assert!(PskKeyExchangeMode::from(0xe4).is_grease());
        assert!(!TlsVersion::from(0x0a0b).is_grease());
        assert!(!SignatureAlgorithm::from(0x0a1a).is_grease());
        assert!(!PskKeyExchangeMode::psk_dhe_ke.is_grease());
    }

    #[test]
    fn tls_version_has_ja4_code() {
        assert_eq!(TlsVersion::TLSv1_3.ja4_code(), "13");
        assert_eq!(TlsVersion::TLSv1_2.ja4_code(), "12");
        assert_eq!(TlsVersion::SSLv3.ja4_code(), "s3");
        assert_eq!(TlsVersion::Unknown(0xffff).ja4_code(), "00");
    }

    #[test]
    fn ja4_client_hello_version_prefers_supported_versions() {
        assert_eq!(
            TlsVersion::ja4_code_from_client_hello(
                TlsVersion::TLSv1_2,
                [TlsVersion::from(0x0a0a), TlsVersion::TLSv1_3]
            ),
            "13"
        );
        assert_eq!(
            TlsVersion::ja4_code_from_client_hello(TlsVersion::TLSv1_2, []),
            "12"
        );
        assert_eq!(
            TlsVersion::ja4_code_from_client_hello(
                TlsVersion::TLSv1_2,
                [TlsVersion::TLSv1_3, TlsVersion::from(0x0001)]
            ),
            "13"
        );
    }
}
