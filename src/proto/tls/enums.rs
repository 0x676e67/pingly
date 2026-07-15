#![allow(non_camel_case_types)]

enum_builder! {
    /// A TLS or DTLS protocol version identifier.
    ///
    /// Unrecognized wire values are retained in `Unknown`.
    ///
    /// See [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html) and
    /// [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.html).
    @U16
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
    @U16
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
    #[allow(dead_code)]
    pub fn is_grease(self) -> bool {
        is_grease_value(self.value())
    }
}

enum_builder! {
    /// A legacy ClientHello compression-method identifier.
    ///
    /// TLS 1.3 clients must offer only `Null`.
    /// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
    @U8
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
    @U8
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
    @U16
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
    @U16
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
    @U16
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
    @U8
    pub enum CertificateStatusType {
        OCSP => 0x01,
    }
}

enum_builder! {
    /// A pre-shared-key key exchange mode advertised by the client.
    ///
    /// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
    @U8
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
    #[allow(dead_code)]
    pub fn is_grease(self) -> bool {
        matches!(
            self.value(),
            0x0b | 0x2a | 0x49 | 0x68 | 0x87 | 0xa6 | 0xc5 | 0xe4
        )
    }
}

enum_builder2! {
    /// A named group identifier used for TLS key establishment.
    ///
    /// Unrecognized wire values are retained in `Unknown`.
    /// See [RFC 9846, Section 4.3.7](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.7).
    @U16
    pub enum NamesGroup {
        sect163k1 => 1,
        sect163k1_2 => 2,
        sect163r2 => 3,
        sect193r1 => 4,
        sect193r2 => 5,
        sect233k1 => 6,
        sect233r1 => 7,
        sect239k1 => 8,
        sect283k1 => 9,
        sect283r1 => 10,
        sect409k1 => 11,
        sect409r1 => 12,
        sect571k1 => 13,
        sect571r1 => 14,
        secp160k1 => 15,
        secp160r1 => 16,
        secp160r2 => 17,
        secp192k1 => 18,
        secp192r1 => 19,
        secp224k1 => 20,
        P_224 => 21,
        P_256 => 23,
        P_384 => 24,
        P_521 => 25,
        X25519 => 29,
        X448 => 30,
        P256r1tls13 => 31,
        P384r1tls13 => 32,
        P521r1tls13 => 33,
        GC256A => 34,
        GC256B => 35,
        GC256C => 36,
        GC256D => 37,
        GC512A => 38,
        GC512B => 39,
        GC512C => 40,
        SM2 => 41,
        ffdhe2048 => 256,
        ffdhe3072 => 257,
        ffdhe4096 => 258,
        ffdhe6144 => 259,
        ffdhe8192 => 260,
        MLKEM1024 => 514,
        X25519MLKEM768 => 4588,
        CECPQ2 => 16696,
        X25519Kyber768Draft00 => 25497,
        X25519Kyber512Draft00 => 65072,
        X25519Kyber768Draft00Old => 65073,
        P256Kyber768Draft00 => 65074,
    }
}

impl NamesGroup {
    /// Returns whether this named group is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(self) -> bool {
        is_grease_value(self.value())
    }
}

impl ::std::fmt::Display for NamesGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            NamesGroup::P_224 => f.write_str("P-224"),
            NamesGroup::P_256 => f.write_str("P-256"),
            NamesGroup::P_384 => f.write_str("P-384"),
            NamesGroup::P_521 => f.write_str("P-521"),
            NamesGroup::Unknown(x) => {
                if self.is_grease() {
                    write!(f, "GREASE ({x:#06x})")
                } else {
                    write!(f, "Unknown ({x:#06x})")
                }
            }
            other => write!(f, "{other:?}"),
        }
    }
}

/// RFC 8701 reserves these patterned values so clients can keep TLS extension points flexible.
///
/// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
pub(super) const fn is_grease_value(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

#[cfg(test)]
mod tests {
    use super::{NamesGroup, PskKeyExchangeMode, SignatureAlgorithm, TlsVersion};

    #[test]
    fn grease_detection_is_available_on_tls_identifier_types() {
        assert!(TlsVersion::from(0x0a0a).is_grease());
        assert!(SignatureAlgorithm::from(0xfafa).is_grease());
        assert!(NamesGroup::from(0x2a2a).is_grease());
        assert!(PskKeyExchangeMode::from(0x0b).is_grease());
        assert!(PskKeyExchangeMode::from(0xe4).is_grease());
        assert!(!TlsVersion::from(0x0a0b).is_grease());
        assert!(!SignatureAlgorithm::from(0x0a1a).is_grease());
        assert!(!NamesGroup::X25519.is_grease());
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
