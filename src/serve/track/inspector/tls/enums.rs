#![allow(non_camel_case_types)]

enum_builder! {
    /// The `TlsVersion` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
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

enum_builder! {
    /// The `SignatureAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
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
    }
}

enum_builder! {
    /// The `CompressionAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum CompressionAlgorithm {
        Null => 0x00,
        Deflate => 0x01,
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

enum_builder! {
    /// Key derivation function used in hybrid public key encryption
    @U16
    pub enum KeyDerivationFunction {
        HKDF_SHA256 => 0x0001,
        HKDF_SHA384 => 0x0002,
        HKDF_SHA512 => 0x0003,
    }
}

enum_builder! {
    /// Authenticated encryption with associated data (AEAD) used in hybrid public key encryption
    @U16
    pub enum AuthenticatedEncryptionWithAssociatedData {
        AES_128_GCM => 0x0001,
        AES_256_GCM => 0x0002,
        ChaCha20Poly1305 => 0x0003,
        ExportOnly => 0xffff,
    }
}

enum_builder! {
    /// The `CertificateCompressionAlgorithm` TLS protocol enum, the algorithm used to compress the certificate.
    /// The algorithm MUST be one of the algorithms listed in the peer's compress_certificate extension.
    @U16
    pub enum CertificateCompressionAlgorithm {
        Zlib => 0x0001,
        Brotli => 0x0002,
        Zstd => 0x0003,
    }
}

enum_builder! {
    ///  The `CertificateStatusType` TLS protocol enum, used in the status_request extension.
    /// Values in this enum are taken from the various RFCs covering TLS, and are listed
    /// by IANA. The `Unknown` item is used when processing unrecognised ordinals.
    /// The `OCSP` value is used to indicate that the certificate status is provided
    /// using the Online Certificate Status Protocol (OCSP).
    @U8
    pub enum CertificateStatusType {
        OCSP => 0x01,
    }
}

enum_builder! {
    @U8
    pub enum PskKeyExchangeMode {
        /// See https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
        psk_ke => 0,
        psk_dhe_ke => 1
    }
}

enum_builder2! {
    /// The `NamesGroup` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
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
        X25519MLKEM768 => 4588,
        CECPQ2 => 16696,
        X25519Kyber768Draft00 => 25497,
        X25519Kyber512Draft00 => 65072,
        X25519Kyber768Draft00Old => 65073,
        P256Kyber768Draft00 => 65074,
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
                if x & 0x0f0f == 0x0a0a {
                    write!(f, "GREASE ({:#06x})", x)
                } else {
                    write!(f, "Unknown ({:#06x})", x)
                }
            }
            other => write!(f, "{:?}", other),
        }
    }
}
