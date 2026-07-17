use nom::{
    bytes::streaming::take,
    combinator::{eof, map_opt, verify},
    error::{make_error, ErrorKind},
    multi::length_data,
    number::streaming::{be_u16, be_u8},
    IResult, Parser,
};

use super::hello::{
    ECHClientHello, ECHClientHelloOuter, HexBytes, HpkeSymmetricCipherSuite, ProtocolName,
    TlsExtension,
};

/// Splits one framed ClientHello extension into its type and exact payload.
///
/// Each extension uses a two-byte type followed by a two-byte payload length.
/// See [RFC 9846, Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3).
pub fn parse_tls_extension_frame(data: &[u8]) -> IResult<&[u8], (u16, &[u8])> {
    let (input, extension_id) = be_u16(data)?;
    let (input, payload) = length_data(be_u16).parse(input)?;

    Ok((input, (extension_id, payload)))
}

/// Parses the client form of the TLS 1.3 `key_share` extension.
///
/// Each entry starts with a two-byte named-group ID and a two-byte key length.
/// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
pub fn parse_key_share(data: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    let length = data.get(..2)?;
    let total_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let payload_end = 2usize.checked_add(total_len)?;
    if data.len() != payload_end {
        return None;
    }

    let payload = data.get(2..payload_end)?;
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let header_end = cursor.checked_add(4)?;
        let header = payload.get(cursor..header_end)?;
        let group = u16::from_be_bytes([header[0], header[1]]);
        let key_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if key_len == 0 {
            return None;
        }

        let key_end = header_end.checked_add(key_len)?;
        let key = payload.get(header_end..key_end)?;
        entries.push((group, key.to_vec()));
        cursor = key_end;
    }

    Some(entries)
}

/// Parses the length fields from a ClientHello OCSP `status_request` payload.
///
/// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
pub fn parse_ocsp_status_request_lengths(data: &[u8]) -> IResult<&[u8], (u16, u16)> {
    let (input, responder_id_list_len) = be_u16(data)?;
    let (input, responder_ids) = take(responder_id_list_len).parse(input)?;

    let mut remaining = responder_ids;
    while !remaining.is_empty() {
        let (input, responder_id_len) = verify(be_u16, |length| *length > 0).parse(remaining)?;
        let (input, _) = take(responder_id_len).parse(input)?;
        remaining = input;
    }

    let (input, request_extensions_len) = be_u16(input)?;
    let (input, _) = take(request_extensions_len).parse(input)?;
    let (input, _) = eof(input)?;

    Ok((input, (responder_id_list_len, request_extensions_len)))
}

/// Parses the client form of the delegated-credentials extension.
///
/// See [RFC 9345, Section 4.1](https://www.rfc-editor.org/rfc/rfc9345.html#section-4.1).
pub fn parse_tls_extension_delegated_credentials(
    id: u16,
    data: &[u8],
) -> IResult<&[u8], TlsExtension> {
    let (input, length) = verify(be_u16, |length| *length >= 2 && *length % 2 == 0).parse(data)?;
    let (input, payload) = take(length).parse(input)?;
    let (input, _) = eof(input)?;
    let (_, algorithms) = parse_u16_type(payload)?;

    Ok((
        input,
        TlsExtension::DelegatedCredentials {
            value: id,
            data: algorithms,
        },
    ))
}

/// Parses the client form of the certificate-compression extension.
///
/// See [RFC 8879, Section 3](https://www.rfc-editor.org/rfc/rfc8879.html#section-3).
pub fn parse_tls_extension_certificate_compression(
    id: u16,
    data: &[u8],
) -> IResult<&[u8], TlsExtension> {
    let (input, length) = verify(be_u8, |length| *length >= 2 && *length % 2 == 0).parse(data)?;
    let (input, payload) = take(length).parse(input)?;
    let (input, _) = eof(input)?;
    let (_, algorithms) = parse_u16_type(payload)?;

    Ok((
        input,
        TlsExtension::CertificateCompression {
            value: id,
            data: algorithms,
        },
    ))
}

/// Parses an outer or inner Encrypted ClientHello extension.
///
/// The outer form retains the encoded two-byte payload length next to its hexadecimal payload.
/// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
pub fn parse_tls_extension_ech(id: u16, data: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (input, is_outer) = map_opt(be_u8, |v| match v {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    })
    .parse(data)?;

    match is_outer {
        true => {
            let (input, (kdf_id, aead_id, config_id)) = (be_u16, be_u16, be_u8).parse(input)?;
            let (input, enc) = length_data(be_u16).parse(input)?;
            let (input, payload_length) = verify(be_u16, |length| *length > 0).parse(input)?;
            let (input, payload) = take(payload_length).parse(input)?;
            let (input, _) = eof(input)?;

            Ok((
                input,
                TlsExtension::EncryptedClientHello {
                    value: id,
                    data: ECHClientHello::Outer(ECHClientHelloOuter {
                        cipher_suite: HpkeSymmetricCipherSuite {
                            aead_id: aead_id.into(),
                            kdf_id: kdf_id.into(),
                        },
                        config_id,
                        enc: HexBytes::from(enc),
                        payload_length,
                        payload: HexBytes::from(payload),
                    }),
                },
            ))
        }
        false => {
            let (input, _) = eof(input)?;
            Ok((
                input,
                TlsExtension::EncryptedClientHello {
                    value: id,
                    data: ECHClientHello::Inner,
                },
            ))
        }
    }
}

/// Parses protocol names from an ALPN payload.
///
/// See [RFC 7301, Section 3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1).
pub fn parse_alpn_packet(data: &[u8]) -> IResult<&[u8], Vec<ProtocolName>> {
    parse_protocol_name_list(data)
}

/// Parses protocol names from an Application-Layer Protocol Settings payload.
///
/// ALPS remains an Internet-Draft; see
/// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
pub fn parse_alps_packet(data: &[u8]) -> IResult<&[u8], Vec<ProtocolName>> {
    parse_protocol_name_list(data)
}

fn parse_protocol_name_list(data: &[u8]) -> IResult<&[u8], Vec<ProtocolName>> {
    let (input, payload_len) = verify(be_u16, |length| *length >= 2).parse(data)?;
    let (input, payload) = take(payload_len).parse(input)?;
    let (input, _) = eof(input)?;

    let mut protocols = Vec::new();
    let mut remaining = payload;
    while !remaining.is_empty() {
        let (next, protocol_len) = verify(be_u8, |length| *length > 0).parse(remaining)?;
        let (next, protocol) = take(protocol_len).parse(next)?;
        let protocol = ProtocolName::try_from(protocol)
            .map_err(|_| nom::Err::Error(make_error(protocol, ErrorKind::Verify)))?;
        protocols.push(protocol);
        remaining = next;
    }

    Ok((input, protocols))
}

fn parse_u16_type<T: From<u16>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    if !i.len().is_multiple_of(2) {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }

    let values = i
        .chunks_exact(2)
        .map(|chunk| T::from(((chunk[0] as u16) << 8) | chunk[1] as u16))
        .collect();
    Ok((&[], values))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_alpn_packet, parse_alps_packet, parse_key_share, parse_ocsp_status_request_lengths,
        parse_tls_extension_certificate_compression, parse_tls_extension_delegated_credentials,
        parse_tls_extension_ech,
    };
    use crate::tls::hello::{ECHClientHello, TlsExtension};

    #[test]
    fn ech_outer_preserves_payload_length() {
        let data = [
            0x00, // outer
            0x00, 0x01, // HKDF-SHA256
            0x00, 0x01, // AES-128-GCM
            0x07, // config_id
            0x00, 0x02, 0xaa, 0xbb, // enc
            0x00, 0x03, 0xcc, 0xdd, 0xee, // payload
        ];

        let (remaining, extension) =
            parse_tls_extension_ech(0xfe0d, &data).expect("valid ECH outer extension");
        assert!(remaining.is_empty());

        let TlsExtension::EncryptedClientHello {
            data: ECHClientHello::Outer(outer),
            ..
        } = extension
        else {
            panic!("expected an ECH outer extension");
        };

        assert_eq!(outer.payload_length, 3);
        assert_eq!(outer.payload.as_bytes(), [0xcc, 0xdd, 0xee]);

        let json = serde_json::to_value(outer).expect("ECH outer serializes");
        assert_eq!(json["payload_length"], 3);
    }

    #[test]
    fn key_share_requires_exact_declared_lengths() {
        let valid = [0, 6, 0, 29, 0, 2, 0xaa, 0xbb];
        assert_eq!(parse_key_share(&valid), Some(vec![(29, vec![0xaa, 0xbb])]));

        assert!(parse_key_share(&[0, 5, 0, 29, 0, 2, 0xaa]).is_none());
        assert!(parse_key_share(&[0, 1, 0]).is_none());
        assert!(parse_key_share(&[0, 0, 0]).is_none());
    }

    #[test]
    fn ocsp_status_request_consumes_nested_vectors() {
        let valid = [0, 3, 0, 1, 0xaa, 0, 2, 0xbb, 0xcc];
        let (remaining, lengths) =
            parse_ocsp_status_request_lengths(&valid).expect("valid OCSP status request");

        assert!(remaining.is_empty());
        assert_eq!(lengths, (3, 2));
        assert_eq!(
            parse_ocsp_status_request_lengths(&[0, 0, 0, 0]),
            Ok((&[][..], (0, 0)))
        );

        for malformed in [
            &[0, 2, 0, 0, 0, 0][..],
            &[0, 3, 0, 2, 0xaa, 0, 0][..],
            &[0, 0, 0, 2, 0xaa][..],
            &[0, 0, 0, 0, 0xaa][..],
        ] {
            assert!(parse_ocsp_status_request_lengths(malformed).is_err());
        }
    }

    #[test]
    fn delegated_credentials_require_a_complete_nonempty_vector() {
        let valid = [0, 4, 0x04, 0x03, 0x08, 0x04];
        assert!(parse_tls_extension_delegated_credentials(34, &valid).is_ok());

        for malformed in [
            &[0, 0][..],
            &[0, 1, 0][..],
            &[0, 4, 0x04, 0x03][..],
            &[0, 2, 0x04, 0x03, 0][..],
        ] {
            assert!(parse_tls_extension_delegated_credentials(34, malformed).is_err());
        }
    }

    #[test]
    fn certificate_compression_requires_a_complete_nonempty_vector() {
        let valid = [4, 0, 1, 0, 2];
        assert!(parse_tls_extension_certificate_compression(27, &valid).is_ok());

        for malformed in [&[0][..], &[1, 0][..], &[4, 0, 1][..], &[2, 0, 1, 0][..]] {
            assert!(parse_tls_extension_certificate_compression(27, malformed).is_err());
        }
    }

    #[test]
    fn ech_requires_exact_outer_and_inner_payloads() {
        let outer = [
            0, 0, 1, 0, 1, 7, 0, 0, // type, suite, config, empty enc
            0, 1, 0xaa, // nonempty payload
        ];
        assert!(parse_tls_extension_ech(0xfe0d, &outer).is_ok());

        let mut trailing = outer.to_vec();
        trailing.push(0);
        assert!(parse_tls_extension_ech(0xfe0d, &trailing).is_err());
        assert!(parse_tls_extension_ech(0xfe0d, &[0, 0, 1, 0, 1, 7, 0, 0, 0, 0]).is_err());
        assert!(parse_tls_extension_ech(0xfe0d, &[1]).is_ok());
        assert!(parse_tls_extension_ech(0xfe0d, &[1, 0]).is_err());
    }

    #[test]
    fn protocol_name_lists_are_strict_and_lossless() {
        let valid = [0, 6, 2, b'h', b'2', 2, 0xff, b'x'];
        let (remaining, protocols) = parse_alps_packet(&valid).expect("valid ALPS names");

        assert!(remaining.is_empty());
        assert_eq!(protocols.len(), 2);
        assert_eq!(protocols[0].as_bytes(), b"h2");
        assert_eq!(protocols[1].as_bytes(), [0xff, b'x']);

        let (remaining, alpn_protocols) = parse_alpn_packet(&valid).expect("valid ALPN names");
        assert!(remaining.is_empty());
        assert_eq!(alpn_protocols, protocols);

        for malformed in [
            &[0, 0][..],
            &[0, 2, 0, 0][..],
            &[0, 3, 2, b'h'][..],
            &[0, 3, 2, b'h', b'2', 0][..],
        ] {
            assert!(parse_alps_packet(malformed).is_err());
            assert!(parse_alpn_packet(malformed).is_err());
        }
    }
}
