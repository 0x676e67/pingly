use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, map_parser},
    error::{make_error, ErrorKind},
    multi::length_data,
    number::streaming::{be_u16, be_u8},
    IResult, Parser,
};

use hex::encode as hex_encode;

use super::hello::{ECHClientHello, ECHClientHelloOuter, HpkeSymmetricCipherSuite, TlsExtension};

/// Parses the client form of the TLS 1.3 `key_share` extension.
///
/// Each entry starts with a two-byte named-group ID and a two-byte key length.
/// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
pub fn parse_key_share(data: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    if data.len() < 2 {
        return None;
    }
    let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + total_len {
        return None;
    }
    let mut res = Vec::new();
    let mut i = 2;
    while i + 4 <= 2 + total_len {
        let group = u16::from_be_bytes([data[i], data[i + 1]]);
        let key_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + key_len > data.len() {
            break;
        }
        let key = data[i..i + key_len].to_vec();
        res.push((group, key));
        i += key_len;
    }
    Some(res)
}

/// Parses the length fields from a ClientHello OCSP `status_request` payload.
///
/// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
pub fn parse_ocsp_status_request_lengths(data: &[u8]) -> IResult<&[u8], (u16, u16)> {
    (be_u16, be_u16).parse(data)
}

/// Parses the client form of the delegated-credentials extension.
///
/// See [RFC 9345, Section 4.1](https://www.rfc-editor.org/rfc/rfc9345.html#section-4.1).
pub fn parse_tls_extension_delegated_credentials(
    id: u16,
    data: &[u8],
) -> IResult<&[u8], TlsExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, |x| TlsExtension::DelegatedCredentials {
            value: id,
            data: x,
        }),
    )
    .parse(data)
}

/// Parses the client form of the certificate-compression extension.
///
/// See [RFC 8879, Section 3](https://www.rfc-editor.org/rfc/rfc8879.html#section-3).
pub fn parse_tls_extension_certificate_compression(
    id: u16,
    data: &[u8],
) -> IResult<&[u8], TlsExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u16_type, |args| {
            TlsExtension::CertificateCompression {
                value: id,
                data: args,
            }
        }),
    )
    .parse(data)
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
            let (input, payload_length) = be_u16(input)?;
            let (input, payload) = take(payload_length).parse(input)?;

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
                        enc: hex_encode(enc),
                        payload_length,
                        payload: hex_encode(payload),
                    }),
                },
            ))
        }
        false => Ok((
            input,
            TlsExtension::EncryptedClientHello {
                value: id,
                data: ECHClientHello::Inner,
            },
        )),
    }
}

/// Parses protocol names from an Application-Layer Protocol Settings payload.
///
/// ALPS remains an Internet-Draft; see
/// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
pub fn parse_alps_packet(d: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();

    if d.len() < 3 {
        return protocols;
    }

    let mut cursor = 0;

    if d[0] == 0 {
        cursor += 1;
    }

    if cursor >= d.len() {
        return protocols;
    }

    cursor += 1;

    while cursor < d.len() {
        let len = d[cursor] as usize;
        cursor += 1;

        if cursor + len > d.len() {
            break;
        }

        let proto_bytes = &d[cursor..cursor + len];
        let proto_str = match std::str::from_utf8(proto_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => return protocols,
        };

        protocols.push(proto_str);
        cursor += len;
    }

    protocols
}

fn parse_u16_type<T: From<u16>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    let len = i.len();
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| T::from(((chunk[0] as u16) << 8) | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

#[cfg(test)]
mod tests {
    use super::parse_tls_extension_ech;
    use crate::proto::tls::hello::{ECHClientHello, TlsExtension};

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
        assert_eq!(outer.payload, "ccddee");

        let json = serde_json::to_value(outer).expect("ECH outer serializes");
        assert_eq!(json["payload_length"], 3);
    }
}
