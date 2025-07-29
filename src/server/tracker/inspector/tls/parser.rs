use nom::{
    combinator::{map, map_opt, map_parser},
    error::{make_error, ErrorKind},
    multi::length_data,
    number::streaming::{be_u16, be_u8},
    IResult, Parser,
};

use super::hello::{ECHClientHello, ECHClientHelloOuter, HpkeSymmetricCipherSuite, TlsExtension};

/// Parse KeyShare extension in TLS 1.3 (RFC 8446) with 4-byte length and 4-byte fields.
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

/// Parse the OCSP status request extension from the ClientHello.
pub fn parse_ocsp_status_request_lengths(data: &[u8]) -> IResult<&[u8], (u16, u16)> {
    (be_u16, be_u16).parse(data)
}

/// Parse extension for delegated credentials.
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

/// Parses extension for certificate compression
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

/// Parses extension for encrypted client hello (ECH).
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
            let (input, payload) = length_data(be_u16).parse(input)?;

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
                        enc: hex::encode(enc),
                        payload: hex::encode(payload),
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

/// The alpn_protocol_name field MUST match the protocol negotiated by ALPN.
/// The extension is only sent by the server, and only for the selected protocol.
/// See <https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps>
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
