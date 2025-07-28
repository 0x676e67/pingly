//! Perma-forked from
//! tls-parser @ 65a2fe0b86f09235515337c501c8a512db1c6dba
//!
//! src and attribution: <https://github.com/rusticata/tls-parser>

use nom::{
    bytes::streaming::take,
    combinator::{complete, map, map_opt, map_parser},
    error::{make_error, ErrorKind},
    multi::{length_data, many0},
    number::streaming::{be_u16, be_u8},
    IResult, Parser,
};

use super::{
    enums::{ApplicationProtocol, ExtensionId, TlsVersion},
    hello::{ClientHelloExtension, ECHClientHello, ECHClientHelloOuter, HpkeSymmetricCipherSuite},
};

pub fn parse_tls_client_hello_extension(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    let (i, ext_type) = be_u16(i)?;
    let id = ExtensionId::from(ext_type);
    let (i, ext_data) = length_data(be_u16).parse(i)?;

    let ext_len = ext_data.len() as u16;

    let (_, ext) = match id {
        ExtensionId::SERVER_NAME => parse_tls_extension_sni_content(ext_data),
        ExtensionId::SUPPORTED_GROUPS => parse_tls_extension_elliptic_curves_content(ext_data),
        ExtensionId::EC_POINT_FORMATS => parse_tls_extension_ec_point_formats_content(ext_data),
        ExtensionId::SIGNATURE_ALGORITHMS => {
            parse_tls_extension_signature_algorithms_content(ext_data)
        }
        ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
            parse_tls_extension_alpn_content(ext_data)
        }
        ExtensionId::SUPPORTED_VERSIONS => {
            parse_tls_extension_supported_versions_content(ext_data, ext_len)
        }
        ExtensionId::COMPRESS_CERTIFICATE => {
            parse_tls_extension_certificate_compression_content(ext_data)
        }
        ExtensionId::DELEGATED_CREDENTIAL => parse_tls_extension_delegated_credentials(ext_data),
        ExtensionId::RECORD_SIZE_LIMIT => {
            let (i, v) = be_u16(ext_data)?;
            Ok((i, ClientHelloExtension::RecordSizeLimit(v)))
        }
        ExtensionId::ENCRYPTED_CLIENT_HELLO => {
            let (i, ech) = parse_ech_client_hello(ext_data)?;
            Ok((i, ClientHelloExtension::EncryptedClientHello(ech)))
        }
        ExtensionId::APPLICATION_SETTINGS | ExtensionId::OLD_APPLICATION_SETTINGS => {
            parse_tls_extension_application_settings_content(ext_data)
        }
        _ => Ok((
            i,
            ClientHelloExtension::Opaque {
                id,
                data: ext_data.to_vec(),
            },
        )),
    }?;
    Ok((i, ext))
}

fn parse_tls_extension_sni_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    let (i, domain) = parse_tls_extension_sni(i)?;
    Ok((i, ClientHelloExtension::ServerName(domain)))
}

fn parse_tls_extension_sni(i: &[u8]) -> IResult<&[u8], Option<String>> {
    if i.is_empty() {
        // special case: SNI extension in server can be empty
        return Ok((i, None));
    }
    let (i, list_len) = be_u16(i)?;
    let (i, mut v) = map_parser(
        take(list_len),
        many0(complete(parse_tls_extension_sni_hostname)),
    )
    .parse(i)?;
    if v.len() > 1 {
        return Err(nom::Err::Error(nom::error::Error::new(
            i,
            ErrorKind::TooLarge,
        )));
    }
    Ok((i, v.pop()))
}

fn parse_tls_extension_sni_hostname(i: &[u8]) -> IResult<&[u8], String> {
    let (i, nt) = be_u8(i)?;
    if nt != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(i, ErrorKind::IsNot)));
    }
    let (i, v) = length_data(be_u16).parse(i)?;
    let host = str::from_utf8(v)
        .map_err(|_| nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not)))?
        .parse()
        .map_err(|_| nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not)))?;

    Ok((i, host))
}

// defined in rfc8422
fn parse_tls_extension_elliptic_curves_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::SupportedGroups),
    )
    .parse(i)
}

fn parse_tls_extension_ec_point_formats_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u8_type, ClientHelloExtension::ECPointFormats),
    )
    .parse(i)
}

// TLS 1.3 draft 23
fn parse_tls_extension_supported_versions_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], ClientHelloExtension> {
    if ext_len == 2 {
        map(be_u16, |x| {
            ClientHelloExtension::SupportedVersions(vec![TlsVersion::from(x)])
        })
        .parse(i)
    } else {
        let (i, _) = be_u8(i)?;
        if ext_len == 0 {
            return Err(nom::Err::Error(make_error(i, ErrorKind::Verify)));
        }
        let (i, l) = map_parser(take(ext_len - 1), parse_u16_type).parse(i)?;
        Ok((i, ClientHelloExtension::SupportedVersions(l)))
    }
}

/// Parse 'Signature Algorithms' extension (rfc8446, TLS 1.3 only)
fn parse_tls_extension_signature_algorithms_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::SignatureAlgorithms),
    )
    .parse(i)
}

// Parse 'Delegated credentials' extensions (rfc9345)
fn parse_tls_extension_delegated_credentials(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::DelegatedCredentials),
    )
    .parse(i)
}

/// Defined in [RFC7301]
fn parse_tls_extension_alpn_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(
            parse_protocol_name_list,
            ClientHelloExtension::ApplicationLayerProtocolNegotiation,
        ),
    )
    .parse(i)
}

fn parse_tls_extension_certificate_compression_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u16_type, ClientHelloExtension::CertificateCompression),
    )
    .parse(i)
}

fn parse_protocol_name_list(mut i: &[u8]) -> IResult<&[u8], Vec<ApplicationProtocol>> {
    let mut v = vec![];
    while !i.is_empty() {
        let (n, alpn) = map_parser(length_data(be_u8), parse_protocol_name).parse(i)?;
        v.push(alpn);
        i = n;
    }
    Ok((&[], v))
}

fn parse_protocol_name(i: &[u8]) -> IResult<&[u8], ApplicationProtocol> {
    let alpn = ApplicationProtocol::from(i);
    Ok((&[], alpn))
}

fn parse_tls_extension_application_settings_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(
            parse_protocol_name_list,
            ClientHelloExtension::ApplicationSettings,
        ),
    )
    .parse(i)
}

fn parse_u8_type<T: From<u8>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    let v = i.iter().map(|i| T::from(*i)).collect();
    Ok((&[], v))
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

fn parse_ech_client_hello(input: &[u8]) -> IResult<&[u8], ECHClientHello> {
    let (input, is_outer) = map_opt(be_u8, |v| match v {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    })
    .parse(input)?;

    match is_outer {
        true => {
            let (input, (kdf_id, aead_id, config_id)) = (be_u16, be_u16, be_u8).parse(input)?;
            let (input, enc) = length_data(be_u16).parse(input)?;
            let (input, payload) = length_data(be_u16).parse(input)?;

            Ok((
                input,
                ECHClientHello::Outer(ECHClientHelloOuter {
                    cipher_suite: HpkeSymmetricCipherSuite {
                        aead_id: aead_id.into(),
                        kdf_id: kdf_id.into(),
                    },
                    config_id,
                    enc: enc.to_vec(),
                    payload: payload.to_vec(),
                }),
            ))
        }
        false => Ok((input, ECHClientHello::Inner)),
    }
}
