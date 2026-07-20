use std::{io, path::Path, sync::Arc};

use rcgen::{
    date_time_ymd, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pemfile::Item;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

use super::tls::rustls::{set_http_alpn_protocols, RustlsConfig};

const SELF_SIGNED_CERTIFICATE_VERSION: &[u8] = b"2";

/// Loads the reusable self-signed certificate generated for local development.
pub(super) fn config_self_signed() -> crate::Result<RustlsConfig> {
    let (cert, key) = get_self_signed_cert()?;
    let cert = rustls_pemfile::certs(&mut cert.as_ref())
        .map(|it| it.map(|it| it.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;

    // Check the entire PEM file for the key in case it is not first section
    let mut key_vec: Vec<Vec<u8>> = rustls_pemfile::read_all(&mut key.as_ref())
        .filter_map(|i| match i.ok()? {
            Item::Sec1Key(key) => Some(key.secret_sec1_der().to_vec()),
            Item::Pkcs1Key(key) => Some(key.secret_pkcs1_der().to_vec()),
            Item::Pkcs8Key(key) => Some(key.secret_pkcs8_der().to_vec()),
            _ => None,
        })
        .collect();

    // Make sure file contains only one key
    if key_vec.len() != 1 {
        return Err(io::Error::other("private key format not supported").into());
    }

    let cert = cert.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::try_from(
        key_vec
            .pop()
            .ok_or_else(|| io::Error::other("private key should be present in the file"))?,
    )
    .map_err(io::Error::other)?;

    Ok(config_from_der(cert, key)?)
}

/// Loads a certificate chain and private key from PEM files.
pub(super) fn config_from_pem_chain_file(cert: &Path, key: &Path) -> crate::Result<RustlsConfig> {
    let cert = std::fs::read(cert)?;
    let cert = rustls_pemfile::certs(&mut cert.as_ref())
        .map(|it| it.map(|it| CertificateDer::from(it.to_vec())))
        .collect::<Result<Vec<_>, _>>()?;

    let key = std::fs::read(key)?;
    let key_cert: PrivateKeyDer = match rustls_pemfile::read_one(&mut key.as_ref())?
        .ok_or_else(|| io::Error::other("could not parse pem file"))?
    {
        Item::Pkcs8Key(key) => Ok(key.into()),
        Item::Sec1Key(key) => Ok(key.into()),
        Item::Pkcs1Key(key) => Ok(key.into()),
        x => Err(io::Error::other(format!(
            "invalid certificate format, received: {x:?}"
        ))),
    }?;

    Ok(config_from_der(cert, key_cert)?)
}

fn config_from_der(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
) -> io::Result<RustlsConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(io::Error::other)?;

    set_http_alpn_protocols(&mut config);

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn get_self_signed_cert() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let certificate_dir = crate::state::directory().join("tls");
    crate::state::prepare_private_directory(&certificate_dir)?;

    let cert_path = certificate_dir.join("cert.pem");
    let key_path = certificate_dir.join("key.pem");
    let version_path = certificate_dir.join("version");
    let version_matches = match std::fs::read(&version_path) {
        Ok(version) => version == SELF_SIGNED_CERTIFICATE_VERSION,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };

    if version_matches && cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(cert_path)?;
        let key = std::fs::read(key_path)?;
        return Ok((cert, key));
    }

    let (cert, key) = generate_self_signed()?;
    std::fs::write(cert_path, &cert)?;
    std::fs::write(key_path, &key)?;
    std::fs::write(version_path, SELF_SIGNED_CERTIFICATE_VERSION)?;
    Ok((cert, key))
}

fn generate_self_signed() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(1975, 1, 1);
    params.not_after = date_time_ymd(4096, 1, 1);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, env!("CARGO_PKG_NAME"));
    distinguished_name.push(DnType::OrganizationName, env!("CARGO_PKG_NAME"));
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // A TLS server certificate is an end-entity certificate, not a CA certificate.
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
    params.is_ca = IsCa::NoCa;
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into()?)];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert = cert.pem();
    tracing::info!("Generating self-signed certificate:\n{}", cert);

    Ok((cert.into_bytes(), key_pair.serialize_pem().into_bytes()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio_rustls::rustls::{
        client::{danger::ServerCertVerifier, WebPkiServerVerifier},
        pki_types::{ServerName, UnixTime},
        RootCertStore,
    };

    use super::generate_self_signed;

    #[test]
    fn self_signed_certificate_is_a_valid_server_end_entity() {
        let (pem, _) = generate_self_signed().expect("certificate should generate");
        let certificate = rustls_pemfile::certs(&mut pem.as_slice())
            .next()
            .expect("certificate should be present")
            .expect("certificate should parse");

        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.clone())
            .expect("certificate should be a trust anchor");
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("verifier should build");
        let server_name = ServerName::try_from("localhost").expect("valid server name");

        verifier
            .verify_server_cert(&certificate, &[], &server_name, &[], UnixTime::now())
            .expect("certificate should be valid for localhost");
    }
}
