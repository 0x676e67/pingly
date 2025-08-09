use std::{io, path::Path, sync::Arc};

use axum_server::tls_rustls::RustlsConfig;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls_pemfile::Item;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

// Load TLS configuration from self-signed PEM files
pub async fn config_self_signed() -> crate::Result<RustlsConfig> {
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
            .expect("private key should be present in the file"),
    )
    .map_err(io::Error::other)?;

    Ok(config_from_der(cert, key)?)
}

/// Load TLS configuration from PEM files
pub async fn config_from_pem_chain_file(
    cert: impl AsRef<Path>,
    chain: impl AsRef<Path>,
) -> crate::Result<RustlsConfig> {
    let cert = tokio::fs::read(cert.as_ref()).await?;
    let cert = rustls_pemfile::certs(&mut cert.as_ref())
        .map(|it| it.map(|it| CertificateDer::from(it.to_vec())))
        .collect::<Result<Vec<_>, _>>()?;

    let key = tokio::fs::read(chain.as_ref()).await?;
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

    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"http/1.0".to_vec(),
        b"http/0.9".to_vec(),
    ];

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn get_self_signed_cert() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let temp_dir = std::env::temp_dir().join(env!("CARGO_PKG_NAME"));
    if !temp_dir.exists() {
        tracing::info!("Creating temp cert directory: {}", temp_dir.display());
        std::fs::create_dir_all(&temp_dir)?;
    }

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(cert_path)?;
        let key = std::fs::read(key_path)?;
        return Ok((cert, key));
    }

    let (cert, key) = generate_self_signed()?;
    std::fs::write(cert_path, &cert)?;
    std::fs::write(key_path, &key)?;
    Ok((cert, key))
}

fn generate_self_signed() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(1975, 1, 1);
    params.not_after = date_time_ymd(4096, 1, 1);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "penumbra-x");
    distinguished_name.push(DnType::OrganizationName, "penumbra-x");
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into()?)];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert = cert.pem();
    tracing::info!("Generating self-signed certificate:\n{}", cert);

    Ok((cert.into_bytes(), key_pair.serialize_pem().into_bytes()))
}
