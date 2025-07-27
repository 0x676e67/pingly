use std::{pin::Pin, task, task::Poll};

use serde::Serialize;
use tls_parser::{TlsCipherSuite, TlsExtension, TlsMessage, TlsMessageHandshake};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

pin_project_lite::pin_project! {
    pub struct TlsInspector<I> {
        #[pin]
        inner: I,

        buf: Vec<u8>,
        client_hello: Option<ClientHello>,
    }
}

impl<I> TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            client_hello: None,
        }
    }

    /// Get client hello payload
    /// Take the ownership of client hello payload, leaving the `None` in the place
    #[inline]
    #[must_use]
    pub fn client_hello(&mut self) -> Option<ClientHello> {
        self.client_hello.take()
    }
}

impl<I> AsyncRead for TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf.filled().len();
        let me = self.project();
        let poll = me.inner.poll_read(cx, buf);

        if me.client_hello.is_none() {
            me.buf.extend(&buf.filled()[len..]);
            *me.client_hello = ClientHello::parse(me.buf);
        }

        poll
    }
}

impl<I> AsyncWrite for TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[derive(Clone, Serialize)]
pub struct ClientHello {
    pub ciphers: Vec<&'static str>,
    pub extensions: Vec<Extension>,
    pub version: String,
    pub random: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Extension {
    name: String,
    value: Vec<u8>,
}

/// ==== impl ClientHello ====

impl ClientHello {
    #[inline]
    fn parse(bytes: &[u8]) -> Option<ClientHello> {
        let (_, r) = tls_parser::parse_tls_raw_record(bytes).ok()?;
        let (_, msg_list) = tls_parser::parse_tls_record_with_header(r.data, &r.hdr).ok()?;

        // Find client hello payload
        if let Some(TlsMessage::Handshake(TlsMessageHandshake::ClientHello(payload))) =
            msg_list.into_iter().find(|msg| {
                matches!(
                    msg,
                    TlsMessage::Handshake(TlsMessageHandshake::ClientHello(_))
                )
            })
        {
            // Parse tls extensions
            let ext = payload.ext?;
            let (_, ext_list) = tls_parser::parse_tls_client_hello_extensions(ext).ok()?;

            let client_hello = ClientHello {
                ciphers: payload
                    .ciphers
                    .iter()
                    .flat_map(|v| TlsCipherSuite::from_id(v.0).map(|v| v.name))
                    .collect(),
                extensions: vec![],
                version: format!("{}", payload.version),
                random: hex::encode(payload.random),
                session_id: payload.session_id.map(hex::encode),
            };

            for extension in ext_list {
                match extension {
                    TlsExtension::SNI(v) => {
                        let _ = v.into_iter().map(|(_, v)| dbg!(String::from_utf8_lossy(v)));
                    }
                    _ => {} /* TlsExtension::MaxFragmentLength(_) => todo!(),
                             * TlsExtension::StatusRequest(_) => todo!(),
                             * TlsExtension::EllipticCurves(vec) => todo!(),
                             * TlsExtension::EcPointFormats(_) => todo!(),
                             * TlsExtension::SignacatureAlgorithms(vec) => todo!(),
                             * TlsExtension::RecordSizeLimit(_) => todo!(),
                             * TlsExtension::SessionTicket(_) => todo!(),
                             * TlsExtension::KeyShareOld(_) => todo!(),
                             * TlsExtension::KeyShare(_) => todo!(),
                             * TlsExtension::PreSharedKey(_) => todo!(),
                             * TlsExtension::EarlyData(_) => todo!(),
                             * TlsExtension::SupportedVersions(vec) => todo!(),
                             * TlsExtension::Cookie(_) => todo!(),
                             * TlsExtension::PskExchangeModes(vec) => todo!(),
                             * TlsExtension::Heartbeat(_) => todo!(),
                             * TlsExtension::ALPN(vec) => todo!(),
                             * TlsExtension::SignedCertificateTimestamp(_) => todo!(),
                             * TlsExtension::Padding(_) => todo!(),
                             * TlsExtension::EncryptThenMac => todo!(),
                             * TlsExtension::ExtendedMasterSecret => todo!(),
                             * TlsExtension::OidFilters(vec) => todo!(),
                             * TlsExtension::PostHandshakeAuth => todo!(),
                             * TlsExtension::NextProtocolNegotiation => todo!(),
                             * TlsExtension::RenegotiationInfo(_) => todo!(),
                             * TlsExtension::EncryptedServerName { ciphersuite, group, key_share,
                             * record_digest, encrypted_sni } => todo!(),
                             * TlsExtension::Grease(_, _) => todo!(),
                             * TlsExtension::Unknown(tls_extension_type, _) => todo!(), */
                }
            }

            return Some(client_hello);
        }

        None
    }
}

/// Find the signature name from the value
#[allow(unused)]
#[inline]
pub fn find_signature_name(value: &u16) -> Option<&'static str> {
    match value {
        513 => Some("rsa_pkcs1_sha1"),
        515 => Some("ecdsa_sha1"),
        1025 => Some("rsa_pkcs1_sha256"),
        1027 => Some("ecdsa_secp256r1_sha256"),
        1056 => Some("rsa_pkcs1_sha256_legacy"),
        1281 => Some("rsa_pkcs1_sha384"),
        1283 => Some("ecdsa_secp384r1_sha384"),
        1312 => Some("rsa_pkcs1_sha384_legacy"),
        1537 => Some("rsa_pkcs1_sha512"),
        1539 => Some("ecdsa_secp521r1_sha512"),
        1568 => Some("rsa_pkcs1_sha512_legacy"),
        1796 => Some("eccsi_sha256"),
        1797 => Some("iso_ibs1"),
        1798 => Some("iso_ibs2"),
        1799 => Some("iso_chinese_ibs"),
        1800 => Some("sm2sig_sm3"),
        1801 => Some("gostr34102012_256a"),
        1802 => Some("gostr34102012_256b"),
        1803 => Some("gostr34102012_256c"),
        1804 => Some("gostr34102012_256d"),
        1805 => Some("gostr34102012_512a"),
        1806 => Some("gostr34102012_512b"),
        1807 => Some("gostr34102012_512c"),
        2052 => Some("rsa_pss_rsae_sha256"),
        2053 => Some("rsa_pss_rsae_sha384"),
        2054 => Some("rsa_pss_rsae_sha512"),
        2055 => Some("ed25519"),
        2056 => Some("ed448"),
        2057 => Some("rsa_pss_pss_sha256"),
        2058 => Some("rsa_pss_pss_sha384"),
        2059 => Some("rsa_pss_pss_sha512"),
        2074 => Some("ecdsa_brainpoolP256r1tls13_sha256"),
        2075 => Some("ecdsa_brainpoolP384r1tls13_sha384"),
        2076 => Some("ecdsa_brainpoolP512r1tls13_sha512"),
        _ => None,
    }
}
