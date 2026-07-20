use std::{
    any::Any,
    io,
    sync::{Arc, OnceLock},
};

use pingly::tls::ClientHelloHandshakeBuffer;
use quinn_proto::{
    crypto::{self, rustls::QuicServerConfig},
    transport_parameters::TransportParameters,
    ConnectionId, Side, TransportError,
};
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;

/// Handshake details exposed by the ClientHello-capturing Quinn session.
pub(super) struct HandshakeData {
    /// Raw ClientHello handshake bytes retained for delayed analysis.
    client_hello: Arc<OnceLock<ClientHelloHandshakeBuffer>>,
}

impl HandshakeData {
    /// Returns shared storage containing the captured ClientHello.
    pub(super) fn client_hello(&self) -> Arc<OnceLock<ClientHelloHandshakeBuffer>> {
        self.client_hello.clone()
    }
}

/// Builds a Quinn configuration that observes TLS handshake bytes before forwarding them.
pub(super) fn server_config(mut rustls: RustlsServerConfig) -> io::Result<quinn::ServerConfig> {
    rustls.alpn_protocols = vec![b"h3".to_vec()];

    let inner = QuicServerConfig::try_from(Arc::new(rustls)).map_err(io::Error::other)?;
    let crypto = CaptureServerConfig {
        inner: Arc::new(inner),
    };
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Quinn crypto configuration that creates one capturing wrapper per handshake.
struct CaptureServerConfig {
    /// Rustls-backed Quinn crypto configuration receiving delegated operations.
    inner: Arc<dyn crypto::ServerConfig>,
}

impl crypto::ServerConfig for CaptureServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.inner.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        parameters: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let client_hello = Arc::new(OnceLock::new());
        Box::new(CaptureSession {
            inner: self.inner.clone().start_session(version, parameters),
            buffer: Some(ClientHelloHandshakeBuffer::new()),
            client_hello,
        })
    }
}

/// QUIC crypto session that retains only the peer's first ClientHello message.
struct CaptureSession {
    /// Rustls-backed session receiving every delegated crypto operation.
    inner: Box<dyn crypto::Session>,

    /// Bounded handshake buffer removed once the ClientHello is complete or invalid.
    buffer: Option<ClientHelloHandshakeBuffer>,

    /// Completed capture shared with response-stage protocol analysis.
    client_hello: Arc<OnceLock<ClientHelloHandshakeBuffer>>,
}

impl CaptureSession {
    fn inspect_handshake(&mut self, bytes: &[u8]) {
        let Some(buffer) = self.buffer.as_mut() else {
            return;
        };
        buffer.extend(bytes);

        if buffer.is_complete() || buffer.is_invalid() || buffer.is_full() {
            if let Some(buffer) = self.buffer.take() {
                let _ = self.client_hello.set(buffer);
            }
        }
    }
}

impl crypto::Session for CaptureSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data().map(|_| {
            Box::new(HandshakeData {
                client_hello: self.client_hello.clone(),
            }) as Box<dyn Any>
        })
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, bytes: &[u8]) -> Result<bool, TransportError> {
        self.inspect_handshake(bytes);
        self.inner.read_handshake(bytes)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buffer: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.inner.write_handshake(buffer)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}
