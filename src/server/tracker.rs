use std::{
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use axum::{
    body::Body,
    http::{header::USER_AGENT, HeaderValue, Method, Request},
    middleware::AddExtension,
    Extension,
};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use pin_project_lite::pin_project;
use serde::{Serialize, Serializer};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{rustls::ProtocolVersion, server::TlsStream};
use tower::Layer;

use crate::{
    http2::{frame, frame::Frame, AkamaiFingerprint, Http2Frame},
    tls::{ClientHello, LazyClientHello},
};

#[cfg(target_os = "linux")]
use crate::tcp::CapturedPacket;

pub type Http1Headers = Arc<boxcar::Vec<(Bytes, Bytes)>>;

/// TrackAcceptor is a wrapper around RustlsAcceptor that inspects incoming TLS connections,
/// automatically detects the negotiated ALPN protocol (such as HTTP/1.1 or HTTP/2),
/// and wraps the stream with the appropriate Inspector type (Http1Inspector or Http2Inspector).
#[derive(Clone)]
pub struct TrackAcceptor(RustlsAcceptor);

impl TrackAcceptor {
    /// Create a new [`TrackAcceptor`] with the provided RustlsAcceptor.
    pub fn new(acceptor: RustlsAcceptor) -> Self {
        Self(acceptor)
    }
}

impl<I, S> Accept<I, S> for TrackAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = Inspector<I>;
    type Service = AddExtension<S, ConnectionTrack>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.0.clone();
        Box::pin(async move {
            let (mut stream, service) = acceptor.accept(TlsInspector::new(stream), service).await?;
            let mut connect_track = ConnectionTrack::default();
            connect_track.set_client_hello(stream.get_mut().0.client_hello());
            connect_track.set_tls_version_negotiated(stream.get_ref().1.protocol_version());

            let stream = match stream.get_ref().1.alpn_protocol() {
                // If ALPN is set to HTTP/2, use Http2Inspector
                Some(b"h2") => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/2");
                    let inspector = Http2Inspector::new(stream);
                    connect_track.set_http2_frames(inspector.frames());
                    Inspector::Http2(inspector)
                }
                //  If ALPN is not set, default to HTTP/1.1
                _ => {
                    tracing::debug!("negotiated ALPN protocol: HTTP/1.1 or not set");
                    let inspector = Http1Inspector::new(stream);
                    connect_track.set_http1_headers(inspector.headers());
                    Inspector::Http1(inspector)
                }
            };

            Ok((stream, Extension(connect_track).layer(service)))
        })
    }
}

/// `Inspector` is an enum that wraps protocol-specific inspectors (such as `Http1Inspector` and
/// `Http2Inspector`) to provide a unified interface for inspecting and tracking different protocol
/// streams. Implements `AsyncRead` and `AsyncWrite` by delegating to the underlying
pub enum Inspector<S> {
    Http1(Http1Inspector<S>),
    Http2(Http2Inspector<S>),
}

impl<I> AsyncRead for Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_read(cx, buf),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_read(cx, buf),
        }
    }
}

impl<I> AsyncWrite for Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_write(cx, buf),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_flush(cx),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Inspector::Http1(inspector) => Pin::new(inspector).poll_shutdown(cx),
            Inspector::Http2(inspector) => Pin::new(inspector).poll_shutdown(cx),
        }
    }
}

pin_project! {
    /// A wrapper over a TLS stream that inspects TLS client hello messages.
    /// It buffers incoming data, parses the client hello message,
    /// and records the parsed client hello for later inspection or analysis.
    /// Does not interfere with normal stream reading or writing.
    pub struct TlsInspector<I> {
        #[pin]
        inner: I,
        client_hello: Option<LazyClientHello>,
    }
}

impl<I> TlsInspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new [`TlsInspector`] instance.
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            client_hello: Some(LazyClientHello::new()),
        }
    }

    /// Extracts and takes ownership of the buffered ClientHello payload,
    /// leaving `None` in its place.
    #[inline]
    #[must_use]
    pub fn client_hello(&mut self) -> Option<LazyClientHello> {
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
        let this = self.project();
        let poll = this.inner.poll_read(cx, buf);

        if let Some(client_hello) = this.client_hello {
            if !client_hello.is_max_record_len() {
                client_hello.extend(&buf.filled()[len..]);
            }
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
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pin_project! {
    /// A wrapper over a TLS stream that inspects HTTP/1.x traffic.
    /// It buffers incoming data, parses HTTP/1 request headers,
    /// and records parsed headers for later inspection or analysis.
    /// Does not interfere with normal stream reading or writing.
    pub struct Http1Inspector<I> {
        #[pin]
        inner: TlsStream<TlsInspector<I>>,
        buf: Vec<u8>,
        headers: Http1Headers,
    }
}

impl<I> Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new [`Http1Inspector`] instance.
    #[inline]
    pub fn new(inner: TlsStream<TlsInspector<I>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            headers: Arc::new(boxcar::Vec::new()),
        }
    }

    /// Get previously parsed HTTP/1 headers
    #[inline]
    pub fn headers(&self) -> Http1Headers {
        self.headers.clone()
    }
}

impl<I> AsyncRead for Http1Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let prev_len = buf.filled().len();
        let poll = this.inner.poll_read(cx, buf);

        // Only process new data
        let new_data = &buf.filled()[prev_len..];
        if !new_data.is_empty() {
            this.buf.extend_from_slice(new_data);
            // Try to parse headers
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            if let Ok(httparse::Status::Complete(_header_len)) = req.parse(this.buf) {
                let headers = this.headers.deref();
                for h in req.headers.iter() {
                    headers.push((
                        Bytes::from(h.name.to_owned()),
                        Bytes::copy_from_slice(h.value),
                    ));
                }
            }
        }

        poll
    }
}

impl<I> AsyncWrite for Http1Inspector<I>
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
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pin_project! {
    /// A wrapper over a TLS stream that inspects HTTP/2 traffic.
    /// It buffers incoming data, parses HTTP/2 frames (including the connection preface),
    /// and records parsed frames for later inspection or analysis.
    /// Does not interfere with normal stream reading
    pub struct Http2Inspector<I> {
        #[pin]
        inner: TlsStream<TlsInspector<I>>,
        buf: Vec<u8>,
        frames: Http2Frame,
    }
}

impl<I> Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new [`Http2Inspector`] instance.
    #[inline]
    pub fn new(inner: TlsStream<TlsInspector<I>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            frames: Arc::new(boxcar::Vec::new()),
        }
    }

    /// Get previously parsed HTTP/2 frames.
    #[inline]
    pub fn frames(&self) -> Http2Frame {
        self.frames.clone()
    }
}

impl<I> AsyncRead for Http2Inspector<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        let len = buf.filled().len();
        let this = self.project();
        let poll = this.inner.poll_read(cx, buf);

        let plen = HTTP2_PREFACE.len();
        let not_http2 = this.buf.len() >= plen && !this.buf.starts_with(HTTP2_PREFACE);
        if !not_http2 {
            this.buf.extend(&buf.filled()[len..]);
            let frames = this.frames.deref();
            while this.buf.len() > plen {
                let last = frames.iter().last().map(|f| f.1);
                if matches!(last, Some(Frame::Headers(_))) {
                    break;
                }
                let (frame_len, frame) = frame::parse(&this.buf[plen..]);
                if frame_len > 0 {
                    this.buf.drain(plen..plen + frame_len);
                    if let Some(frame) = frame {
                        frames.push(frame);
                    }
                } else {
                    break;
                }
            }
        }

        poll
    }
}

impl<I> AsyncWrite for Http2Inspector<I>
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
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// TLS handshake tracking information, which includes the client hello payload.
#[derive(Serialize)]
pub struct TlsTrackInfo {
    ja3: String,
    ja3_hash: String,
    #[serde(rename = "ja4")]
    ja4_fingerprint: String,
    #[serde(rename = "ja4_r")]
    ja4_raw: String,
    #[serde(flatten)]
    client_hello: ClientHello,
}

/// HTTP/1.x request header tracking information.
pub struct Http1TrackInfo(Http1Headers);

/// HTTP/2 tracking information, including Akamai fingerprint and sent frames.
#[derive(Serialize)]
pub struct Http2TrackInfo {
    akamai_fingerprint: String,
    akamai_fingerprint_hash: String,

    #[serde(serialize_with = "serialize_sent_frames")]
    sent_frames: Http2Frame,
}

/// Collects TLS, HTTP/1, and HTTP/2 handshake info for tracking.
#[derive(Clone, Default)]
pub struct ConnectionTrack {
    /// The TLS protocol version that was negotiated for this connection, if any.
    tls_version_negotiated: Option<ProtocolVersion>,
    client_hello: Option<LazyClientHello>,
    http1_headers: Option<Http1Headers>,
    http2_frames: Option<Http2Frame>,
}

/// TrackInfo aggregates tracking details for a single connection,
/// including TLS handshake info, HTTP/1 headers, and HTTP/2 frames.
/// Useful for logging, analysis, or debugging connection
#[derive(Serialize)]
pub struct TrackInfo {
    donate: &'static str,
    address: SocketAddr,
    http_version: String,

    #[serde(serialize_with = "serialize_method")]
    method: Method,

    #[serde(serialize_with = "serialize_user_agent")]
    user_agent: Option<HeaderValue>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsTrackInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http1: Option<Http1TrackInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    http2: Option<Http2TrackInfo>,

    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tcp: Vec<CapturedPacket>,
}

/// Track enum to specify which tracking information to collect.
#[repr(u8)]
pub enum Track {
    All,
    Tls,
    HTTP1,
    HTTP2,
}

// ==== impl Http1TrackInfo ====

impl TlsTrackInfo {
    /// Create a new [`TlsTrackInfo`] instance.
    pub fn new(client_hello: ClientHello) -> TlsTrackInfo {
        let (ja3, ja3_hash) = client_hello.ja3_fingerprint();
        let (ja4_fingerprint, ja4_raw) = client_hello.ja4_fingerprint();

        TlsTrackInfo {
            ja3,
            ja3_hash,
            ja4_fingerprint,
            ja4_raw,
            client_hello,
        }
    }

    /// Set TLS version negotiated during the handshake.
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.client_hello.set_tls_version_negotiated(version);
    }
}

// ==== impl Http1TrackInfo ====

impl Http1TrackInfo {
    /// Create a new [`Http1TrackInfo`] instance.
    pub fn new(headers: Http1Headers) -> Http1TrackInfo {
        Http1TrackInfo(headers)
    }
}

impl Serialize for Http1TrackInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.count()))?;
        for (_, (name, value)) in self.0.iter() {
            let s = format!(
                "{}: {}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(value)
            );
            seq.serialize_element(&s)?;
        }
        seq.end()
    }
}

// ==== impl Http2TrackInfo ====

impl Http2TrackInfo {
    /// Create a new [`Http2TrackInfo`] instance.
    pub fn new(sent_frames: Http2Frame) -> Option<Http2TrackInfo> {
        let akamai = AkamaiFingerprint::from_frames(&sent_frames)?;

        Some(Self {
            akamai_fingerprint: akamai.fingerprint,
            akamai_fingerprint_hash: akamai.hash,
            sent_frames,
        })
    }
}

fn serialize_sent_frames<S>(sent_frames: &Http2Frame, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let vec = sent_frames
        .iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    vec.serialize(serializer)
}

// ==== impl ConnectionTrack ====

impl ConnectionTrack {
    /// Set TLS version negotiated during the handshake.
    #[inline]
    pub fn set_tls_version_negotiated(&mut self, version: Option<ProtocolVersion>) {
        self.tls_version_negotiated = version;
    }

    /// Set TLS client hello
    #[inline]
    pub fn set_client_hello(&mut self, client_hello: Option<LazyClientHello>) {
        self.client_hello = client_hello;
    }

    /// Set HTTP/1 headers
    #[inline]
    pub fn set_http1_headers(&mut self, headers: Http1Headers) {
        self.http1_headers = Some(headers);
    }

    /// Set HTTP/2 frames
    #[inline]
    pub fn set_http2_frames(&mut self, frames: Http2Frame) {
        self.http2_frames = Some(frames);
    }
}

// ==== impl TrackInfo ====

impl TrackInfo {
    const DONATE_URL: &'static str = "Analysis server for TLS and HTTP/1/2/3, developed by 0x676e67: https://github.com/0x676e67/pingly";

    /// Create a new [`TrackInfo`] instance.
    #[inline]
    pub fn new(
        track: Track,
        addr: SocketAddr,
        req: Request<Body>,
        connection_track: ConnectionTrack,
    ) -> TrackInfo {
        #[cfg(target_os = "linux")]
        return Self::new_with_tcp(track, addr, req, connection_track, Vec::new());

        #[cfg(not(target_os = "linux"))]
        {
            let mut tls = connection_track
                .client_hello
                .and_then(LazyClientHello::parse)
                .map(TlsTrackInfo::new);

            if let Some(tls) = tls.as_mut() {
                tls.set_tls_version_negotiated(connection_track.tls_version_negotiated);
            }

            let track_info = TrackInfo {
                donate: Self::DONATE_URL,
                address: addr,
                http_version: format!("{:?}", req.version()),
                method: req.method().clone(),
                user_agent: req.headers().get(USER_AGENT).cloned(),
                tls,
                http1: connection_track.http1_headers.map(Http1TrackInfo::new),
                http2: connection_track.http2_frames.and_then(Http2TrackInfo::new),
            };

            match track {
                Track::All => track_info,
                Track::Tls => TrackInfo {
                    http1: None,
                    http2: None,
                    ..track_info
                },
                Track::HTTP1 => TrackInfo {
                    tls: None,
                    http2: None,
                    ..track_info
                },
                Track::HTTP2 => TrackInfo {
                    tls: None,
                    http1: None,
                    ..track_info
                },
            }
        }
    }

    /// Create a new [`TrackInfo`] instance with TCP data.
    #[inline]
    #[cfg(target_os = "linux")]
    pub fn new_with_tcp(
        track: Track,
        addr: SocketAddr,
        req: Request<Body>,
        connection_track: ConnectionTrack,
        tcp_packets: Vec<CapturedPacket>,
    ) -> TrackInfo {
        let mut tls = connection_track
            .client_hello
            .and_then(LazyClientHello::parse)
            .map(TlsTrackInfo::new);

        if let Some(tls) = tls.as_mut() {
            tls.set_tls_version_negotiated(connection_track.tls_version_negotiated);
        }

        let track_info = TrackInfo {
            donate: Self::DONATE_URL,
            address: addr,
            http_version: format!("{:?}", req.version()),
            method: req.method().clone(),
            user_agent: req.headers().get(USER_AGENT).cloned(),
            tls,
            http1: connection_track.http1_headers.map(Http1TrackInfo::new),
            http2: connection_track.http2_frames.and_then(Http2TrackInfo::new),
            #[cfg(target_os = "linux")]
            tcp: tcp_packets,
        };

        match track {
            Track::All => track_info,
            Track::Tls => TrackInfo {
                http1: None,
                http2: None,
                #[cfg(target_os = "linux")]
                tcp: Vec::new(),
                ..track_info
            },
            Track::HTTP1 => TrackInfo {
                tls: None,
                http2: None,
                #[cfg(target_os = "linux")]
                tcp: Vec::new(),
                ..track_info
            },
            Track::HTTP2 => TrackInfo {
                tls: None,
                http1: None,
                #[cfg(target_os = "linux")]
                tcp: Vec::new(),
                ..track_info
            },
        }
    }
}

fn serialize_user_agent<S>(value: &Option<HeaderValue>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => value
            .to_str()
            .map_err(serde::ser::Error::custom)
            .and_then(|s| serializer.serialize_str(s)),
        None => serializer.serialize_none(),
    }
}

fn serialize_method<S>(method: &Method, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(method.as_str())
}
