pub mod accept;
pub mod info;
mod inspector;

use info::{Http2TrackInfo, TlsTrackInfo};
use inspector::{ClientHello, Http1Headers, Http2Frame, Http2Inspector, TlsInspector};

use crate::track::info::Http1TrackInfo;

/// ConnectionTrack
/// Collects TLS, HTTP/1, and HTTP/2 handshake info for tracking.
#[derive(Clone, Default)]
pub struct ConnectionTrack {
    client_hello: Option<ClientHello>,
    http1_headers: Option<Http1Headers>,
    http2_frames: Option<Http2Frame>,
}

impl ConnectionTrack {
    /// Set TLS client hello
    #[inline]
    pub fn set_client_hello(&mut self, client_hello: Option<ClientHello>) {
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

    /// Convert to all track info tuple
    #[inline]
    pub fn into_track_info(
        self,
    ) -> (
        Option<TlsTrackInfo>,
        Option<Http1TrackInfo>,
        Option<Http2TrackInfo>,
    ) {
        (
            self.client_hello.map(TlsTrackInfo::new),
            self.http1_headers.map(Http1TrackInfo::new),
            self.http2_frames.and_then(Http2TrackInfo::new),
        )
    }

    /// Convert to HTTP/1 track info
    #[inline]
    pub fn into_http1_headers(self) -> Option<Http1TrackInfo> {
        self.http1_headers.map(Http1TrackInfo::new)
    }

    /// Convert to HTTP/2 track info
    #[inline]
    pub fn into_http2_track_info(self) -> Option<Http2TrackInfo> {
        self.http2_frames.and_then(Http2TrackInfo::new)
    }

    /// Convert to TLS track info
    #[inline]
    pub fn into_tls_track_info(self) -> Option<TlsTrackInfo> {
        self.client_hello.map(TlsTrackInfo::new)
    }
}
