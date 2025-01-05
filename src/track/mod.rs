mod accept;
mod info;
mod inspector;

pub use self::accept::TrackAcceptor;
pub use self::inspector::{Http2Frame, Http2Inspector, TlsInspector};
pub use info::{Http2TrackInfo, TlsTrackInfo};
use inspector::ClientHello;

/// ConnectTrack
/// Wrapper for tls and http2 settings
#[derive(Clone)]
pub struct ConnectTrack {
    client_hello: Option<ClientHello>,
    http2_frames: Http2Frame,
}

impl ConnectTrack {
    pub fn new(client_hello: Option<ClientHello>, http2_frames: Http2Frame) -> Self {
        Self {
            client_hello,
            http2_frames,
        }
    }

    pub fn into_track_info(self) -> (Option<TlsTrackInfo>, Option<Http2TrackInfo>) {
        (
            self.client_hello.map(TlsTrackInfo::new),
            Http2TrackInfo::new(self.http2_frames),
        )
    }

    pub fn into_http2_track_info(self) -> Option<Http2TrackInfo> {
        Http2TrackInfo::new(self.http2_frames)
    }

    pub fn into_tls_track_info(self) -> Option<TlsTrackInfo> {
        self.client_hello.map(TlsTrackInfo::new)
    }
}
