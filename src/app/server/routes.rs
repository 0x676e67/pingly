//! Request handlers for the protocol analysis endpoints.

#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{net::SocketAddr, sync::LazyLock};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
    Extension, Router,
};
use axum_extra::response::ErasedJson;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::tracker::info::{ConnectionTrack, Track, TrackInfo};
#[cfg(target_os = "linux")]
use crate::tcp::TcpCaptureTrack;
use crate::{error::Error, Result};

const INDEX_PATH: &str = "/";
const ALL_PATH: &str = "/api/all";
const TLS_PATH: &str = "/api/tls";
const HTTP1_PATH: &str = "/api/http1";
const HTTP2_PATH: &str = "/api/http2";
const TCP_PATH: &str = "/api/tcp";

const UI_TEMPLATE: &str = include_str!("ui/index.html");
const UI_SCRIPT: &str = include_str!("ui/app.js");
const UI_SCRIPT_MARKER: &str = "<!-- PINGLY_SCRIPT -->";
const UI_ROUTES_MARKER: &str = "/* PINGLY_ROUTES */ []";

#[derive(Serialize)]
struct PublicRoute {
    /// HTTP method shown in the route directory.
    method: &'static str,

    /// Absolute path registered by the server.
    path: &'static str,

    /// Short description shown in the interface.
    purpose: &'static str,

    /// Runtime conditions required for the route.
    availability: &'static str,
}

const PUBLIC_ROUTES: &[PublicRoute] = &[
    PublicRoute {
        method: "GET",
        path: INDEX_PATH,
        purpose: "Protocol inspector",
        availability: "Always",
    },
    PublicRoute {
        method: "ANY",
        path: ALL_PATH,
        purpose: "Complete analysis",
        availability: "Always",
    },
    PublicRoute {
        method: "ANY",
        path: TLS_PATH,
        purpose: "TLS analysis",
        availability: "Always",
    },
    PublicRoute {
        method: "ANY",
        path: HTTP1_PATH,
        purpose: "HTTP/1 analysis",
        availability: "Always",
    },
    PublicRoute {
        method: "ANY",
        path: HTTP2_PATH,
        purpose: "HTTP/2 analysis",
        availability: "Always",
    },
    PublicRoute {
        method: "ANY",
        path: TCP_PATH,
        purpose: "TCP packet capture",
        availability: "Linux + capture",
    },
];

static UI_DOCUMENT: LazyLock<Box<str>> = LazyLock::new(build_ui_document);

// Compression can change the transfer bytes without changing the UI document, so the
// validator is weak across content codings.
// https://www.rfc-editor.org/rfc/rfc9110.html#name-entity-tag
static UI_ETAG_TEXT: LazyLock<Box<str>> = LazyLock::new(|| {
    let digest = Sha256::digest(UI_DOCUMENT.as_bytes());
    format!("W/\"{}\"", hex::encode(digest)).into_boxed_str()
});

static UI_ETAG_VALUE: LazyLock<HeaderValue> = LazyLock::new(|| {
    HeaderValue::from_str(UI_ETAG_TEXT.as_ref())
        .unwrap_or_else(|_| HeaderValue::from_static("W/\"pingly-ui\""))
});

/// Builds the public routes and enables optional platform routes.
pub(crate) fn router(#[cfg(target_os = "linux")] tcp_capture: Option<&TcpCaptureTrack>) -> Router {
    let router = Router::new()
        .route(INDEX_PATH, get(index))
        .route(ALL_PATH, any(track))
        .route(TLS_PATH, any(tls_track))
        .route(HTTP1_PATH, any(http1_track))
        .route(HTTP2_PATH, any(http2_track));

    #[cfg(target_os = "linux")]
    let router = if let Some(capture) = tcp_capture {
        router
            .route(TCP_PATH, any(tcp_track))
            .layer(Extension(capture.clone()))
    } else {
        router
    };

    router
}

fn build_ui_document() -> Box<str> {
    let routes = serde_json::to_string(PUBLIC_ROUTES).unwrap_or_else(|_| "[]".to_owned());
    let Some((script_head, script_tail)) = UI_SCRIPT.split_once(UI_ROUTES_MARKER) else {
        return UI_TEMPLATE.into();
    };

    let mut script = String::with_capacity(UI_SCRIPT.len() + routes.len());
    script.push_str(script_head);
    script.push_str(&routes);
    script.push_str(script_tail);

    let Some((body, tail)) = UI_TEMPLATE.split_once(UI_SCRIPT_MARKER) else {
        return UI_TEMPLATE.into();
    };

    let mut document = String::with_capacity(UI_TEMPLATE.len() + script.len() + 17);
    document.push_str(body);
    document.push_str("<script>");
    document.push_str(&script);
    document.push_str("</script>");
    document.push_str(tail);
    document.into_boxed_str()
}

fn matches_ui_etag(headers: &HeaderMap) -> bool {
    for value in headers.get_all(header::IF_NONE_MATCH) {
        let Ok(value) = value.to_str() else {
            continue;
        };

        // GET and HEAD use weak comparison for If-None-Match validators.
        // https://www.rfc-editor.org/rfc/rfc9110.html#name-if-none-match
        if value.split(',').any(|candidate| {
            let candidate = candidate.trim();
            let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
            let current = UI_ETAG_TEXT
                .strip_prefix("W/")
                .unwrap_or(UI_ETAG_TEXT.as_ref());

            candidate == "*" || candidate == current
        }) {
            return true;
        }
    }

    false
}

/// Serves the protocol analysis interface as a single cache-revalidated document.
pub(crate) async fn index(request_headers: HeaderMap) -> Response {
    let mut response = if matches_ui_etag(&request_headers) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let document: &'static str = UI_DOCUMENT.as_ref();
        Html(document).into_response()
    };

    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    response_headers.insert(header::ETAG, UI_ETAG_VALUE.clone());
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );

    response
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::warn!(%self, "server track error");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

fn spawn_blocking_analysis<F, R>(analysis: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let span = tracing::Span::current();

    // Blocking tasks do not automatically inherit the request's current tracing span.
    tokio::task::spawn_blocking(move || span.in_scope(analysis))
}

#[inline]
pub(crate) async fn track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    #[cfg(target_os = "linux")] tcp_capture: Option<Extension<TcpCaptureTrack>>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    #[cfg(target_os = "linux")]
    let tcp_packets = if let Some(Extension(capture)) = tcp_capture {
        // Give libpcap a moment to publish packets from this connection before reading them.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_ip = addr.ip().to_string();
        let client_port = addr.port();
        let packets = capture.get_packets_for_client(&client_ip, client_port);
        capture.clear_packets_for_client(&client_ip, client_port);
        packets
    } else {
        Vec::new()
    };

    #[cfg(target_os = "linux")]
    {
        spawn_blocking_analysis(move || {
            TrackInfo::new_with_tcp(Track::All, addr, req, track, tcp_packets)
        })
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
    }

    #[cfg(not(target_os = "linux"))]
    {
        spawn_blocking_analysis(move || TrackInfo::new(Track::All, addr, req, track))
            .await
            .map(ErasedJson::pretty)
            .map_err(Error::from)
    }
}

#[inline]
pub(crate) async fn tls_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::Tls, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub(crate) async fn http1_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::HTTP1, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
pub(crate) async fn http2_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(track): Extension<ConnectionTrack>,
    req: Request<Body>,
) -> Result<ErasedJson> {
    spawn_blocking_analysis(move || TrackInfo::new(Track::HTTP2, addr, req, track))
        .await
        .map(ErasedJson::pretty)
        .map_err(Error::from)
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) async fn tcp_track(
    Extension(ConnectInfo(addr)): Extension<ConnectInfo<SocketAddr>>,
    Extension(capture): Extension<TcpCaptureTrack>,
) -> Result<ErasedJson> {
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_ip = addr.ip().to_string();
    let client_port = addr.port();
    let packets = capture.get_packets_for_client(&client_ip, client_port);
    capture.clear_packets_for_client(&client_ip, client_port);

    Ok(ErasedJson::pretty(&packets))
}
#[cfg(test)]
mod tests {
    use axum::{
        body::to_bytes,
        http::{header, HeaderMap, HeaderValue, StatusCode},
    };

    use super::{
        index, PUBLIC_ROUTES, UI_DOCUMENT, UI_ETAG_TEXT, UI_ROUTES_MARKER, UI_SCRIPT,
        UI_SCRIPT_MARKER, UI_TEMPLATE,
    };

    #[test]
    fn ui_document_uses_verified_cdn_assets_and_embeds_its_script() {
        assert_eq!(UI_DOCUMENT.matches("@primer/primitives@11.7.1").count(), 2);
        assert!(UI_DOCUMENT.contains("@tabler/core@1.4.0"));
        assert!(UI_DOCUMENT.contains("@tabler/icons-webfont@3.44.0"));
        assert!(UI_DOCUMENT
            .contains("sha384-tyGOUiC6/O2IZry7gBhZ2iuyYIp+dgaAjQVXkX8ZUSuP7D8KoMhPKYCeqKY8lykt"));
        assert!(UI_DOCUMENT
            .contains("sha384-Dr6x7dVhkHJRYxojTVMY8ZZt494t/y5kZYqWFzpiIz+7hZMNw+4N3O1qG+yFGtHD"));
        assert!(UI_DOCUMENT
            .contains("sha384-mooE85Luwgx+AyykX7e90VcN8/QCFTSIwPuHLmvcsLVoA0en7lKYb9XlOzn5G2co"));
        assert!(UI_DOCUMENT.contains("crossorigin=\"anonymous\""));
        assert!(!UI_DOCUMENT.contains("<style>"));
        assert!(UI_DOCUMENT.contains("<script>\"use strict\";"));
        assert!(UI_DOCUMENT.contains("id=\"analysis-workspace\""));
        assert!(!UI_DOCUMENT.contains("id=\"import-button\""));
        assert!(!UI_DOCUMENT.contains("id=\"file-input\""));
        assert!(!UI_SCRIPT.contains("importJsonFile"));
        assert!(!UI_DOCUMENT.contains(UI_SCRIPT_MARKER));
        assert!(!UI_DOCUMENT.contains(UI_ROUTES_MARKER));
        assert!(!UI_SCRIPT.to_ascii_lowercase().contains("</script"));
    }

    #[test]
    fn theme_bootstrap_runs_before_external_stylesheets() {
        let theme = UI_TEMPLATE
            .find("prefers-color-scheme: dark")
            .expect("theme bootstrap should be present");
        let stylesheet = UI_TEMPLATE
            .find("@tabler/core@1.4.0")
            .expect("Tabler stylesheet should be present");

        assert!(theme < stylesheet);
        assert!(UI_TEMPLATE.contains("root.dataset.darkTheme = \"dark_dimmed\""));
        assert!(UI_TEMPLATE.contains("root.dataset.lightTheme = \"light\""));
        assert!(UI_TEMPLATE.contains("window.pinglyPrimerTheme = Object.freeze"));
        assert!(UI_TEMPLATE.contains("window.applyPinglyPrimerTheme = function"));
        assert!(UI_SCRIPT.contains("function stylePrimerButton"));
        assert!(UI_SCRIPT.contains("button-primary-bgColor-rest"));
        assert!(UI_TEMPLATE.contains("\"--tblr-code-bg\": \"var(--bgColor-accent-muted)\""));
        assert!(UI_TEMPLATE.contains("\"--tblr-code-color\": \"var(--fgColor-default)\""));
        assert!(UI_TEMPLATE.contains("\"--tblr-primary\": \"var(--button-primary-bgColor-rest)\""));
        assert!(UI_TEMPLATE.contains("bg-body-tertiary text-body border fw-bold"));
        assert!(UI_TEMPLATE.contains("fill='%23212830'"));
        assert!(!UI_TEMPLATE.contains("fill='%230066eb'"));

        for tone in ["blue", "orange", "green", "purple"] {
            let class = format!("avatar avatar-sm bg-{tone}-lt text-{tone}");
            assert!(UI_TEMPLATE.contains(&class));
        }
    }

    #[test]
    fn fingerprint_layout_uses_shared_responsive_components() {
        assert!(UI_SCRIPT.contains("function createFingerprintSection"));
        assert!(UI_SCRIPT.contains("col-12 col-md-6 col-xl-4"));
        assert!(UI_SCRIPT.contains("Source string"));
        assert!(UI_SCRIPT.contains("badge bg-blue-lt text-blue rounded-pill"));
        assert!(UI_SCRIPT.contains("btn btn-outline-secondary btn-sm p-2 flex-shrink-0"));
        assert!(!UI_SCRIPT.contains("d-flex flex-column flex-xl-row gap-3 mb-4"));
        assert!(UI_TEMPLATE.contains("col-12 col-sm-auto ms-sm-auto"));
    }

    #[test]
    fn desktop_sidebar_tracks_the_sticky_header() {
        assert!(UI_TEMPLATE.contains("id=\"app-header\""));
        assert!(UI_TEMPLATE.contains("id=\"analysis-sidebar\""));
        assert!(UI_TEMPLATE.contains("id=\"analysis-nav\""));
        assert!(UI_SCRIPT.contains("function syncStickySidebar"));
        assert!(UI_SCRIPT.contains("classList.toggle(\"position-sticky\""));
        assert!(UI_TEMPLATE.contains("<div class=\"d-flex flex-column w-100\">"));
        assert!(!UI_TEMPLATE.contains("align-self-start overflow-y-auto"));
        assert!(UI_SCRIPT.contains("(min-width: 768px)"));
        assert!(UI_SCRIPT.contains("desktop ? \"vertical\" : \"horizontal\""));
    }

    #[test]
    fn json_panel_switches_between_public_analysis_routes() {
        assert!(UI_TEMPLATE.contains("id=\"json-route-options\""));
        assert!(UI_TEMPLATE.contains("id=\"json-route-label\""));
        assert!(UI_TEMPLATE.contains("nav nav-pills flex-nowrap"));
        assert!(UI_SCRIPT.contains("const DEFAULT_JSON_ROUTE = \"/api/all\""));
        assert!(UI_SCRIPT.contains("function renderJsonRouteOptions"));
        assert!(UI_SCRIPT.contains("async function selectJsonRoute"));
        assert!(UI_SCRIPT.contains("state.jsonData"));
    }

    #[test]
    fn ui_document_injects_public_routes_from_rust_metadata() {
        assert!(UI_SCRIPT.contains(UI_ROUTES_MARKER));

        for route in PUBLIC_ROUTES {
            let path = format!("\"path\":\"{}\"", route.path);
            assert!(UI_DOCUMENT.contains(&path));
        }

        assert!(!UI_DOCUMENT.contains("API response"));
        assert!(!UI_DOCUMENT.contains("/.well-known/acme-challenge"));
    }

    #[tokio::test]
    async fn ui_document_revalidates_with_etag() {
        let response = index(HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("public, no-cache"))
        );

        let etag = response
            .headers()
            .get(header::ETAG)
            .expect("UI response should have an ETag")
            .clone();
        assert_eq!(
            etag.to_str().expect("ETag should be ASCII"),
            UI_ETAG_TEXT.as_ref()
        );
        assert!(!to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("UI body should be readable")
            .is_empty());

        let mut request_headers = HeaderMap::new();
        request_headers.insert(header::IF_NONE_MATCH, etag);
        let response = index(request_headers).await;

        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(to_bytes(response.into_body(), 1)
            .await
            .expect("304 body should be readable")
            .is_empty());
    }

    #[tokio::test]
    async fn ui_document_accepts_strong_equivalent_etag_validators() {
        let validator = HeaderValue::from_str(
            UI_ETAG_TEXT
                .strip_prefix("W/")
                .expect("UI ETag should be weak"),
        )
        .expect("strong ETag should be valid");
        let mut request_headers = HeaderMap::new();
        request_headers.insert(header::IF_NONE_MATCH, validator);

        assert_eq!(
            index(request_headers).await.status(),
            StatusCode::NOT_MODIFIED
        );
    }
}
