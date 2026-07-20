use pingly::{
    h2::{frame::StreamDependency, AkamaiFingerprint, Frame},
    h3::{HeadersFrame, Http3Fingerprint, SettingsFrame},
    tls::ClientHello,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

struct BrowserSample {
    name: &'static str,

    response: &'static [u8],

    priority: StreamDependency,
}

struct Http3BrowserSample {
    name: &'static str,

    response: &'static [u8],
}

const BROWSER_SAMPLES: &[BrowserSample] = &[
    BrowserSample {
        name: "Chrome",
        response: include_bytes!("data/chrome.json"),
        priority: StreamDependency {
            weight: 256,
            depends_on: 0,
            exclusive: 1,
        },
    },
    BrowserSample {
        name: "Firefox",
        response: include_bytes!("data/firefox.json"),
        priority: StreamDependency {
            weight: 42,
            depends_on: 0,
            exclusive: 0,
        },
    },
];

const HTTP3_BROWSER_SAMPLES: &[Http3BrowserSample] = &[
    Http3BrowserSample {
        name: "Chrome",
        response: include_bytes!("data/h3_chrome.json"),
    },
    Http3BrowserSample {
        name: "Firefox",
        response: include_bytes!("data/h3_firefox.json"),
    },
];

#[derive(Deserialize)]
struct ApiResponse {
    tls: TlsResponse,

    http2: Http2Response,
}

#[derive(Deserialize)]
struct Http3ApiResponse {
    tls: TlsResponse,

    http3: Http3Response,
}

#[derive(Deserialize)]
struct TlsResponse {
    ja3: Box<str>,

    ja3_hash: Box<str>,

    #[serde(rename = "ja4")]
    ja4_fingerprint: Box<str>,

    #[serde(rename = "ja4_r")]
    ja4_raw: Box<str>,

    #[serde(flatten)]
    client_hello: ClientHello,
}

#[derive(Deserialize)]
struct Http2Response {
    akamai_fingerprint: Box<str>,

    akamai_fingerprint_hash: Box<str>,

    sent_frames: Vec<Frame>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Http3Response {
    #[serde(flatten)]
    fingerprint: Http3Fingerprint,

    settings: SettingsFrame,

    headers: HeadersFrame,
}

#[test]
fn browser_samples_roundtrip_tls_and_http2_models() {
    for sample in BROWSER_SAMPLES {
        assert_browser_sample(sample);
    }
}

#[test]
fn browser_samples_roundtrip_tls_and_http3_models() {
    for sample in HTTP3_BROWSER_SAMPLES {
        assert_http3_browser_sample(sample);
    }
}

fn assert_browser_sample(sample: &BrowserSample) {
    let response: ApiResponse = serde_json::from_slice(sample.response).unwrap();

    assert_tls(sample.name, &response.tls);
    assert_http2(sample, &response.http2);
}

fn assert_http3_browser_sample(sample: &Http3BrowserSample) {
    let response: Http3ApiResponse = serde_json::from_slice(sample.response).unwrap();

    assert_tls(sample.name, &response.tls);
    assert!(
        response.tls.ja4_fingerprint.starts_with('q'),
        "{} HTTP/3 JA4 transport marker",
        sample.name
    );
    assert!(
        response.tls.ja4_raw.starts_with('q'),
        "{} HTTP/3 JA4_r transport marker",
        sample.name
    );

    assert!(
        response
            .tls
            .client_hello
            .quic_transport_parameters()
            .is_some(),
        "{} HTTP/3 QUIC transport parameters",
        sample.name
    );
    let calculated =
        Http3Fingerprint::from_frames(&response.http3.settings, &response.http3.headers);

    assert_eq!(
        calculated, response.http3.fingerprint,
        "{} HTTP/3 fingerprint",
        sample.name
    );

    let restored: Http3Response = json_roundtrip(&response.http3);
    assert_eq!(
        restored, response.http3,
        "{} HTTP/3 JSON roundtrip",
        sample.name
    );
}

fn assert_tls(browser: &str, tls: &TlsResponse) {
    let ja3 = tls.client_hello.ja3();
    let ja4 = tls.client_hello.ja4();

    assert_eq!(ja3.raw.as_ref(), tls.ja3.as_ref(), "{browser} JA3 source");
    assert_eq!(
        ja3.hash.as_ref(),
        tls.ja3_hash.as_ref(),
        "{browser} JA3 hash"
    );
    assert_eq!(
        ja4.fingerprint.as_ref(),
        tls.ja4_fingerprint.as_ref(),
        "{browser} JA4 fingerprint"
    );
    assert_eq!(
        ja4.raw.as_ref(),
        tls.ja4_raw.as_ref(),
        "{browser} JA4 source"
    );

    let restored: ClientHello = json_roundtrip(&tls.client_hello);

    assert_eq!(
        restored, tls.client_hello,
        "{browser} ClientHello JSON roundtrip"
    );
    assert_eq!(restored.ja3(), ja3, "{browser} restored JA3");
    assert_eq!(restored.ja4(), ja4, "{browser} restored JA4");
}

fn assert_http2(sample: &BrowserSample, http2: &Http2Response) {
    let [Frame::Settings(_), Frame::WindowUpdate(_), Frame::Headers(headers)] =
        http2.sent_frames.as_slice()
    else {
        panic!(
            "{} sample should contain SETTINGS, WINDOW_UPDATE, and HEADERS frames",
            sample.name
        );
    };

    assert_eq!(
        headers.priority.as_ref(),
        Some(&sample.priority),
        "{} HEADERS priority",
        sample.name
    );

    let fingerprint = AkamaiFingerprint::from_frames(&http2.sent_frames).unwrap();
    assert_eq!(
        fingerprint.fingerprint.as_ref(),
        http2.akamai_fingerprint.as_ref(),
        "{} Akamai fingerprint",
        sample.name
    );
    assert_eq!(
        fingerprint.hash.as_ref(),
        http2.akamai_fingerprint_hash.as_ref(),
        "{} Akamai hash",
        sample.name
    );

    let restored: Vec<Frame> = json_roundtrip(&http2.sent_frames);

    assert_eq!(
        restored, http2.sent_frames,
        "{} frame JSON roundtrip",
        sample.name
    );
    assert_eq!(
        AkamaiFingerprint::from_frames(&restored),
        Some(fingerprint),
        "{} restored Akamai fingerprint",
        sample.name
    );
}

fn json_roundtrip<T>(value: &T) -> T
where
    T: DeserializeOwned + Serialize,
{
    let json = serde_json::to_vec(value).unwrap();
    serde_json::from_slice(&json).unwrap()
}
