use pingly::proto::{
    http2::{frame::StreamDependency, AkamaiFingerprint, Frame},
    tls::ClientHello,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

struct BrowserSample {
    name: &'static str,

    response: &'static [u8],

    priority: StreamDependency,
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

#[derive(Deserialize)]
struct ApiResponse {
    tls: TlsResponse,

    http2: Http2Response,
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

#[test]
fn browser_samples_roundtrip_tls_and_http2_models() {
    for sample in BROWSER_SAMPLES {
        assert_browser_sample(sample);
    }
}

fn assert_browser_sample(sample: &BrowserSample) {
    let response: ApiResponse = serde_json::from_slice(sample.response).unwrap();

    assert_tls(sample.name, &response.tls);
    assert_http2(sample, &response.http2);
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
