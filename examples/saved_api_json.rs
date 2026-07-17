//! Restore protocol models from a bundled Chrome API response.

use std::io;

use pingly::{
    h2::{AkamaiFingerprint, Frame},
    tls::{ClientHello, Ja3Fingerprint, Ja4Fingerprint},
};
use serde::Deserialize;

const CHROME_RESPONSE: &[u8] = include_bytes!("../tests/data/chrome.json");

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

impl TlsResponse {
    fn verified_fingerprints(&self) -> io::Result<(Ja3Fingerprint, Ja4Fingerprint)> {
        let ja3 = self.client_hello.ja3();
        let ja4 = self.client_hello.ja4();

        let matches_saved = ja3.raw.as_ref() == self.ja3.as_ref()
            && ja3.hash.as_ref() == self.ja3_hash.as_ref()
            && ja4.fingerprint.as_ref() == self.ja4_fingerprint.as_ref()
            && ja4.raw.as_ref() == self.ja4_raw.as_ref();

        if !matches_saved {
            return Err(invalid_data(
                "the recomputed TLS fingerprints do not match the saved response",
            ));
        }

        Ok((ja3, ja4))
    }
}

#[derive(Deserialize)]
struct Http2Response {
    akamai_fingerprint: Box<str>,

    akamai_fingerprint_hash: Box<str>,

    sent_frames: Vec<Frame>,
}

impl Http2Response {
    fn verified_fingerprint(&self) -> io::Result<AkamaiFingerprint> {
        let fingerprint = AkamaiFingerprint::from_frames(&self.sent_frames)
            .ok_or_else(|| invalid_data("the HTTP/2 response contains no frames"))?;

        if fingerprint.fingerprint.as_ref() != self.akamai_fingerprint.as_ref()
            || fingerprint.hash.as_ref() != self.akamai_fingerprint_hash.as_ref()
        {
            return Err(invalid_data(format!(
                "saved Akamai fingerprint {} ({}) differs from recomputed {} ({})",
                self.akamai_fingerprint,
                self.akamai_fingerprint_hash,
                fingerprint.fingerprint,
                fingerprint.hash,
            )));
        }

        Ok(fingerprint)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response: ApiResponse = serde_json::from_slice(CHROME_RESPONSE)?;
    let (ja3, ja4) = response.tls.verified_fingerprints()?;
    let akamai = response.http2.verified_fingerprint()?;

    println!("TLS JA3: {} ({})", ja3.raw, ja3.hash);
    println!("TLS JA4: {}", ja4.fingerprint);
    println!("HTTP/2 Akamai: {} ({})", akamai.fingerprint, akamai.hash);
    println!("HTTP/2 frames: {}", response.http2.sent_frames.len());

    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
