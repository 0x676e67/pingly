//! Parse a captured HTTP/2 client connection and calculate its fingerprints.
//!
//! The input begins with the client connection preface from
//! [RFC 9113, Section 3.4](https://www.rfc-editor.org/rfc/rfc9113#section-3.4).

use std::{env, fs, io, path::PathBuf};

use pingly::h2::{AkamaiFingerprint, Frame, Http2Fingerprint, Http2Parser};

const USAGE: &str = "usage: cargo run --example http2_connection -- <http2-connection.bin>";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(input_path()?)?;

    let mut parser = Http2Parser::new();
    let mut frames = Vec::new();

    for chunk in bytes.chunks(251) {
        parser.push_into(chunk, &mut frames)?;
    }
    parser.finish()?;

    let akamai = AkamaiFingerprint::from_frames(&frames).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the connection contains no HTTP/2 frames",
        )
    })?;
    let fingerprint = Http2Fingerprint::from_frames(&frames).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the connection contains no HTTP/2 HEADERS frame",
        )
    })?;

    let json = serde_json::to_string_pretty(&frames)?;
    let restored: Vec<Frame> = serde_json::from_str(&json)?;
    let restored_akamai = AkamaiFingerprint::from_frames(&restored).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the restored connection contains no HTTP/2 frames",
        )
    })?;
    let restored_fingerprint = Http2Fingerprint::from_frames(&restored).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the restored connection contains no HTTP/2 HEADERS frame",
        )
    })?;

    if restored_akamai != akamai || restored_fingerprint != fingerprint {
        return Err(io::Error::other("fingerprints changed after JSON roundtrip").into());
    }

    println!("Frames: {}", frames.len());
    println!("HTTP/2 fingerprint: {}", fingerprint.h2_text);
    println!("HTTP/2 hash: {}", fingerprint.h2_text_hash);
    println!("Akamai fingerprint: {}", akamai.fingerprint);
    println!("Akamai hash: {}", akamai.hash);
    println!("\nHTTP/2 frames JSON:\n{json}");

    Ok(())
}

fn input_path() -> Result<PathBuf, io::Error> {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USAGE))
}
