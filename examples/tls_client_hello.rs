//! Parse a TLS ClientHello from captured record bytes.

use std::{env, fs, io, path::PathBuf};

use pingly::proto::tls::{ClientHello, ClientHelloBuffer};

const USAGE: &str =
    "usage: cargo run --example tls_client_hello --no-default-features -- <client-hello.bin>";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(input_path()?)?;

    let mut buffer = ClientHelloBuffer::new();
    let mut client_hello = None;

    // A TCP reader can split the record at any byte. Fixed-size chunks make the
    // example exercise the same incremental API without requiring a live socket.
    for chunk in bytes.chunks(256) {
        let accepted = buffer.extend(chunk);

        if let Some(parsed) = buffer.try_parse()? {
            client_hello = Some(parsed);
            break;
        }

        if accepted != chunk.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the ClientHello exceeds the maximum supported TLS record size",
            )
            .into());
        }
    }

    let client_hello = client_hello.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the capture ends before a complete ClientHello record",
        )
    })?;

    let ja3 = client_hello.ja3();
    let ja4 = client_hello.ja4();
    let json = serde_json::to_string_pretty(&client_hello)?;
    let restored: ClientHello = serde_json::from_str(&json)?;

    if restored.ja3() != ja3 || restored.ja4() != ja4 {
        return Err(io::Error::other("fingerprints changed after JSON roundtrip").into());
    }

    println!("JA3 raw: {}", ja3.raw);
    println!("JA3 hash: {}", ja3.hash);
    println!("JA4 raw: {}", ja4.raw);
    println!("JA4 fingerprint: {}", ja4.fingerprint);
    println!("\nClientHello JSON:\n{json}");

    Ok(())
}

fn input_path() -> Result<PathBuf, io::Error> {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USAGE))
}
