# pingly

[![CI](https://github.com/0x676e67/pingly/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/pingly/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/pingly)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/pingly.svg?logo=rust)](https://crates.io/crates/pingly)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

**Pingly** is a TLS, HTTP/1, and HTTP/2 analysis server and Rust library. It reveals request
fingerprints (JA3/JA4 and Akamai HTTP/2), header order, HTTP/2 frames, and other wire details.

## Run the server

```console
cargo run -- run --bind 127.0.0.1:8181
```

The server uses TLS by default and generates a self-signed certificate when no certificate and key
are supplied. The analysis endpoints are:

- `/api/all`
- `/api/tls`
- `/api/http1`
- `/api/http2`
- `/api/tcp` on Linux when packet capture is enabled

## Use the library

```toml
[dependencies]
pingly = { version = "0.1", default-features = false }
serde_json = "1"
```
Disabling default features keeps the library dependency focused on protocol parsing. The default
`server` and `mimalloc` features remain enabled for `cargo run` and `cargo install`.


### TLS ClientHello

Parse a complete ClientHello capture, including a handshake fragmented across TLS records, and
retain enough source data to recompute JA3 and JA4 after a JSON roundtrip:

```rust,no_run
use pingly::proto::tls::ClientHello;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let record = std::fs::read("client-hello.bin")?;
    let hello = ClientHello::parse(&record)?;

    let ja3 = hello.ja3();
    println!("JA3: {} ({})", ja3.raw, ja3.hash);
    println!("JA4: {}", hello.ja4().fingerprint);

    let json = serde_json::to_vec_pretty(&hello)?;
    let restored: ClientHello = serde_json::from_slice(&json)?;
    assert_eq!(restored.ja4(), hello.ja4());
    Ok(())
}
```

For TCP chunks, use `ClientHelloBuffer::extend` and `try_parse`. `Ok(None)` means a TLS record
or the fragmented handshake is still incomplete; malformed complete captures return
`ClientHelloParseError`. The default buffer retains at most 64 KiB and stops accepting bytes once
the ClientHello completes; `with_capture_limit` customizes that bound.

### HTTP/2

Use `parse_connection` for a finite capture that includes the HTTP/2 client connection preface, or
`parse_frames` when the bytes begin directly at a frame header:

```rust,no_run
use pingly::proto::http2::{parse_connection, AkamaiFingerprint};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("http2-connection.bin")?;
    let frames = parse_connection(&bytes)?;
    let fingerprint = AkamaiFingerprint::from_frames(&frames);

    let json = serde_json::to_vec_pretty(&frames)?;
    let restored: Vec<pingly::proto::http2::Frame> =
        serde_json::from_slice(&json)?;
    assert_eq!(AkamaiFingerprint::from_frames(&restored), fingerprint);
    Ok(())
}
```

`Http2Parser` is the incremental alternative for arbitrary TCP chunks:

```rust
use pingly::proto::http2::Http2Parser;

let mut parser = Http2Parser::new();
let mut frames = Vec::new();

for chunk in [b"PRI * HTTP/2.0\r\n".as_slice(), b"\r\nSM\r\n\r\n".as_slice()] {
    parser.push_into(chunk, &mut frames).unwrap();
}

parser.finish().unwrap();
assert!(frames.is_empty());
```

## Run the examples

The standalone examples use only the protocol library and work with default features disabled:

    cargo run --example tls_client_hello --no-default-features -- client-hello.bin
    cargo run --example http2_connection --no-default-features -- http2-connection.bin
    cargo run --example saved_api_json --no-default-features

tls_client_hello accepts a capture beginning with a TLS ClientHello handshake and demonstrates
incremental record reassembly, JA3/JA4 calculation, and JSON roundtripping.

http2_connection accepts a client byte stream beginning with the HTTP/2 connection preface and
demonstrates incremental frame parsing, Akamai fingerprinting, and JSON roundtripping.

saved_api_json restores the bundled Chrome response from tests/data/chrome.json and checks that
its TLS and HTTP/2 fingerprints still match the serialized values.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](./LICENSE) or http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.
