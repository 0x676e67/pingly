# pingly

[![CI](https://github.com/0x676e67/pingly/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/pingly/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/pingly)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/pingly.svg?logo=rust)](https://crates.io/crates/pingly)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

**Pingly** is a Rust server and library for inspecting TLS and HTTP traffic.

## Features

- JA3, JA4, and Akamai HTTP/2 fingerprints
- HTTP/1 headers and HTTP/2 frames
- Incremental parsing and Serde support

## Server

```console
cargo run -- run --bind 127.0.0.1:8181
```

TLS is enabled by default. A self-signed certificate is generated when no certificate and key are
provided.

- `/api/all`
- `/api/tls`
- `/api/http1`
- `/api/http2`
- `/api/tcp` on Linux when packet capture is enabled

## Example

Add Pingly without the server features:

```toml
[dependencies]
pingly = { version = "0.1", default-features = false }
```

And then parse a captured TLS ClientHello:

```rust
use pingly::tls::ClientHello;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The capture may contain a ClientHello split across several TLS records.
    let bytes = std::fs::read("client-hello.bin")?;
    let hello = ClientHello::parse(&bytes)?;

    println!("JA3: {}", hello.ja3().hash);
    println!("JA4: {}", hello.ja4().fingerprint);
    Ok(())
}
```

See [examples](./examples) for incremental parsing, HTTP/2 fingerprints, and saved JSON.

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](./LICENSE) or http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.
