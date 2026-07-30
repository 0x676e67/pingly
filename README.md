# pingly

[![CI](https://github.com/0x676e67/pingly/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/pingly/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/pingly)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/pingly.svg?logo=rust)](https://crates.io/crates/pingly)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

**Pingly** parses captured TLS, HTTP, QUIC, and TCP wire data. Run it as a server with JSON
endpoints and a Web UI, or use its Rust parsers with saved captures.

## Features

- JA3, JA4, Akamai HTTP/2, HTTP/3, and passive TCP fingerprints
- Ordered HTTP/1 fields, HTTP/2 frames, QPACK fields, and QUIC transport parameters
- Incremental parsers and Serde round trips for saved captures
- Linux packet capture with TCP and request latency analysis
- Browser-based protocol inspection
- Automatic ACME certificates with TLS-ALPN-01 or HTTP-01

## Manual

```bash
$ pingly -h
TLS and HTTP/1/2/3 fingerprint analysis server

Usage: pingly
       pingly <COMMAND>

Commands:
  run      Run tracking server
  systemd  Manage the systemd service
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

$ pingly systemd -h
Manage the systemd service

Usage: pingly systemd <COMMAND>

Commands:
  start    Install, enable, and start the systemd service
  restart  Update and restart the systemd service
  stop     Stop the systemd service
  logs     Show recent systemd logs and follow new entries
  status   Show the systemd service status
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Deployment

The Alpine image is published to `ghcr.io/0x676e67/pingly`. Run it locally with:

```bash
docker run --rm --name pingly \
  -p 8181:8181 \
  -v pingly-state:/var/lib/pingly \
  ghcr.io/0x676e67/pingly:latest
```

For a public deployment, keep ACME data in a named volume and map port 443 for the default
TLS-ALPN-01 challenge:

```bash
docker run -d --name pingly --restart unless-stopped \
  -p 443:8181 \
  -v pingly-state:/var/lib/pingly \
  ghcr.io/0x676e67/pingly:latest run --bind 0.0.0.0:8181 \
  --acme-domain pingly.us.kg \
  --acme-email admin@gmail.com \
  --acme-production
```

For HTTP-01, also pass `-p 80:8080`, `--acme-challenge http-01`, and
`--acme-http-bind 0.0.0.0:8080`.

## Library

Add Pingly to your project:

```toml
[dependencies]
pingly = "0.2"
```

The parsers work with captured protocol bytes. For example, a TLS ClientHello can span several TLS
records:

```rust
use pingly::tls::ClientHello;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("client-hello.bin")?;
    let hello = ClientHello::parse(&bytes)?;

    println!("JA3: {}", hello.ja3().hash);
    println!("JA4: {}", hello.ja4().fingerprint);
    Ok(())
}
```

HTTP/3 parsing expects decrypted QUIC stream bytes; the library does not decrypt UDP packets. See
the [examples](./examples) for incremental parsing, protocol fingerprints, and saved JSON.

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](./LICENSE)).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.
