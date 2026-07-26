# pingly

[![CI](https://github.com/0x676e67/pingly/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/pingly/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/pingly)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/pingly.svg?logo=rust)](https://crates.io/crates/pingly)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

**Pingly** is a Rust server and library for inspecting TLS and HTTP traffic.

## Features

- JA3, JA4, Akamai HTTP/2, and HTTP/3 fingerprints
- HTTP/1 headers, HTTP/2 frames, and HTTP/3/QUIC wire details
- Incremental parsing and serialization
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

For HTTP-01, also publish port 80 with `-p 80:8080` and add `--acme-challenge http-01` and
`--acme-http-bind 0.0.0.0:8080`. Without Docker, run the same ACME options with
`pingly run --bind 0.0.0.0:443`. Omit `--acme-production` to use Let's Encrypt staging.
Certificates and account data use the platform cache directory; systemd services use their managed
state directory.

## Example

Add Pingly to your project:

```toml
[dependencies]
pingly = "0.2"
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

See [examples](./examples) for incremental parsing, protocol fingerprints, and saved JSON.

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](./LICENSE)).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.
