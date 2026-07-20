# pingly

[![CI](https://github.com/0x676e67/pingly/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/pingly/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/pingly)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/pingly.svg?logo=rust)](https://crates.io/crates/pingly)

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

**Pingly** is a Rust server and library for inspecting TLS and HTTP traffic.

## Features

- JA3, JA4, and Akamai HTTP/2 fingerprints
- HTTP/1 headers and HTTP/2 frames
- Incremental parsing and serialization
- Automatic ACME certificates with TLS-ALPN-01 or HTTP-01

## Manual

```bash
$ pingly -h
TLS and HTTP/1/2 fingerprint analysis server

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

## ACME

TLS-ALPN-01 validates on public TCP port 443 and is the default:

```bash
pingly run --bind 0.0.0.0:443 \
  --acme-domain pingly.us.kg \
  --acme-email admin@gmail.com
```

HTTP-01 serves its challenge on `0.0.0.0:80` by default:

```bash
pingly run --bind 0.0.0.0:443 \
  --acme-domain pingly.us.kg \
  --acme-email admin@gmail.com \
  --acme-challenge http-01
```

Both commands use Let's Encrypt staging until `--acme-production` is supplied. Certificates and
account data use the platform cache directory; systemd services use their managed state directory.

## Docker

The latest Alpine image is published to `ghcr.io/0x676e67/pingly`. Keep certificates in a named
volume when running it:

```bash
docker pull ghcr.io/0x676e67/pingly:latest
docker run --rm --name pingly \
  -p 8181:8181 \
  -v pingly-state:/var/lib/pingly \
  ghcr.io/0x676e67/pingly:latest
```

For TLS-ALPN-01, map public port 443 to the container's unprivileged listener:

```bash
docker run -d --name pingly --restart unless-stopped \
  -p 443:8181 \
  -v pingly-state:/var/lib/pingly \
  ghcr.io/0x676e67/pingly:latest run --bind 0.0.0.0:8181 \
  --acme-domain pingly.us.kg \
  --acme-email admin@gmail.com \
  --acme-production
```

HTTP-01 additionally needs `-p 80:8080`, `--acme-challenge http-01`, and
`--acme-http-bind 0.0.0.0:8080`.

## Example

Add Pingly to your project:

```toml
[dependencies]
pingly = "0.1"
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

Licensed under the Apache License, Version 2.0 ([LICENSE](./LICENSE)).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.
