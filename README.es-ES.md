# pingly

[![CI](https://github.com/0x676e67/pingly/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/pingly/actions/workflows/ci.yml)
[![Crates.io License](https://img.shields.io/crates/l/pingly)](./LICENSE)
[![crates.io](https://img.shields.io/crates/v/pingly.svg?logo=rust)](https://crates.io/crates/pingly)

> 🚀 Ayúdame a seguir trabajando sin problemas en el código abierto [patrocinándome en GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

**Pingly** es un servidor y librería en Rust para inspeccionar el tráfico TLS y HTTP.

## Características

- Huellas dactilares (fingerprints) JA3, JA4, Akamai HTTP/2 y HTTP/3
- Detalles de cabeceras HTTP/1, tramas HTTP/2 y datos de red (wire) HTTP/3/QUIC
- Análisis (parsing) y serialización incremental
- Certificados ACME automáticos con TLS-ALPN-01 o HTTP-01

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

## Despliegue

La imagen de Alpine se publica en `ghcr.io/0x676e67/pingly`. Ejecútala localmente con:

```bash
docker run --rm --name pingly \
  -p 8181:8181 \
  -v pingly-state:/var/lib/pingly \
  ghcr.io/0x676e67/pingly:latest
```

Para un despliegue público, mantén los datos de ACME en un volumen nombrado y mapea el puerto 443 para el desafío TLS-ALPN-01 predeterminado:

```bash
docker run -d --name pingly --restart unless-stopped \
  -p 443:8181 \
  -v pingly-state:/var/lib/pingly \
  ghcr.io/0x676e67/pingly:latest run --bind 0.0.0.0:8181 \
  --acme-domain pingly.us.kg \
  --acme-email admin@gmail.com \
  --acme-production
```

Para HTTP-01, publica también el puerto 80 con `-p 80:8080` y añade `--acme-challenge http-01` y `--acme-http-bind 0.0.0.0:8080`. Sin Docker, ejecuta las mismas opciones de ACME con `pingly run --bind 0.0.0.0:443`. Omite `--acme-production` para usar el entorno de pruebas (staging) de Let's Encrypt. Los certificados y los datos de la cuenta utilizan el directorio de caché de la plataforma; los servicios de systemd utilizan su directorio de estado gestionado.

## Ejemplo

Añade Pingly a tu proyecto:

```toml
[dependencies]
pingly = "0.2"
```

Y luego analiza un TLS ClientHello capturado:

```rust
use pingly::tls::ClientHello;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // La captura puede contener un ClientHello dividido en varios registros TLS.
    let bytes = std::fs::read("client-hello.bin")?;
    let hello = ClientHello::parse(&bytes)?;

    println!("JA3: {}", hello.ja3().hash);
    println!("JA4: {}", hello.ja4().fingerprint);
    Ok(())
}
```

Consulta los [ejemplos](./examples) para ver el análisis incremental, las huellas dactilares de protocolos y el JSON guardado.

## Licencia

Licenciado bajo la Apache License, Versión 2.0 ([LICENSE](./LICENSE)).

## Contribución

A menos que indiques explícitamente lo contrario, cualquier contribución enviada intencionalmente para su inclusión en el trabajo por ti, según se define en la licencia [Apache-2.0](./LICENSE), se licenciará como se indica anteriormente, sin términos o condiciones adicionales.
