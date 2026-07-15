//! Protocol data models and fingerprint parsers used by the pingly server.
//!
//! The crate can parse TLS ClientHello records and HTTP/2 byte streams, serialize the decoded
//! packets to JSON, and deserialize saved API data back into the same owned structures.
//!
//! # TLS ClientHello
//!
//! [`proto::tls::ClientHello::parse`] handles a complete TLS record. For TCP
//! chunks, append bytes to [`proto::tls::ClientHelloBuffer`] and call
//! `try_parse` until it returns a value.
//!
//! ```no_run
//! use pingly::proto::tls::ClientHello;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let record = std::fs::read("client-hello.bin")?;
//! let hello = ClientHello::parse(&record)?;
//! let ja3 = hello.ja3();
//! let ja4 = hello.ja4();
//!
//! let json = serde_json::to_vec_pretty(&hello)?;
//! let restored: ClientHello = serde_json::from_slice(&json)?;
//! assert_eq!(restored.ja3(), ja3);
//! assert_eq!(restored.ja4(), ja4);
//! # Ok(())
//! # }
//! ```
//!
//! # HTTP/2
//!
//! [`proto::http2::parse_connection`] handles finite bytes beginning with the
//! HTTP/2 client connection preface. [`proto::http2::Http2Parser`] accepts
//! arbitrary TCP chunks, while [`proto::http2::parse_frames`] starts directly
//! at a frame header.
//!
//! ```no_run
//! use pingly::proto::http2::{parse_connection, AkamaiFingerprint};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = std::fs::read("http2-connection.bin")?;
//! let frames = parse_connection(&bytes)?;
//! let fingerprint = AkamaiFingerprint::from_frames(&frames);
//!
//! let json = serde_json::to_vec_pretty(&frames)?;
//! let restored = serde_json::from_slice::<Vec<pingly::proto::http2::Frame>>(&json)?;
//! assert_eq!(AkamaiFingerprint::from_frames(&restored), fingerprint);
//! # Ok(())
//! # }
//! ```

pub mod proto;
