//! Protocol data models and fingerprint parsers used by the pingly server.
//!
//! The crate can parse TLS ClientHello captures and HTTP/2 byte streams, serialize the decoded
//! packets to JSON, and deserialize saved API data back into the same owned structures.
//!
//! # TLS ClientHello
//!
//! [`tls::ClientHello::parse`] handles a complete ClientHello across one or more TLS records. For
//! TCP chunks, append bytes to [`tls::ClientHelloBuffer`] and call
//! `try_parse` until it returns a value.
//!
//! ```no_run
//! use pingly::tls::ClientHello;
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
//! [`h2::parse_connection`] handles finite bytes beginning with the HTTP/2 client connection
//! preface. [`h2::Http2Parser`] accepts arbitrary TCP chunks, while [`h2::parse_frames`] starts
//! directly at a frame header.
//!
//! ```no_run
//! use pingly::h2::{parse_connection, AkamaiFingerprint};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = std::fs::read("http2-connection.bin")?;
//! let frames = parse_connection(&bytes)?;
//! let fingerprint = AkamaiFingerprint::from_frames(&frames);
//!
//! let json = serde_json::to_vec_pretty(&frames)?;
//! let restored = serde_json::from_slice::<Vec<pingly::h2::Frame>>(&json)?;
//! assert_eq!(AkamaiFingerprint::from_frames(&restored), fingerprint);
//! # Ok(())
//! # }
//! ```

#![deny(unused)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, deny(warnings))]

pub mod h2;
pub mod tls;
