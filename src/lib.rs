//! Protocol data models and fingerprint parsers used by the pingly server.
//!
//! The crate can parse TLS ClientHello captures, HTTP/1 message heads, and HTTP/2 byte streams.
//! Decoded structures can be serialized to JSON and restored without losing protocol data.
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
//! # HTTP/1
//!
//! [h1::Http1HeadBuffer] captures arbitrary chunks without parsing fields, so validation and
//! owned model construction can be moved off an I/O path. [h1::Http1Parser] parses immediately.
//! Both preserve field order, original field-name casing, and field-value bytes.
//!
//! ```
//! use pingly::h1::Http1HeadBuffer;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut capture = Http1HeadBuffer::response();
//!
//! for chunk in b"HTTP/1.1 200 OK\r\nServer: pingly\r\n\r\n".chunks(9) {
//!     capture.extend(chunk);
//! }
//!
//! let response = capture
//!     .parse()?
//!     .into_response()
//!     .ok_or_else(|| std::io::Error::other("capture did not contain an HTTP/1 response"))?;
//! assert_eq!(response.status_code, 200);
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

pub mod h1;
pub mod h2;
pub mod tls;
