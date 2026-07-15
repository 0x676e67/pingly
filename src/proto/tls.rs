//! TLS ClientHello capture, parsing, and fingerprint analysis.
//!
//! The captured structures preserve client-advertised ordering and raw protocol identifiers where
//! those details are needed for JA3 and JA4 analysis.
//!
//! See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).

#[macro_use]
mod macros;
pub(crate) mod enums;
mod hello;
mod ja3;
mod ja4;
mod parser;

pub use hello::{ClientHello, LazyClientHello};
