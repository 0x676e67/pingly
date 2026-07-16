//! TLS ClientHello data captured from the wire.
//!
//! See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2)
//! for the ClientHello layout and [Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3)
//! for its extension block.

use std::{borrow::Cow, fmt};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use tls_parser::{TlsCipherSuite as ParsedTlsCipherSuite, TlsExtensionType, TlsMessageHandshake};

use super::{
    enums::{
        is_grease_value, AuthenticatedEncryptionWithAssociatedData,
        CertificateCompressionAlgorithm, CertificateStatusType, CompressionAlgorithm,
        ECPointFormat, KeyDerivationFunction, PskKeyExchangeMode, SignatureAlgorithm, TlsVersion,
    },
    group::NamedGroup,
    ja3::Ja3Fingerprint,
    ja4::Ja4Fingerprint,
    parser,
};

const DEFAULT_CLIENT_HELLO_CAPACITY: usize = 2048;
const DEFAULT_CLIENT_HELLO_CAPTURE_LIMIT: usize = 64 * 1024;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;

/// Buffers raw TLS record bytes so the ClientHello can be parsed after the handshake.
///
/// Deferring parsing keeps fingerprint analysis out of the handshake path. The buffer may be filled
/// incrementally when the ClientHello spans multiple reads.
#[derive(Debug, Clone)]
pub struct ClientHelloBuffer {
    /// TLS record bytes retained through the ClientHello.
    buf: Vec<u8>,

    /// Maximum bytes retained for an incomplete or malformed capture.
    capture_limit: usize,

    /// Whether the retained records contain a complete ClientHello.
    complete: bool,

    /// Incremental framing state used to avoid rescanning retained records on every read.
    capture: ClientHelloCaptureState,
}

/// Minimal state needed to locate the end of a fragmented ClientHello.
#[derive(Debug, Clone, Default)]
struct ClientHelloCaptureState {
    /// Start of the next TLS record that has not been consumed.
    record_offset: usize,

    /// First handshake header, which may itself span TLS records.
    handshake_header: [u8; TLS_HANDSHAKE_HEADER_LEN],

    /// Number of bytes currently stored in `handshake_header`.
    handshake_header_len: usize,

    /// Declared handshake length including its four-byte header.
    handshake_len: Option<usize>,

    /// Number of ClientHello handshake bytes observed across complete records.
    handshake_bytes_seen: usize,

    /// Framing error found while incrementally inspecting the capture.
    error: Option<ClientHelloParseStage>,
}

impl ClientHelloCaptureState {
    fn consume_payload(&mut self, payload: &[u8]) -> Result<bool, ClientHelloParseStage> {
        let mut cursor = 0usize;

        if self.handshake_header_len < TLS_HANDSHAKE_HEADER_LEN {
            let remaining_header = TLS_HANDSHAKE_HEADER_LEN - self.handshake_header_len;
            let copied = remaining_header.min(payload.len());
            let header_end = self.handshake_header_len + copied;
            self.handshake_header[self.handshake_header_len..header_end]
                .copy_from_slice(&payload[..copied]);
            self.handshake_header_len = header_end;
            self.handshake_bytes_seen += copied;
            cursor = copied;

            if self.handshake_header_len < TLS_HANDSHAKE_HEADER_LEN {
                return Ok(false);
            }

            self.handshake_len =
                client_hello_handshake_len(&self.handshake_header).map_err(|error| error.stage)?;
        }

        let handshake_len = self
            .handshake_len
            .ok_or(ClientHelloParseStage::ClientHello)?;
        let remaining = handshake_len.saturating_sub(self.handshake_bytes_seen);
        let available = payload.len().saturating_sub(cursor);
        self.handshake_bytes_seen += remaining.min(available);

        Ok(self.handshake_bytes_seen >= handshake_len)
    }
}

impl ClientHelloBuffer {
    /// Creates an empty ClientHello buffer with capacity for a typical browser handshake.
    pub fn new() -> Self {
        Self::with_capacity_and_limit(
            DEFAULT_CLIENT_HELLO_CAPACITY,
            DEFAULT_CLIENT_HELLO_CAPTURE_LIMIT,
        )
    }

    /// Creates an empty buffer with at least the requested initial capacity.
    ///
    /// Requesting more than the default capture limit raises the limit to the requested capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_limit(capacity, DEFAULT_CLIENT_HELLO_CAPTURE_LIMIT.max(capacity))
    }

    /// Creates an empty buffer with a custom maximum capture size.
    pub fn with_capture_limit(capture_limit: usize) -> Self {
        Self::with_capacity_and_limit(
            DEFAULT_CLIENT_HELLO_CAPACITY.min(capture_limit),
            capture_limit,
        )
    }

    /// Creates an empty buffer with explicit allocation and capture limits.
    ///
    /// The effective capture limit is never smaller than the requested initial capacity.
    pub fn with_capacity_and_limit(capacity: usize, capture_limit: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            capture_limit: capture_limit.max(capacity),
            capture: ClientHelloCaptureState::default(),
            complete: false,
        }
    }

    /// Creates a buffer from captured TLS record bytes.
    ///
    /// Passing a `Vec<u8>` transfers its allocation into the buffer. Slices are
    /// copied because the parser owns bytes that may outlive the input read.
    /// Bytes after the record that completes the ClientHello are discarded, matching
    /// [`Self::extend`].
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        let buf = bytes.into();
        let capture_limit = DEFAULT_CLIENT_HELLO_CAPTURE_LIMIT.max(buf.len());
        let mut buffer = Self {
            buf,
            capture_limit,
            complete: false,
            capture: ClientHelloCaptureState::default(),
        };
        if let Some(record_end) = buffer.scan_available_records() {
            buffer.buf.truncate(record_end);
        }
        buffer
    }

    /// Attempts to parse the first complete TLS ClientHello handshake in the buffer.
    ///
    /// The buffer remains available after either success or failure, which is
    /// useful when inspecting malformed captures.
    pub fn parse(&self) -> Result<ClientHello, ClientHelloParseError> {
        ClientHello::parse(&self.buf)
    }

    /// Parses a ClientHello once all of its TLS handshake records are complete.
    ///
    /// Returns `Ok(None)` while a record or the fragmented handshake is incomplete. A complete
    /// but malformed capture returns a [`ClientHelloParseError`]. TLS record fragmentation is
    /// defined by
    /// [RFC 9846, Section 5.1](https://www.rfc-editor.org/rfc/rfc9846#section-5.1).
    pub fn try_parse(&self) -> Result<Option<ClientHello>, ClientHelloParseError> {
        if let Some(stage) = self.capture.error {
            return Err(ClientHelloParseError::new(stage));
        }
        if !self.complete {
            return Ok(None);
        }

        let Some(captured) = capture_client_hello(&self.buf)? else {
            return Ok(None);
        };

        ClientHello::parse_handshake(captured.handshake.as_ref()).map(Some)
    }

    /// Returns the currently buffered TLS bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the number of currently buffered bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns whether no TLS bytes have been buffered yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns whether the retained records contain a complete ClientHello.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns whether incremental TLS framing encountered malformed input.
    pub const fn is_invalid(&self) -> bool {
        self.capture.error.is_some()
    }

    /// Returns the maximum number of TLS bytes retained for an incomplete or malformed capture.
    pub const fn capture_limit(&self) -> usize {
        self.capture_limit
    }

    /// Returns whether the configured capture limit has been reached.
    pub fn is_full(&self) -> bool {
        self.buf.len() >= self.capture_limit
    }

    /// Appends TLS bytes until the ClientHello completes or the capture limit is reached.
    ///
    /// Returns the number of bytes retained from `data`. Bytes after the TLS record that
    /// completes the ClientHello are discarded.
    pub fn extend(&mut self, data: &[u8]) -> usize {
        if self.complete || self.is_invalid() || self.is_full() {
            return 0;
        }

        let initial_len = self.buf.len();
        let accepted = data
            .len()
            .min(self.capture_limit.saturating_sub(initial_len));
        self.buf.extend_from_slice(&data[..accepted]);

        if let Some(record_end) = self.scan_available_records() {
            self.buf.truncate(record_end);
        }

        self.buf.len().saturating_sub(initial_len)
    }

    fn scan_available_records(&mut self) -> Option<usize> {
        while !self.complete && self.capture.error.is_none() {
            let record_offset = self.capture.record_offset;
            let Some(header_end) = record_offset.checked_add(TLS_RECORD_HEADER_LEN) else {
                self.capture.error = Some(ClientHelloParseStage::TlsRecord);
                return None;
            };
            let header = self.buf.get(record_offset..header_end)?;
            if header[0] != TLS_HANDSHAKE_CONTENT_TYPE {
                self.capture.error = Some(ClientHelloParseStage::RecordMessages);
                return None;
            }

            let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if payload_len > usize::from(tls_parser::MAX_RECORD_LEN) {
                self.capture.error = Some(ClientHelloParseStage::TlsRecord);
                return None;
            }
            let Some(record_end) = header_end.checked_add(payload_len) else {
                self.capture.error = Some(ClientHelloParseStage::TlsRecord);
                return None;
            };
            let payload = self.buf.get(header_end..record_end)?;

            match self.capture.consume_payload(payload) {
                Ok(true) => {
                    self.capture.record_offset = record_end;
                    self.complete = true;
                    return Some(record_end);
                }
                Ok(false) => self.capture.record_offset = record_end,
                Err(stage) => {
                    self.capture.error = Some(stage);
                    return None;
                }
            }
        }

        None
    }
}

/// A complete ClientHello handshake reassembled from its TLS records.
struct CapturedClientHello<'a> {
    /// Reassembled handshake bytes, including the four-byte handshake header.
    handshake: Cow<'a, [u8]>,
}

/// Finds and reassembles a ClientHello split across one or more TLS handshake records.
///
/// RFC 9846 permits handshake messages to cross record boundaries:
/// <https://www.rfc-editor.org/rfc/rfc9846#section-5.1>
fn capture_client_hello(
    data: &[u8],
) -> Result<Option<CapturedClientHello<'_>>, ClientHelloParseError> {
    let mut cursor = 0usize;
    let mut handshake = Vec::new();

    loop {
        let Some(header_end) = cursor.checked_add(TLS_RECORD_HEADER_LEN) else {
            return Err(ClientHelloParseError::new(ClientHelloParseStage::TlsRecord));
        };
        let Some(header) = data.get(cursor..header_end) else {
            return Ok(None);
        };
        if header[0] != TLS_HANDSHAKE_CONTENT_TYPE {
            return Err(ClientHelloParseError::new(
                ClientHelloParseStage::RecordMessages,
            ));
        }

        let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if payload_len > usize::from(tls_parser::MAX_RECORD_LEN) {
            return Err(ClientHelloParseError::new(ClientHelloParseStage::TlsRecord));
        }
        let Some(record_end) = header_end.checked_add(payload_len) else {
            return Err(ClientHelloParseError::new(ClientHelloParseStage::TlsRecord));
        };
        let Some(payload) = data.get(header_end..record_end) else {
            return Ok(None);
        };

        if handshake.is_empty() {
            if let Some(handshake_len) = client_hello_handshake_len(payload)? {
                if let Some(handshake) = payload.get(..handshake_len) {
                    return Ok(Some(CapturedClientHello {
                        handshake: Cow::Borrowed(handshake),
                    }));
                }
            }
        }

        handshake.extend_from_slice(payload);
        if let Some(handshake_len) = client_hello_handshake_len(&handshake)? {
            if handshake.len() >= handshake_len {
                handshake.truncate(handshake_len);
                return Ok(Some(CapturedClientHello {
                    handshake: Cow::Owned(handshake),
                }));
            }
        }

        cursor = record_end;
    }
}

fn client_hello_handshake_len(data: &[u8]) -> Result<Option<usize>, ClientHelloParseError> {
    let Some(header) = data.get(..TLS_HANDSHAKE_HEADER_LEN) else {
        return Ok(None);
    };
    if header[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(ClientHelloParseError::new(
            ClientHelloParseStage::ClientHello,
        ));
    }

    let payload_len = usize::try_from(u32::from_be_bytes([0, header[1], header[2], header[3]]))
        .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::ClientHello))?;
    TLS_HANDSHAKE_HEADER_LEN
        .checked_add(payload_len)
        .map(Some)
        .ok_or(ClientHelloParseError::new(
            ClientHelloParseStage::ClientHello,
        ))
}

impl Default for ClientHelloBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for ClientHelloBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<&[u8]> for ClientHelloBuffer {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// Owned bytes serialized as canonical lowercase hexadecimal text.
///
/// This keeps binary TLS fields compact in memory while preserving the existing JSON shape.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct HexBytes(Box<[u8]>);

impl HexBytes {
    /// Creates an owned byte value from owned or borrowed bytes.
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the decoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the decoded byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the value contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the value and returns its owned bytes.
    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HexBytes({self})")
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Box::<str>::deserialize(deserializer)?;
        if encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom(
                "hexadecimal TLS bytes must use lowercase ASCII digits",
            ));
        }

        hex::decode(encoded.as_ref())
            .map(Self::from)
            .map_err(de::Error::custom)
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for HexBytes {
    fn from(bytes: Box<[u8]>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for HexBytes {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl<const N: usize> From<[u8; N]> for HexBytes {
    fn from(bytes: [u8; N]) -> Self {
        Self(Vec::from(bytes).into_boxed_slice())
    }
}

/// An invalid TLS application protocol name length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("TLS protocol names must contain 1 to 255 bytes, got {length}")]
pub struct ProtocolNameError {
    /// Invalid decoded byte length.
    pub length: usize,
}

/// An owned ALPN-compatible opaque protocol name.
///
/// RFC 7301 defines protocol names as non-empty opaque byte strings rather than UTF-8 text.
/// Valid UTF-8 names serialize as JSON strings; other names use an object containing `hex`.
/// See [RFC 7301, Section 3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProtocolName(Box<[u8]>);

impl ProtocolName {
    /// Creates a protocol name from one to 255 bytes.
    pub fn from_bytes(bytes: impl Into<Box<[u8]>>) -> Result<Self, ProtocolNameError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > usize::from(u8::MAX) {
            return Err(ProtocolNameError {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque protocol-name bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the name as UTF-8 when its bytes form valid text.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }

    /// Returns the protocol-name byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the protocol name is empty.
    ///
    /// Valid protocol names always return `false`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for ProtocolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = self.as_str() {
            return formatter.write_str(value);
        }
        for byte in self.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ProtocolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(value) => formatter.debug_tuple("ProtocolName").field(&value).finish(),
            None => write!(formatter, "ProtocolName({self})"),
        }
    }
}

impl Serialize for ProtocolName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.as_str() {
            Some(value) => serializer.serialize_str(value),
            None => ProtocolNameHex {
                hex: hex::encode(self.as_bytes()).into_boxed_str(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = match ProtocolNameRepr::deserialize(deserializer)? {
            ProtocolNameRepr::Text(value) => value.into_boxed_bytes(),
            ProtocolNameRepr::Bytes { hex } => hex.into_bytes(),
        };
        Self::from_bytes(bytes).map_err(de::Error::custom)
    }
}

impl AsRef<[u8]> for ProtocolName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for ProtocolName {
    type Error = ProtocolNameError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<Box<[u8]>> for ProtocolName {
    type Error = ProtocolNameError;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for ProtocolName {
    type Error = ProtocolNameError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&str> for ProtocolName {
    type Error = ProtocolNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_bytes(value.as_bytes())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
/// Accepted JSON representations of a TLS protocol name.
enum ProtocolNameRepr {
    /// A UTF-8 protocol name represented directly as JSON text.
    Text(Box<str>),

    /// An opaque protocol name represented by canonical hexadecimal bytes.
    Bytes { hex: HexBytes },
}

#[derive(Serialize)]
/// JSON representation used when a protocol name is not valid UTF-8.
struct ProtocolNameHex {
    /// Canonical lowercase hexadecimal bytes.
    hex: Box<str>,
}

/// A cipher suite offered by a TLS client.
///
/// Registered identifiers use the IANA name exposed by `tls-parser`. GREASE identifiers use
/// `GREASE`, while other unregistered identifiers use `Unknown`, so every wire ID remains in
/// the client-advertised list.
///
/// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct TlsCipherSuite {
    /// The 16-bit cipher-suite identifier observed on the wire.
    pub id: u16,

    /// The registered cipher-suite name, `GREASE`, or `Unknown`.
    pub name: Box<str>,
}

impl TlsCipherSuite {
    /// Resolves a wire identifier into its canonical display name.
    pub fn from_id(id: u16) -> Self {
        Self {
            id,
            name: Self::name_for_id(id).into(),
        }
    }

    /// Resolves a registered IANA cipher-suite name.
    ///
    /// `GREASE` and `Unknown` cannot identify a unique wire value and therefore return `None`.
    pub fn from_name(name: &str) -> Option<Self> {
        ParsedTlsCipherSuite::from_name(name).map(|cipher| Self {
            id: cipher.id.0,
            name: cipher.name.into(),
        })
    }

    /// Returns whether this identifier is reserved for GREASE.
    ///
    /// See [RFC 8701, Section 2](https://www.rfc-editor.org/rfc/rfc8701.html#section-2).
    pub fn is_grease(&self) -> bool {
        is_grease_value(self.id)
    }

    fn name_for_id(id: u16) -> &'static str {
        ParsedTlsCipherSuite::from_id(id)
            .map(|cipher| cipher.name)
            .unwrap_or_else(|| {
                if is_grease_value(id) {
                    "GREASE"
                } else {
                    "Unknown"
                }
            })
    }
}

impl From<u16> for TlsCipherSuite {
    fn from(id: u16) -> Self {
        Self::from_id(id)
    }
}

/// Deserialization shape used to validate a saved cipher-suite ID and name.
#[derive(Deserialize)]
struct TlsCipherSuiteRepr {
    /// The numeric identifier stored in JSON.
    id: u16,

    /// The human-readable name stored alongside the identifier.
    name: Box<str>,
}

impl<'de> Deserialize<'de> for TlsCipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = TlsCipherSuiteRepr::deserialize(deserializer)?;
        let expected = Self::name_for_id(repr.id);

        if repr.name.as_ref() != expected {
            return Err(de::Error::custom(format_args!(
                "TLS cipher suite {:#06x} has name {expected:?}, not {:?}",
                repr.id, repr.name,
            )));
        }

        Ok(Self {
            id: repr.id,
            name: repr.name,
        })
    }
}

/// A decoded TLS ClientHello and the negotiated version observed after the handshake.
///
/// Client-advertised vectors retain their wire order because order is significant to TLS client
/// fingerprinting.
///
/// See [RFC 9846, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// The wire `legacy_version` field.
    ///
    /// A TLS 1.3 client normally sends TLS 1.2 (`0x0303`) here and advertises its real preferences
    /// through the `supported_versions` extension.
    pub tls_version: TlsVersion,

    /// The protocol version selected by the server, or `None` before negotiation completes.
    pub tls_version_negotiated: Option<TlsVersion>,

    /// The 32-byte ClientHello random value encoded as lowercase hexadecimal.
    #[serde(deserialize_with = "client_hello_hex::random")]
    pub client_random: HexBytes,

    /// The legacy session identifier encoded as lowercase hexadecimal, when present.
    #[serde(deserialize_with = "client_hello_hex::session_id")]
    pub session_id: Option<HexBytes>,

    /// Compression methods in client-advertised order.
    pub compression_algorithms: Vec<CompressionAlgorithm>,

    /// Cipher suites in client-advertised order, including GREASE and unregistered identifiers.
    pub cipher_suites: Vec<TlsCipherSuite>,

    /// Decoded extensions in the order sent by the client.
    pub extensions: Vec<TlsExtension>,
}

mod client_hello_hex {
    use serde::{de, Deserialize, Deserializer};

    use super::HexBytes;

    pub(super) fn random<'de, D>(deserializer: D) -> Result<HexBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = HexBytes::deserialize(deserializer)?;
        if value.len() != 32 {
            return Err(de::Error::custom(format_args!(
                "TLS ClientHello random must contain 32 bytes, got {}",
                value.len(),
            )));
        }
        Ok(value)
    }

    pub(super) fn session_id<'de, D>(deserializer: D) -> Result<Option<HexBytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<HexBytes>::deserialize(deserializer)?;
        if let Some(value) = &value {
            if value.is_empty() || value.len() > 32 {
                return Err(de::Error::custom(format_args!(
                    "TLS legacy session ID must contain 1 to 32 bytes, got {}",
                    value.len(),
                )));
            }
        }
        Ok(value)
    }
}

/// A decoded or preserved extension from a [`ClientHello`].
///
/// Every `value` field is the numeric `ExtensionType` observed on the wire. Byte-oriented payloads
/// are serialized as lowercase hexadecimal unless a variant documents another representation.
///
/// See [RFC 9846, Section 4.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsExtension {
    /// Server names advertised through Server Name Indication (SNI).
    ///
    /// See [RFC 6066, Section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
    ServerName {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::server_name")]
        value: u16,

        /// Advertised names decoded as UTF-8, replacing malformed byte sequences when necessary.
        data: Vec<Box<str>>,
    },

    /// Named groups supported for key establishment.
    ///
    /// See [RFC 9846, Section 4.3.7](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.7).
    SupportedGroups {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::supported_groups")]
        value: u16,

        /// Named groups in client preference order.
        data: Vec<NamedGroup>,
    },

    /// Elliptic-curve point formats advertised by a pre-TLS 1.3 client.
    ///
    /// See [RFC 8422, Section 5.1.2](https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2).
    EcPointFormats {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::ec_point_formats")]
        value: u16,

        /// Point formats in client preference order.
        data: Vec<ECPointFormat>,
    },

    /// Signature schemes accepted by the client.
    ///
    /// See [RFC 9846, Section 4.3.3](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.3).
    SignatureAlgorithms {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::signature_algorithms")]
        value: u16,

        /// Signature schemes in client preference order.
        data: Vec<SignatureAlgorithm>,
    },

    /// A request for a stapled certificate status response.
    ///
    /// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
    StatusRequest {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::status_request")]
        value: u16,

        /// Parsed OCSP status request parameters.
        data: StatusRequest,
    },

    /// Application protocols offered through ALPN, such as `h2`.
    ///
    /// See [RFC 7301, Section 3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1).
    ApplicationLayerProtocolNegotiation {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::alpn")]
        value: u16,

        /// Opaque protocol names in client preference order.
        data: Vec<ProtocolName>,
    },

    /// Protocol names from the former `0x4469` Application Settings code point.
    ///
    /// ALPS remains an Internet-Draft; see
    /// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
    ApplicationSettingsOld {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::application_settings_old")]
        value: u16,

        /// Application protocol names carried by the extension.
        data: Vec<ProtocolName>,
    },

    /// Protocol names from the current `0x44cd` Application Settings code point.
    ///
    /// ALPS remains an Internet-Draft; see
    /// [draft-vvv-tls-alps](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps).
    ApplicationSettings {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::application_settings")]
        value: u16,

        /// Application protocol names carried by the extension.
        data: Vec<ProtocolName>,
    },

    /// TLS versions the client is prepared to negotiate.
    ///
    /// See [RFC 9846, Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.1).
    SupportedVersions {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::supported_versions")]
        value: u16,

        /// Versions in client preference order.
        data: Vec<TlsVersion>,
    },

    /// A TLS 1.2 session ticket offered for resumption.
    ///
    /// See [RFC 5077, Section 3.2](https://www.rfc-editor.org/rfc/rfc5077.html#section-3.2).
    SessionTicket {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::session_ticket")]
        value: u16,

        /// Opaque ticket bytes encoded as lowercase hexadecimal.
        data: HexBytes,
    },

    /// Supported certificate compression algorithms.
    ///
    /// See [RFC 8879, Section 3](https://www.rfc-editor.org/rfc/rfc8879.html#section-3).
    CertificateCompression {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::certificate_compression")]
        value: u16,

        /// Compression algorithms in client preference order.
        data: Vec<CertificateCompressionAlgorithm>,
    },

    /// Maximum protected record size accepted by the client.
    ///
    /// See [RFC 8449, Section 4](https://www.rfc-editor.org/rfc/rfc8449.html#section-4).
    RecordSizeLimit {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::record_size_limit")]
        value: u16,

        /// Advertised record size limit in bytes.
        data: u16,
    },

    /// Signature schemes accepted for delegated credentials.
    ///
    /// See [RFC 9345, Section 4.1](https://www.rfc-editor.org/rfc/rfc9345.html#section-4.1).
    DelegatedCredentials {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::delegated_credentials")]
        value: u16,

        /// Supported delegated-credential signature schemes.
        data: Vec<SignatureAlgorithm>,
    },

    /// An Encrypted ClientHello (ECH) offer.
    ///
    /// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
    EncryptedClientHello {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::encrypted_client_hello")]
        value: u16,

        /// Parsed outer or inner ECH payload.
        data: ECHClientHello,
    },

    /// A request for Signed Certificate Timestamps through the TLS extension.
    ///
    /// See [RFC 6962, Section 3.3.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-3.3.1).
    SignedCertificateTimestamp {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::signed_certificate_timestamp")]
        value: u16,

        /// Raw payload encoded as lowercase hexadecimal when one was present.
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<HexBytes>,
    },

    /// The secure renegotiation indication used by TLS 1.2 and earlier.
    ///
    /// See [RFC 5746, Section 3.2](https://www.rfc-editor.org/rfc/rfc5746.html#section-3.2).
    RenegotiationInfo {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::renegotiation_info")]
        value: u16,
    },

    /// The Extended Master Secret indication used by TLS 1.2 and earlier.
    ///
    /// See [RFC 7627, Section 3](https://www.rfc-editor.org/rfc/rfc7627.html#section-3).
    ExtendedMasterSecret {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::extended_master_secret")]
        value: u16,
    },

    /// ClientHello padding used to alter the message length.
    ///
    /// See [RFC 7685, Section 3](https://www.rfc-editor.org/rfc/rfc7685.html#section-3).
    Padding {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::padding")]
        value: u16,

        /// Padding bytes encoded as lowercase hexadecimal.
        data: HexBytes,
    },

    /// Ephemeral key shares offered for TLS 1.3 key establishment.
    ///
    /// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
    KeyShare {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::key_share")]
        value: u16,

        /// Parsed key shares in client preference order.
        data: Vec<KeyShare>,
    },

    /// Key exchange modes the client permits for pre-shared keys.
    ///
    /// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
    PskKeyExchangeModes {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::psk_key_exchange_modes")]
        value: u16,

        /// Parsed PSK key exchange modes.
        data: PskKeyExchangeModes,
    },

    /// Pre-shared key identities and binders offered for resumption or 0-RTT.
    ///
    /// See [RFC 9846, Section 4.3.11](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.11).
    PreSharedKey {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::pre_shared_key")]
        value: u16,

        /// Complete opaque extension payload encoded as lowercase hexadecimal.
        data: HexBytes,
    },

    /// A legacy experimental Encrypted Server Name Indication (ESNI) offer.
    ///
    /// ESNI was replaced by ECH; see
    /// [draft-ietf-tls-esni-00](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-00).
    EncryptedServerName {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::encrypted_server_name")]
        value: u16,

        /// Recognized TLS cipher-suite name, or `Unknown`.
        ciphersuite: Box<str>,

        /// Named group used for the key share.
        group: NamedGroup,

        /// Key share bytes encoded as lowercase hexadecimal.
        key_share: HexBytes,

        /// ESNIKeys record digest encoded as lowercase hexadecimal.
        record_digest: HexBytes,

        /// Encrypted server-name bytes encoded as lowercase hexadecimal.
        encrypted_sni: HexBytes,
    },

    /// Filters applied to certificate extension object identifiers.
    ///
    /// See [RFC 9846, Section 4.3.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.5).
    OidFilters {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::oid_filters")]
        value: u16,

        /// Requested certificate extension filters.
        data: Vec<OidFilter>,
    },

    /// A reserved GREASE extension used to exercise protocol extensibility.
    ///
    /// See [RFC 8701, Section 3](https://www.rfc-editor.org/rfc/rfc8701.html#section-3).
    Grease {
        /// GREASE extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::grease")]
        value: u16,
    },

    /// An extension that is valid to preserve but is not decoded into a dedicated variant.
    Opaque {
        /// Numeric extension type as observed on the wire.
        #[serde(deserialize_with = "extension_id::opaque")]
        value: u16,

        /// Raw payload encoded as lowercase hexadecimal, or `None` for an empty payload.
        data: Option<HexBytes>,
    },
}

mod extension_id {
    use serde::{de, Deserialize, Deserializer};
    use tls_parser::TlsExtensionType;

    use super::is_grease_value;

    const CERTIFICATE_COMPRESSION: u16 = 27;
    const DELEGATED_CREDENTIALS: u16 = 34;
    const APPLICATION_SETTINGS_OLD: u16 = 17_513;
    const APPLICATION_SETTINGS: u16 = 17_613;
    const ENCRYPTED_CLIENT_HELLO: u16 = 65_037;

    const DEDICATED_TYPES: &[u16] = &[
        TlsExtensionType::ServerName.0,
        TlsExtensionType::StatusRequest.0,
        TlsExtensionType::SupportedGroups.0,
        TlsExtensionType::EcPointFormats.0,
        TlsExtensionType::SignatureAlgorithms.0,
        TlsExtensionType::ApplicationLayerProtocolNegotiation.0,
        TlsExtensionType::SignedCertificateTimestamp.0,
        TlsExtensionType::Padding.0,
        TlsExtensionType::ExtendedMasterSecret.0,
        CERTIFICATE_COMPRESSION,
        TlsExtensionType::RecordSizeLimit.0,
        DELEGATED_CREDENTIALS,
        TlsExtensionType::SessionTicketTLS.0,
        TlsExtensionType::PreSharedKey.0,
        TlsExtensionType::SupportedVersions.0,
        TlsExtensionType::PskExchangeModes.0,
        TlsExtensionType::OidFilters.0,
        TlsExtensionType::KeyShare.0,
        APPLICATION_SETTINGS_OLD,
        APPLICATION_SETTINGS,
        ENCRYPTED_CLIENT_HELLO,
        TlsExtensionType::RenegotiationInfo.0,
        TlsExtensionType::EncryptedServerName.0,
    ];

    macro_rules! exact_id {
        ($name:ident, $expected:expr) => {
            pub(super) fn $name<'de, D>(deserializer: D) -> Result<u16, D::Error>
            where
                D: Deserializer<'de>,
            {
                exact(deserializer, $expected)
            }
        };
    }

    exact_id!(server_name, TlsExtensionType::ServerName.0);
    exact_id!(status_request, TlsExtensionType::StatusRequest.0);
    exact_id!(supported_groups, TlsExtensionType::SupportedGroups.0);
    exact_id!(ec_point_formats, TlsExtensionType::EcPointFormats.0);
    exact_id!(
        signature_algorithms,
        TlsExtensionType::SignatureAlgorithms.0
    );
    exact_id!(
        alpn,
        TlsExtensionType::ApplicationLayerProtocolNegotiation.0
    );
    exact_id!(
        signed_certificate_timestamp,
        TlsExtensionType::SignedCertificateTimestamp.0
    );
    exact_id!(padding, TlsExtensionType::Padding.0);
    exact_id!(
        extended_master_secret,
        TlsExtensionType::ExtendedMasterSecret.0
    );
    exact_id!(certificate_compression, CERTIFICATE_COMPRESSION);
    exact_id!(record_size_limit, TlsExtensionType::RecordSizeLimit.0);
    exact_id!(delegated_credentials, DELEGATED_CREDENTIALS);
    exact_id!(session_ticket, TlsExtensionType::SessionTicketTLS.0);
    exact_id!(pre_shared_key, TlsExtensionType::PreSharedKey.0);
    exact_id!(supported_versions, TlsExtensionType::SupportedVersions.0);
    exact_id!(psk_key_exchange_modes, TlsExtensionType::PskExchangeModes.0);
    exact_id!(oid_filters, TlsExtensionType::OidFilters.0);
    exact_id!(key_share, TlsExtensionType::KeyShare.0);
    exact_id!(application_settings_old, APPLICATION_SETTINGS_OLD);
    exact_id!(application_settings, APPLICATION_SETTINGS);
    exact_id!(encrypted_client_hello, ENCRYPTED_CLIENT_HELLO);
    exact_id!(renegotiation_info, TlsExtensionType::RenegotiationInfo.0);
    exact_id!(
        encrypted_server_name,
        TlsExtensionType::EncryptedServerName.0
    );

    fn exact<'de, D>(deserializer: D, expected: u16) -> Result<u16, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        if value != expected {
            return Err(de::Error::custom(format_args!(
                "TLS extension variant expects ID {expected}, got {value}"
            )));
        }
        Ok(value)
    }

    pub(super) fn grease<'de, D>(deserializer: D) -> Result<u16, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        if !is_grease_value(value) {
            return Err(de::Error::custom(format_args!(
                "TLS GREASE extension has non-GREASE ID {value}"
            )));
        }
        Ok(value)
    }

    pub(super) fn opaque<'de, D>(deserializer: D) -> Result<u16, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        if is_grease_value(value) || DEDICATED_TYPES.contains(&value) {
            return Err(de::Error::custom(format_args!(
                "TLS extension ID {value} has a dedicated variant"
            )));
        }
        Ok(value)
    }
}

impl TlsExtension {
    /// Returns the numeric `ExtensionType` observed on the wire.
    pub fn value(&self) -> u16 {
        match self {
            TlsExtension::ServerName { value, .. }
            | TlsExtension::SupportedGroups { value, .. }
            | TlsExtension::EcPointFormats { value, .. }
            | TlsExtension::SignatureAlgorithms { value, .. }
            | TlsExtension::StatusRequest { value, .. }
            | TlsExtension::ApplicationLayerProtocolNegotiation { value, .. }
            | TlsExtension::ApplicationSettingsOld { value, .. }
            | TlsExtension::ApplicationSettings { value, .. }
            | TlsExtension::SupportedVersions { value, .. }
            | TlsExtension::SessionTicket { value, .. }
            | TlsExtension::CertificateCompression { value, .. }
            | TlsExtension::RecordSizeLimit { value, .. }
            | TlsExtension::DelegatedCredentials { value, .. }
            | TlsExtension::EncryptedClientHello { value, .. }
            | TlsExtension::SignedCertificateTimestamp { value, .. }
            | TlsExtension::RenegotiationInfo { value }
            | TlsExtension::ExtendedMasterSecret { value }
            | TlsExtension::Padding { value, .. }
            | TlsExtension::KeyShare { value, .. }
            | TlsExtension::PskKeyExchangeModes { value, .. }
            | TlsExtension::PreSharedKey { value, .. }
            | TlsExtension::EncryptedServerName { value, .. }
            | TlsExtension::OidFilters { value, .. }
            | TlsExtension::Grease { value }
            | TlsExtension::Opaque { value, .. } => *value,
        }
    }

    /// Returns whether this extension uses an RFC 8701 GREASE type.
    ///
    /// See [RFC 8701, Section 3](https://www.rfc-editor.org/rfc/rfc8701.html#section-3).
    pub fn is_grease(&self) -> bool {
        is_grease_value(self.value())
    }
}

/// The OCSP parameters carried by a ClientHello `status_request` extension.
///
/// See [RFC 6066, Section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct StatusRequest {
    /// The certificate status protocol requested by the client.
    pub certificate_status_type: CertificateStatusType,

    /// Declared byte length of the OCSP responder ID list.
    pub responder_id_list: u16,

    /// Declared byte length of the OCSP request extensions.
    pub request_extensions: u16,
}

impl<'de> Deserialize<'de> for StatusRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = StatusRequestRepr::deserialize(deserializer)?;
        if repr.certificate_status_type != CertificateStatusType::OCSP {
            return Err(de::Error::custom(
                "ClientHello status_request currently supports only OCSP",
            ));
        }
        if matches!(repr.responder_id_list, 1 | 2) {
            return Err(de::Error::custom(
                "an OCSP responder ID list must be empty or contain at least three bytes",
            ));
        }

        Ok(Self {
            certificate_status_type: repr.certificate_status_type,
            responder_id_list: repr.responder_id_list,
            request_extensions: repr.request_extensions,
        })
    }
}

/// Deserialization shape used to validate OCSP status request metadata.
#[derive(Deserialize)]
struct StatusRequestRepr {
    /// Saved certificate status protocol.
    certificate_status_type: CertificateStatusType,

    /// Saved responder ID list byte length.
    responder_id_list: u16,

    /// Saved request extensions byte length.
    request_extensions: u16,
}

/// The outer or inner form of an Encrypted ClientHello extension.
///
/// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ECHClientHello {
    /// The public ClientHelloOuter payload carrying the encrypted ClientHelloInner.
    Outer(ECHClientHelloOuter),
    /// The empty marker repeated inside ClientHelloInner.
    ///
    /// Including this marker permits the server to respond with ECH-related extensions after it
    /// discards ClientHelloOuter.
    Inner,
}

/// Encryption metadata and ciphertext carried by an ECH ClientHelloOuter.
///
/// See [RFC 9849, Section 5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct ECHClientHelloOuter {
    /// The HPKE KDF and AEAD pair used to encrypt ClientHelloInner.
    pub cipher_suite: HpkeSymmetricCipherSuite,

    /// The selected ECH configuration identifier.
    pub config_id: u8,

    /// The HPKE encapsulated key encoded as lowercase hexadecimal.
    ///
    /// This can be empty in a ClientHelloOuter sent after HelloRetryRequest.
    pub enc: HexBytes,

    /// The encrypted EncodedClientHelloInner bytes encoded as lowercase hexadecimal.
    ///
    /// Its decoded byte length is recorded in `payload_length`.
    pub payload: HexBytes,

    /// The encoded `uint16` length of the encrypted payload in bytes.
    ///
    /// This is retained explicitly because `payload` is exposed as hexadecimal text.
    pub payload_length: u16,
}

impl<'de> Deserialize<'de> for ECHClientHelloOuter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ECHClientHelloOuterRepr::deserialize(deserializer)?;
        if repr.enc.len() > usize::from(u16::MAX) {
            return Err(de::Error::custom(format_args!(
                "ECH encapsulated key exceeds 65535 bytes: {}",
                repr.enc.len(),
            )));
        }
        let payload_length = u16::try_from(repr.payload.len()).map_err(|_| {
            de::Error::custom(format_args!(
                "ECH payload exceeds 65535 bytes: {}",
                repr.payload.len(),
            ))
        })?;
        if payload_length == 0 {
            return Err(de::Error::custom("ECH outer payload must not be empty"));
        }
        if payload_length != repr.payload_length {
            return Err(de::Error::custom(format_args!(
                "ECH payload length is {}, but payload_length is {}",
                payload_length, repr.payload_length,
            )));
        }

        Ok(Self {
            cipher_suite: repr.cipher_suite,
            config_id: repr.config_id,
            enc: repr.enc,
            payload: repr.payload,
            payload_length: repr.payload_length,
        })
    }
}

/// Deserialization shape used to validate ECH vector lengths.
#[derive(Deserialize)]
struct ECHClientHelloOuterRepr {
    /// Saved HPKE cipher suite.
    cipher_suite: HpkeSymmetricCipherSuite,

    /// Saved ECH configuration identifier.
    config_id: u8,

    /// Saved HPKE encapsulated key bytes.
    enc: HexBytes,

    /// Saved encrypted ClientHelloInner bytes.
    payload: HexBytes,

    /// Saved payload byte length.
    payload_length: u16,
}

/// The HPKE KDF and AEAD pair selected for ECH encryption.
///
/// See [RFC 9849, Section 4](https://www.rfc-editor.org/rfc/rfc9849.html#section-4) and
/// [RFC 9180, Section 7.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct HpkeSymmetricCipherSuite {
    /// The HPKE key derivation function identifier.
    pub kdf_id: KeyDerivationFunction,

    /// The HPKE authenticated-encryption algorithm identifier.
    pub aead_id: AuthenticatedEncryptionWithAssociatedData,
}

/// An ephemeral key share offered by the client.
///
/// Each item retains the named-group ID and name. Non-GREASE items serialize their opaque key
/// exchange bytes under `value`; GREASE items omit those arbitrary payload bytes.
///
/// See [RFC 9846, Section 4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct KeyShare {
    /// The 16-bit named-group identifier observed on the wire.
    pub id: u16,

    /// The registered group name, `GREASE`, or `Unknown`.
    pub name: Box<str>,

    /// The opaque key exchange bytes encoded as lowercase hexadecimal.
    ///
    /// GREASE key exchange bytes can contain any value and are therefore omitted.
    /// See [RFC 8701, Section 3](https://www.rfc-editor.org/rfc/rfc8701.html#section-3).
    #[serde(rename = "value", skip_serializing_if = "Option::is_none")]
    pub key_exchange: Option<HexBytes>,
}

impl KeyShare {
    fn from_wire(id: u16, key_exchange: Vec<u8>) -> Self {
        let group = NamedGroup::from(id);
        let key_exchange = (!group.is_grease()).then(|| HexBytes::from(key_exchange));

        Self {
            id: group.id,
            name: group.name,
            key_exchange,
        }
    }
}

impl<'de> Deserialize<'de> for KeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = KeyShareRepr::deserialize(deserializer)?;
        let id = repr.id;
        let group = NamedGroup::from_serialized_parts(id, repr.name).map_err(|expected| {
            de::Error::custom(format_args!(
                "TLS key share group {id:#06x} has name {expected:?}, not the saved name",
            ))
        })?;

        match (group.is_grease(), repr.key_exchange) {
            (true, Some(_)) => Err(de::Error::custom(
                "GREASE key shares must omit key exchange bytes",
            )),
            (false, None) => Err(de::Error::custom(
                "non-GREASE key shares require key exchange bytes",
            )),
            (false, Some(key_exchange))
                if key_exchange.is_empty() || key_exchange.len() > usize::from(u16::MAX) =>
            {
                Err(de::Error::custom(
                    "non-GREASE key shares require 1 to 65535 key exchange bytes",
                ))
            }
            (_, key_exchange) => Ok(Self {
                id: group.id,
                name: group.name,
                key_exchange,
            }),
        }
    }
}

/// Deserialization shape used to validate a saved key-share ID, name, and payload.
#[derive(Deserialize)]
struct KeyShareRepr {
    /// The numeric named-group identifier stored in JSON.
    id: u16,

    /// The human-readable group name stored alongside the identifier.
    name: Box<str>,

    /// The optional key exchange bytes stored under the public `value` key.
    #[serde(rename = "value")]
    key_exchange: Option<HexBytes>,
}

/// Pre-shared-key key exchange modes offered by the client.
///
/// See [RFC 9846, Section 4.3.9](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct PskKeyExchangeModes {
    /// Modes in client preference order.
    pub ke_modes: Vec<PskKeyExchangeMode>,
}

/// A certificate-extension filter from the ClientHello `oid_filters` extension.
///
/// See [RFC 9846, Section 4.3.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct OidFilter {
    /// The DER-encoded certificate extension OID, represented as lowercase hexadecimal.
    pub cert_ext_oid: HexBytes,

    /// The required certificate extension value, represented as lowercase hexadecimal.
    pub cert_ext_val: HexBytes,
}

impl<'de> Deserialize<'de> for OidFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = OidFilterRepr::deserialize(deserializer)?;
        if repr.cert_ext_oid.is_empty() || repr.cert_ext_oid.len() > usize::from(u8::MAX) {
            return Err(de::Error::custom(format_args!(
                "certificate extension OID must contain 1 to 255 bytes, got {}",
                repr.cert_ext_oid.len(),
            )));
        }
        if repr.cert_ext_val.len() > usize::from(u16::MAX) {
            return Err(de::Error::custom(format_args!(
                "certificate extension value exceeds 65535 bytes: {}",
                repr.cert_ext_val.len(),
            )));
        }

        Ok(Self {
            cert_ext_oid: repr.cert_ext_oid,
            cert_ext_val: repr.cert_ext_val,
        })
    }
}

/// Deserialization shape used to validate an OID filter.
#[derive(Deserialize)]
struct OidFilterRepr {
    /// Saved DER-encoded certificate extension OID.
    cert_ext_oid: HexBytes,

    /// Saved required certificate extension value.
    cert_ext_val: HexBytes,
}

/// The ClientHello layer at which binary parsing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientHelloParseStage {
    /// TLS record framing is incomplete or invalid.
    TlsRecord,

    /// A complete record does not contain a valid handshake message.
    RecordMessages,

    /// The first handshake message is not a ClientHello.
    ClientHello,

    /// The ClientHello extension vector is malformed.
    Extensions,

    /// The OCSP status request payload is malformed.
    StatusRequest,

    /// The ALPN protocol-name list is malformed.
    ApplicationLayerProtocolNegotiation,

    /// An Application-Layer Protocol Settings protocol-name list is malformed.
    ApplicationSettings,

    /// The delegated-credentials payload is malformed.
    DelegatedCredentials,

    /// The certificate-compression payload is malformed.
    CertificateCompression,

    /// The Encrypted ClientHello payload is malformed.
    EncryptedClientHello,

    /// The key-share vector is malformed.
    KeyShare,
}

/// A structured TLS ClientHello parsing failure.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("failed to parse TLS ClientHello at {stage:?}")]
pub struct ClientHelloParseError {
    /// The layer or extension parser that rejected the input.
    pub stage: ClientHelloParseStage,

    /// The extension type involved in the failure, when applicable.
    pub extension_id: Option<u16>,

    /// The extension payload length observed on the wire, when applicable.
    pub payload_len: Option<usize>,
}

impl ClientHelloParseError {
    const fn new(stage: ClientHelloParseStage) -> Self {
        Self {
            stage,
            extension_id: None,
            payload_len: None,
        }
    }

    const fn extension(
        stage: ClientHelloParseStage,
        extension_id: u16,
        payload_len: usize,
    ) -> Self {
        Self {
            stage,
            extension_id: Some(extension_id),
            payload_len: Some(payload_len),
        }
    }
}

impl ClientHello {
    /// Records the protocol version selected after the handshake.
    ///
    /// Passing `None` clears a previously recorded negotiated version.
    pub fn set_tls_version_negotiated(&mut self, version: Option<TlsVersion>) {
        self.tls_version_negotiated = version;
    }

    /// Parses the first ClientHello from one or more complete TLS records.
    ///
    /// Unknown cipher-suite identifiers and GREASE values are preserved in the cipher_suites list.
    pub fn parse(buf: &[u8]) -> Result<Self, ClientHelloParseError> {
        match Self::parse_inner(buf) {
            Ok(client_hello) => {
                tracing::debug!(
                    capture_len = buf.len(),
                    legacy_version = %client_hello.tls_version,
                    cipher_count = client_hello.cipher_suites.len(),
                    extension_count = client_hello.extensions.len(),
                    "parsed TLS ClientHello",
                );
                Ok(client_hello)
            }
            Err(error) => {
                tracing::debug!(
                    capture_len = buf.len(),
                    stage = ?error.stage,
                    extension_id = ?error.extension_id,
                    payload_len = ?error.payload_len,
                    "failed to parse TLS ClientHello",
                );
                Err(error)
            }
        }
    }

    fn parse_inner(buf: &[u8]) -> Result<Self, ClientHelloParseError> {
        let captured = capture_client_hello(buf)?
            .ok_or(ClientHelloParseError::new(ClientHelloParseStage::TlsRecord))?;
        Self::parse_handshake(captured.handshake.as_ref())
    }

    fn parse_handshake(handshake: &[u8]) -> Result<Self, ClientHelloParseError> {
        let body = handshake
            .get(TLS_HANDSHAKE_HEADER_LEN..)
            .ok_or(ClientHelloParseError::new(
                ClientHelloParseStage::RecordMessages,
            ))?;
        let (remaining, message) = tls_parser::parse_tls_handshake_msg_client_hello(body)
            .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::RecordMessages))?;
        if !remaining.is_empty() {
            return Err(ClientHelloParseError::new(
                ClientHelloParseStage::RecordMessages,
            ));
        }
        let TlsMessageHandshake::ClientHello(payload) = message else {
            return Err(ClientHelloParseError::new(
                ClientHelloParseStage::ClientHello,
            ));
        };

        let cipher_suites = payload
            .ciphers
            .iter()
            .map(|cipher| TlsCipherSuite::from(cipher.0))
            .collect();

        let mut client_hello = ClientHello {
            tls_version: TlsVersion::from(payload.version.0),
            tls_version_negotiated: None,
            cipher_suites,
            client_random: HexBytes::from(payload.random),
            session_id: payload.session_id.map(HexBytes::from),
            compression_algorithms: payload
                .comp
                .iter()
                .map(|c| CompressionAlgorithm::from(c.0))
                .collect(),
            extensions: Vec::with_capacity(5),
        };

        let Some(extension_bytes) = payload.ext else {
            return Ok(client_hello);
        };
        let (remaining, ext_list) = tls_parser::parse_tls_client_hello_extensions(extension_bytes)
            .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::Extensions))?;
        if !remaining.is_empty() {
            return Err(ClientHelloParseError::new(
                ClientHelloParseStage::Extensions,
            ));
        }

        let mut raw_extensions = extension_bytes;
        for ext in ext_list {
            let (remaining, (extension_id, extension_payload)) =
                parser::parse_tls_extension_frame(raw_extensions)
                    .map_err(|_| ClientHelloParseError::new(ClientHelloParseStage::Extensions))?;
            raw_extensions = remaining;

            tracing::trace!(extension_id, "decoding TLS ClientHello extension");

            match ext {
                tls_parser::TlsExtension::SNI(name) => {
                    client_hello.extensions.push(TlsExtension::ServerName {
                        value: extension_id,
                        data: name
                            .into_iter()
                            .map(|n| n.1)
                            .map(|n| String::from_utf8_lossy(n).into_owned().into_boxed_str())
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::EllipticCurves(groups) => {
                    client_hello.extensions.push(TlsExtension::SupportedGroups {
                        value: extension_id,
                        data: groups
                            .into_iter()
                            .map(|group| NamedGroup::from(group.0))
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::SupportedVersions(versions) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SupportedVersions {
                            value: extension_id,
                            data: versions
                                .into_iter()
                                .map(|version| TlsVersion::from(version.0))
                                .collect(),
                        });
                }
                tls_parser::TlsExtension::SessionTicket(data) => {
                    client_hello.extensions.push(TlsExtension::SessionTicket {
                        value: extension_id,
                        data: HexBytes::from(data),
                    });
                }
                tls_parser::TlsExtension::SignatureAlgorithms(algorithms) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SignatureAlgorithms {
                            value: extension_id,
                            data: algorithms
                                .into_iter()
                                .map(SignatureAlgorithm::from)
                                .collect(),
                        });
                }
                tls_parser::TlsExtension::StatusRequest(data) => {
                    let Some((status, data)) = data else {
                        return Err(ClientHelloParseError::extension(
                            ClientHelloParseStage::StatusRequest,
                            extension_id,
                            extension_payload.len(),
                        ));
                    };

                    let certificate_status_type = CertificateStatusType::from(status.0);
                    if certificate_status_type != CertificateStatusType::OCSP {
                        return Err(ClientHelloParseError::extension(
                            ClientHelloParseStage::StatusRequest,
                            extension_id,
                            extension_payload.len(),
                        ));
                    }

                    let (_, (responder_id_list, request_extensions)) =
                        parser::parse_ocsp_status_request_lengths(data).map_err(|_| {
                            ClientHelloParseError::extension(
                                ClientHelloParseStage::StatusRequest,
                                extension_id,
                                extension_payload.len(),
                            )
                        })?;
                    client_hello.extensions.push(TlsExtension::StatusRequest {
                        value: extension_id,
                        data: StatusRequest {
                            certificate_status_type,
                            responder_id_list,
                            request_extensions,
                        },
                    });
                }
                tls_parser::TlsExtension::EcPointFormats(formats) => {
                    client_hello.extensions.push(TlsExtension::EcPointFormats {
                        value: extension_id,
                        data: formats.iter().map(|f| ECPointFormat::from(*f)).collect(),
                    });
                }
                tls_parser::TlsExtension::ALPN(_) => {
                    let (_, protocols) =
                        parser::parse_alpn_packet(extension_payload).map_err(|_| {
                            ClientHelloParseError::extension(
                                ClientHelloParseStage::ApplicationLayerProtocolNegotiation,
                                extension_id,
                                extension_payload.len(),
                            )
                        })?;

                    client_hello.extensions.push(
                        TlsExtension::ApplicationLayerProtocolNegotiation {
                            value: extension_id,
                            data: protocols,
                        },
                    );
                }
                tls_parser::TlsExtension::SignedCertificateTimestamp(timestamps) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::SignedCertificateTimestamp {
                            value: extension_id,
                            data: timestamps.map(HexBytes::from),
                        });
                }
                tls_parser::TlsExtension::RenegotiationInfo(_) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::RenegotiationInfo {
                            value: extension_id,
                        });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(34), algorithms) => {
                    let extension =
                        parser::parse_tls_extension_delegated_credentials(extension_id, algorithms)
                            .map_err(|_| {
                                ClientHelloParseError::extension(
                                    ClientHelloParseStage::DelegatedCredentials,
                                    extension_id,
                                    algorithms.len(),
                                )
                            })?
                            .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::RecordSizeLimit(limit) => {
                    client_hello.extensions.push(TlsExtension::RecordSizeLimit {
                        value: extension_id,
                        data: limit,
                    });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(27), data) => {
                    let extension =
                        parser::parse_tls_extension_certificate_compression(extension_id, data)
                            .map_err(|_| {
                                ClientHelloParseError::extension(
                                    ClientHelloParseStage::CertificateCompression,
                                    extension_id,
                                    data.len(),
                                )
                            })?
                            .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(65037), data) => {
                    let extension = parser::parse_tls_extension_ech(extension_id, data)
                        .map_err(|_| {
                            ClientHelloParseError::extension(
                                ClientHelloParseStage::EncryptedClientHello,
                                extension_id,
                                data.len(),
                            )
                        })?
                        .1;
                    client_hello.extensions.push(extension);
                }
                tls_parser::TlsExtension::Padding(padding) => {
                    client_hello.extensions.push(TlsExtension::Padding {
                        value: extension_id,
                        data: HexBytes::from(padding),
                    });
                }
                tls_parser::TlsExtension::KeyShare(data) => {
                    client_hello.extensions.push(TlsExtension::KeyShare {
                        value: extension_id,
                        data: parser::parse_key_share(data)
                            .ok_or(ClientHelloParseError::extension(
                                ClientHelloParseStage::KeyShare,
                                extension_id,
                                data.len(),
                            ))?
                            .into_iter()
                            .map(|(group, key_exchange)| KeyShare::from_wire(group, key_exchange))
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::PskExchangeModes(data) => {
                    client_hello
                        .extensions
                        .push(TlsExtension::PskKeyExchangeModes {
                            value: extension_id,
                            data: PskKeyExchangeModes {
                                ke_modes: data.into_iter().map(PskKeyExchangeMode::from).collect(),
                            },
                        });
                }
                tls_parser::TlsExtension::PreSharedKey(data) => {
                    client_hello.extensions.push(TlsExtension::PreSharedKey {
                        value: extension_id,
                        data: HexBytes::from(data),
                    });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(17513), protocols) => {
                    let (_, protocols) = parser::parse_alps_packet(protocols).map_err(|_| {
                        ClientHelloParseError::extension(
                            ClientHelloParseStage::ApplicationSettings,
                            extension_id,
                            protocols.len(),
                        )
                    })?;

                    client_hello
                        .extensions
                        .push(TlsExtension::ApplicationSettingsOld {
                            value: extension_id,
                            data: protocols,
                        });
                }
                tls_parser::TlsExtension::Unknown(TlsExtensionType(17613), protocols) => {
                    let (_, protocols) = parser::parse_alps_packet(protocols).map_err(|_| {
                        ClientHelloParseError::extension(
                            ClientHelloParseStage::ApplicationSettings,
                            extension_id,
                            protocols.len(),
                        )
                    })?;

                    client_hello
                        .extensions
                        .push(TlsExtension::ApplicationSettings {
                            value: extension_id,
                            data: protocols,
                        });
                }
                tls_parser::TlsExtension::ExtendedMasterSecret => {
                    client_hello
                        .extensions
                        .push(TlsExtension::ExtendedMasterSecret {
                            value: extension_id,
                        });
                }
                tls_parser::TlsExtension::Grease(..) => {
                    client_hello.extensions.push(TlsExtension::Grease {
                        value: extension_id,
                    });
                }

                tls_parser::TlsExtension::MaxFragmentLength(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(HexBytes::from(data.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::KeyShareOld(items) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(HexBytes::from(items)),
                    });
                }
                tls_parser::TlsExtension::EarlyData(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: data.map(|value| HexBytes::from(value.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::Cookie(items) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(HexBytes::from(items)),
                    });
                }
                tls_parser::TlsExtension::Heartbeat(data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(HexBytes::from(data.to_be_bytes())),
                    });
                }
                tls_parser::TlsExtension::EncryptThenMac => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::OidFilters(oid_filters) => {
                    client_hello.extensions.push(TlsExtension::OidFilters {
                        value: extension_id,
                        data: oid_filters
                            .into_iter()
                            .map(|f| OidFilter {
                                cert_ext_oid: HexBytes::from(f.cert_ext_oid),
                                cert_ext_val: HexBytes::from(f.cert_ext_val),
                            })
                            .collect(),
                    });
                }
                tls_parser::TlsExtension::PostHandshakeAuth => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::NextProtocolNegotiation => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: None,
                    });
                }
                tls_parser::TlsExtension::EncryptedServerName {
                    ciphersuite,
                    group,
                    key_share,
                    record_digest,
                    encrypted_sni,
                } => {
                    client_hello
                        .extensions
                        .push(TlsExtension::EncryptedServerName {
                            value: extension_id,
                            ciphersuite: tls_parser::TlsCipherSuite::from_id(ciphersuite.0)
                                .map(|c| c.name)
                                .unwrap_or("Unknown")
                                .into(),
                            group: NamedGroup::from(group.0),
                            key_share: HexBytes::from(key_share),
                            record_digest: HexBytes::from(record_digest),
                            encrypted_sni: HexBytes::from(encrypted_sni),
                        });
                }

                tls_parser::TlsExtension::Unknown(_, data) => {
                    client_hello.extensions.push(TlsExtension::Opaque {
                        value: extension_id,
                        data: Some(HexBytes::from(data)),
                    });
                }
            }
        }
        if !raw_extensions.is_empty() {
            return Err(ClientHelloParseError::new(
                ClientHelloParseStage::Extensions,
            ));
        }

        Ok(client_hello)
    }

    /// Calculates the JA4 fingerprint and its unhashed source form.
    pub fn ja4(&self) -> Ja4Fingerprint {
        Ja4Fingerprint::from(self)
    }

    /// Calculates the JA3 source string and MD5 digest.
    pub fn ja3(&self) -> Ja3Fingerprint {
        Ja3Fingerprint::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientHello, ClientHelloBuffer, ClientHelloParseStage, ECHClientHelloOuter, HexBytes,
        KeyShare, ProtocolName, StatusRequest, TlsCipherSuite, TlsExtension,
    };
    use crate::tls::{CompressionAlgorithm, NamedGroup, TlsVersion};

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).unwrap();
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn client_hello_handshake(extensions: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        if let Some(extensions) = extensions {
            let length = u16::try_from(extensions.len()).unwrap();
            body.extend_from_slice(&length.to_be_bytes());
            body.extend_from_slice(extensions);
        }

        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut handshake = vec![1, length[1], length[2], length[3]];
        handshake.extend_from_slice(&body);
        handshake
    }

    #[test]
    fn tls_cipher_suite_resolves_and_validates_ids_and_names() {
        let known = TlsCipherSuite::from_id(0x1301);
        assert_eq!(known.id, 0x1301);
        assert_eq!(known.name.as_ref(), "TLS_AES_128_GCM_SHA256");
        assert!(!known.is_grease());

        assert_eq!(
            TlsCipherSuite::from_name("TLS_AES_128_GCM_SHA256"),
            Some(known)
        );
        assert!(TlsCipherSuite::from_name("GREASE").is_none());

        let grease = TlsCipherSuite::from_id(0x0a0a);
        assert_eq!(grease.name.as_ref(), "GREASE");
        assert!(grease.is_grease());

        let unknown = TlsCipherSuite::from_id(0xffff);
        assert_eq!(unknown.name.as_ref(), "Unknown");
        assert!(!unknown.is_grease());

        let error = serde_json::from_value::<TlsCipherSuite>(serde_json::json!({
            "id": 0x1301,
            "name": "TLS_AES_256_GCM_SHA384"
        }))
        .expect_err("mismatched cipher-suite name must fail");
        assert!(
            error
                .to_string()
                .contains("has name \"TLS_AES_128_GCM_SHA256\""),
            "{error}"
        );
    }

    #[test]
    fn hex_bytes_serialize_canonically_and_reject_invalid_text() {
        let bytes = HexBytes::from([0x00, 0xab, 0xff]);
        let json = serde_json::to_value(&bytes).expect("hex bytes serialize");

        assert_eq!(json, serde_json::json!("00abff"));
        assert_eq!(
            serde_json::from_value::<HexBytes>(json).expect("hex bytes deserialize"),
            bytes
        );

        for invalid in ["0", "00AB", "00gg"] {
            assert!(serde_json::from_value::<HexBytes>(serde_json::json!(invalid)).is_err());
        }
    }

    #[test]
    fn protocol_names_roundtrip_text_and_opaque_bytes() {
        let h2 = ProtocolName::try_from("h2").unwrap();
        let h2_json = serde_json::to_value(&h2).expect("UTF-8 protocol name serializes");
        assert_eq!(h2_json, serde_json::json!("h2"));
        assert_eq!(serde_json::from_value::<ProtocolName>(h2_json).unwrap(), h2);

        let opaque = ProtocolName::try_from(&[0xff, b'x'][..]).unwrap();
        let opaque_json = serde_json::to_value(&opaque).expect("opaque protocol name serializes");
        assert_eq!(opaque_json, serde_json::json!({"hex": "ff78"}));
        assert_eq!(
            serde_json::from_value::<ProtocolName>(opaque_json).unwrap(),
            opaque
        );

        for invalid in [
            serde_json::json!(""),
            serde_json::json!({"hex": ""}),
            serde_json::json!({"hex": "FF"}),
            serde_json::json!("a".repeat(256)),
        ] {
            assert!(serde_json::from_value::<ProtocolName>(invalid).is_err());
        }
    }

    #[test]
    fn ech_json_validates_payload_length() {
        let valid = serde_json::json!({
            "cipher_suite": {
                "kdf_id": "HKDF_SHA256",
                "aead_id": "AES_128_GCM"
            },
            "config_id": 7,
            "enc": "",
            "payload": "aa",
            "payload_length": 1
        });
        let outer = serde_json::from_value::<ECHClientHelloOuter>(valid.clone())
            .expect("valid ECH outer deserializes");
        assert_eq!(outer.payload.as_bytes(), [0xaa]);

        let mut mismatch = valid.clone();
        mismatch["payload_length"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ECHClientHelloOuter>(mismatch).is_err());

        let mut empty = valid;
        empty["payload"] = serde_json::json!("");
        empty["payload_length"] = serde_json::json!(0);
        assert!(serde_json::from_value::<ECHClientHelloOuter>(empty).is_err());
    }

    #[test]
    fn key_shares_serialize_id_name_and_optional_exchange_bytes() {
        let grease = KeyShare::from_wire(0x3a3a, vec![0x00]);

        assert_eq!(grease.id, 0x3a3a);
        assert_eq!(grease.name.as_ref(), "GREASE");
        assert_eq!(grease.key_exchange, None);

        let grease_json = serde_json::to_value(&grease).expect("GREASE KeyShare serializes");
        assert_eq!(
            grease_json,
            serde_json::json!({
                "id": 0x3a3a,
                "name": "GREASE"
            })
        );

        let x25519 = KeyShare::from_wire(29, vec![0x01, 0x02]);
        let x25519_json = serde_json::to_value(&x25519).expect("x25519 KeyShare serializes");
        assert_eq!(
            x25519_json,
            serde_json::json!({
                "id": 29,
                "name": "x25519",
                "value": "0102"
            })
        );

        assert_eq!(
            serde_json::from_value::<KeyShare>(grease_json).expect("GREASE KeyShare deserializes"),
            grease
        );
        assert_eq!(
            serde_json::from_value::<KeyShare>(x25519_json).expect("x25519 KeyShare deserializes"),
            x25519
        );

        assert!(serde_json::from_value::<KeyShare>(serde_json::json!({
            "id": 29,
            "name": "x25519"
        }))
        .is_err());
        assert!(serde_json::from_value::<KeyShare>(serde_json::json!({
            "id": 29,
            "name": "x25519",
            "value": ""
        }))
        .is_err());
        assert!(serde_json::from_value::<KeyShare>(serde_json::json!({
            "id": 0x3a3a,
            "name": "GREASE",
            "value": "00"
        }))
        .is_err());
    }

    #[test]
    fn malformed_client_hello_reports_parse_stages() {
        let Err(record_error) = ClientHello::parse(&[]) else {
            panic!("expected malformed TLS record to fail");
        };
        assert_eq!(record_error.stage, ClientHelloParseStage::TlsRecord);
        assert_eq!(record_error.extension_id, None);
        assert_eq!(record_error.payload_len, None);

        let Err(message_error) = ClientHello::parse(&[0; 5]) else {
            panic!("expected malformed TLS messages to fail");
        };
        assert_eq!(message_error.stage, ClientHelloParseStage::RecordMessages);
        assert_eq!(message_error.extension_id, None);
        assert_eq!(message_error.payload_len, None);
    }

    #[test]
    fn client_hello_buffer_uses_requested_initial_capacity() {
        let mut buffer = ClientHelloBuffer::with_capacity(64);

        assert!(buffer.is_empty());
        assert!(buffer.buf.capacity() >= 64);
        assert_eq!(buffer.extend(&[1, 2, 3]), 3);
        assert_eq!(buffer.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn client_hello_buffer_distinguishes_incomplete_and_malformed_records() {
        let mut buffer = ClientHelloBuffer::from(vec![0; 4]);

        assert!(buffer.try_parse().unwrap().is_none());
        buffer.extend(&[0]);

        let error = buffer.try_parse().unwrap_err();
        assert_eq!(error.stage, ClientHelloParseStage::RecordMessages);
        assert!(buffer.is_invalid());
        assert_eq!(buffer.extend(&[1, 2, 3]), 0);
        assert_eq!(buffer.as_bytes(), &[0; 5]);

        let borrowed = ClientHelloBuffer::from(&[1, 2, 3][..]);
        assert_eq!(borrowed.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn client_hello_buffer_reassembles_records_without_an_extension_block() {
        let handshake = client_hello_handshake(None);
        let first = tls_record(&handshake[..13]);
        let second = tls_record(&handshake[13..]);
        let extra = [0x17, 0x03, 0x03, 0, 1, 0];

        let mut buffer = ClientHelloBuffer::new();
        assert_eq!(buffer.extend(&first), first.len());
        assert!(!buffer.is_complete());
        assert!(buffer.try_parse().unwrap().is_none());

        let mut tail = second.clone();
        tail.extend_from_slice(&extra);
        assert_eq!(buffer.extend(&tail), second.len());
        assert!(buffer.is_complete());
        assert_eq!(buffer.len(), first.len() + second.len());
        assert_eq!(buffer.extend(&extra), 0);

        let client_hello = buffer.try_parse().unwrap().unwrap();
        assert_eq!(client_hello.cipher_suites[0].id, 0x1301);
        assert!(client_hello.extensions.is_empty());
        assert_eq!(buffer.parse().unwrap(), client_hello);
    }

    #[test]
    fn client_hello_buffer_from_bytes_discards_following_records() {
        let expected = tls_record(&client_hello_handshake(None));
        let mut capture = expected.clone();
        capture.extend_from_slice(&[0x17, 0x03, 0x03, 0, 1, 0]);

        let buffer = ClientHelloBuffer::from(capture);

        assert!(buffer.is_complete());
        assert_eq!(buffer.as_bytes(), expected);
    }

    #[test]
    fn client_hello_buffer_tracks_fragmented_records_incrementally() {
        let handshake = client_hello_handshake(None);
        let records = handshake.chunks(1).flat_map(tls_record).collect::<Vec<_>>();
        let mut buffer = ClientHelloBuffer::new();

        for (index, byte) in records.chunks(1).enumerate() {
            assert_eq!(buffer.extend(byte), 1);
            if index + 1 < records.len() {
                assert!(buffer.try_parse().unwrap().is_none());
            }
        }

        assert!(buffer.is_complete());
        assert!(!buffer.is_invalid());
        assert_eq!(buffer.capture.record_offset, records.len());

        let client_hello = buffer.try_parse().unwrap().unwrap();
        assert_eq!(client_hello.cipher_suites[0].id, 0x1301);
    }

    #[test]
    fn client_hello_rejects_an_unconsumed_extension_tail() {
        let handshake = client_hello_handshake(Some(&[0]));
        let error = ClientHello::parse(&tls_record(&handshake)).unwrap_err();

        assert_eq!(error.stage, ClientHelloParseStage::Extensions);
    }

    #[test]
    fn client_hello_reports_strict_extension_parse_stages() {
        let cases = [
            (
                &[0x00, 0x05, 0x00, 0x00][..],
                ClientHelloParseStage::StatusRequest,
                5,
                0,
            ),
            (
                &[0x00, 0x05, 0x00, 0x01, 0x02][..],
                ClientHelloParseStage::StatusRequest,
                5,
                1,
            ),
            (
                &[0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0x00][..],
                ClientHelloParseStage::ApplicationLayerProtocolNegotiation,
                16,
                3,
            ),
            (
                &[0x00, 0x10, 0x00, 0x06, 0x00, 0x03, 0x02, b'h', b'2', 0x00][..],
                ClientHelloParseStage::ApplicationLayerProtocolNegotiation,
                16,
                6,
            ),
            (
                &[0x44, 0xcd, 0x00, 0x02, 0x00, 0x00][..],
                ClientHelloParseStage::ApplicationSettings,
                17_613,
                2,
            ),
        ];

        for (extension, stage, extension_id, payload_len) in cases {
            let handshake = client_hello_handshake(Some(extension));
            let error = ClientHello::parse(&tls_record(&handshake)).unwrap_err();

            assert_eq!(error.stage, stage);
            assert_eq!(error.extension_id, Some(extension_id));
            assert_eq!(error.payload_len, Some(payload_len));
        }
    }

    #[test]
    fn status_request_deserialization_rejects_non_ocsp_metadata() {
        let valid = serde_json::json!({"certificate_status_type": "OCSP", "responder_id_list": 0, "request_extensions": 0});
        assert!(serde_json::from_value::<StatusRequest>(valid.clone()).is_ok());
        let mut unknown_type = valid.clone();
        unknown_type["certificate_status_type"] = serde_json::json!("Unknown (0x0002)");
        assert!(serde_json::from_value::<StatusRequest>(unknown_type).is_err());
        for responder_id_list in [1, 2] {
            let mut invalid_length = valid.clone();
            invalid_length["responder_id_list"] = serde_json::json!(responder_id_list);
            assert!(serde_json::from_value::<StatusRequest>(invalid_length).is_err());
        }
    }

    #[test]
    fn client_hello_buffer_enforces_the_capture_limit() {
        let mut buffer = ClientHelloBuffer::with_capture_limit(32);
        let input = vec![0; 48];

        assert_eq!(buffer.extend(&input), 32);
        assert_eq!(buffer.len(), 32);
        assert_eq!(buffer.capture_limit(), 32);
        assert!(buffer.is_full());
        assert_eq!(buffer.extend(&[1, 2, 3]), 0);

        let oversized = ClientHelloBuffer::from(&[0x16, 0x03, 0x03, 0x41, 0x01][..]);
        let error = oversized.try_parse().unwrap_err();
        assert_eq!(error.stage, ClientHelloParseStage::TlsRecord);
    }

    #[test]
    fn client_hello_json_roundtrip_preserves_fingerprints() {
        let client_hello = ClientHello {
            tls_version: TlsVersion::TLSv1_2,
            tls_version_negotiated: Some(TlsVersion::TLSv1_3),
            cipher_suites: vec![TlsCipherSuite::from(0x0a0a), TlsCipherSuite::from(0x1301)],
            client_random: HexBytes::from([0; 32]),
            session_id: None,
            compression_algorithms: vec![CompressionAlgorithm::Null],
            extensions: vec![
                TlsExtension::SupportedVersions {
                    value: 0x002b,
                    data: vec![TlsVersion::from(0x2a2a), TlsVersion::TLSv1_3],
                },
                TlsExtension::SupportedGroups {
                    value: 0x000a,
                    data: vec![NamedGroup::from(29), NamedGroup::from(0x4a4a)],
                },
            ],
        };
        let ja3 = client_hello.ja3();
        let ja4 = client_hello.ja4();
        let json = serde_json::to_value(&client_hello).expect("ClientHello serializes");

        assert_eq!(
            json["cipher_suites"],
            serde_json::json!([
                {
                    "id": 2570,
                    "name": "GREASE"
                },
                {
                    "id": 4865,
                    "name": "TLS_AES_128_GCM_SHA256"
                }
            ])
        );
        assert!(json.get("cipher_values").is_none());
        assert!(json.get("ciphers").is_none());
        let mut invalid_random = json.clone();
        invalid_random["client_random"] = serde_json::json!("00");
        assert!(serde_json::from_value::<ClientHello>(invalid_random).is_err());

        let mut empty_session_id = json.clone();
        empty_session_id["session_id"] = serde_json::json!("");
        assert!(serde_json::from_value::<ClientHello>(empty_session_id).is_err());

        let mut oversized_session_id = json.clone();
        oversized_session_id["session_id"] = serde_json::json!("00".repeat(33));
        assert!(serde_json::from_value::<ClientHello>(oversized_session_id).is_err());

        let mut legacy_json = json.clone();
        let legacy_object = legacy_json
            .as_object_mut()
            .expect("ClientHello serializes as an object");
        let cipher_suites = legacy_object
            .remove("cipher_suites")
            .expect("cipher_suites is present");
        legacy_object.insert("ciphers".to_owned(), cipher_suites);
        assert!(serde_json::from_value::<ClientHello>(legacy_json).is_err());

        let restored: ClientHello =
            serde_json::from_value(json.clone()).expect("ClientHello deserializes");
        assert_eq!(restored, client_hello);
        assert_eq!(restored.ja3(), ja3);
        assert_eq!(restored.ja4(), ja4);
        assert_eq!(
            serde_json::to_value(restored).expect("restored ClientHello serializes"),
            json
        );
    }

    #[test]
    fn tls_extensions_reject_variant_id_mismatches() {
        let wrong_known_id = serde_json::json!({
            "supported_versions": {"value": 0, "data": []}
        });
        let non_grease_id = serde_json::json!({
            "grease": {"value": 0}
        });
        let dedicated_opaque_id = serde_json::json!({
            "opaque": {"value": 43, "data": null}
        });

        assert!(serde_json::from_value::<TlsExtension>(wrong_known_id).is_err());
        assert!(serde_json::from_value::<TlsExtension>(non_grease_id).is_err());
        assert!(serde_json::from_value::<TlsExtension>(dedicated_opaque_id).is_err());

        let grease = serde_json::json!({"grease": {"value": 2570}});
        let opaque = serde_json::json!({"opaque": {"value": 1, "data": null}});
        assert!(serde_json::from_value::<TlsExtension>(grease).is_ok());
        assert!(serde_json::from_value::<TlsExtension>(opaque).is_ok());
    }
}
