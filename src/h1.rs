//! HTTP/1 request and response head parsing.
//!
//! The models in this module preserve field order, original field-name casing, and field-value
//! bytes. Message bodies are deliberately outside the parser's scope.

use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

mod parser;
mod wire_bytes;

pub use parser::{
    parse_request_head, parse_response_head, Http1HeadBuffer, Http1ParseError, Http1Parser,
    DEFAULT_HTTP1_HEADER_LIMIT, DEFAULT_HTTP1_HEAD_CAPACITY, DEFAULT_HTTP1_HEAD_LIMIT,
};

/// Whether an HTTP/1 parser expects a request or response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeadKind {
    /// A request line followed by request fields.
    Request,

    /// A status line followed by response fields.
    Response,
}

/// An owned HTTP/1 request or response head.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Http1Head {
    /// A parsed request head.
    Request(RequestHead),

    /// A parsed response head.
    Response(ResponseHead),
}

impl Http1Head {
    /// Returns the start-line category represented by this head.
    pub const fn kind(&self) -> HeadKind {
        match self {
            Self::Request(_) => HeadKind::Request,
            Self::Response(_) => HeadKind::Response,
        }
    }

    /// Returns the request head when this value contains one.
    pub const fn as_request(&self) -> Option<&RequestHead> {
        match self {
            Self::Request(request) => Some(request),
            Self::Response(_) => None,
        }
    }

    /// Returns the response head when this value contains one.
    pub const fn as_response(&self) -> Option<&ResponseHead> {
        match self {
            Self::Request(_) => None,
            Self::Response(response) => Some(response),
        }
    }

    /// Consumes this value and returns its request head, if present.
    pub fn into_request(self) -> Option<RequestHead> {
        match self {
            Self::Request(request) => Some(request),
            Self::Response(_) => None,
        }
    }

    /// Consumes this value and returns its response head, if present.
    pub fn into_response(self) -> Option<ResponseHead> {
        match self {
            Self::Request(_) => None,
            Self::Response(response) => Some(response),
        }
    }
}

/// An HTTP/1.x protocol version.
///
/// HTTP/1 uses a single decimal minor version on the wire. See
/// [RFC 9112, Section 2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u8);

impl Version {
    /// HTTP/1.0.
    pub const HTTP_10: Self = Self(0);

    /// HTTP/1.1.
    pub const HTTP_11: Self = Self(1);

    /// Creates an HTTP/1 version from its single decimal minor version digit.
    pub const fn from_minor(minor: u8) -> Option<Self> {
        if minor <= 9 {
            Some(Self(minor))
        } else {
            None
        }
    }

    /// Returns the minor version digit.
    pub const fn minor(self) -> u8 {
        self.0
    }

    fn parse(value: &str) -> Option<Self> {
        let minor = value.strip_prefix("HTTP/1.")?.as_bytes();
        if minor.len() != 1 {
            return None;
        }

        let digit = minor[0];
        digit
            .is_ascii_digit()
            .then(|| Self(digit.saturating_sub(b'0')))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HTTP/1.{}", self.0)
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Box::<str>::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| de::Error::custom(format_args!("invalid HTTP/1 version {value:?}")))
    }
}

/// One HTTP/1 field line, preserving its original position and name casing.
///
/// Field names are case-insensitive, but retaining their received spelling is useful for traffic
/// analysis. See [RFC 9110, Section 5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    /// The field name exactly as received, including its original casing.
    pub name: Box<str>,

    /// The parsed field value bytes.
    ///
    /// Valid UTF-8 is serialized as a JSON string. Other bytes use an object containing
    /// lowercase hexadecimal.
    #[serde(with = "wire_bytes")]
    pub value: Box<[u8]>,
}

impl HeaderField {
    /// Creates an owned field from its name and value.
    pub fn new(name: impl Into<Box<str>>, value: impl Into<Box<[u8]>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Returns the field value as UTF-8 when it contains valid text.
    pub fn value_as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

/// A parsed HTTP/1 request line and its ordered fields.
///
/// Request-line syntax is defined by
/// [RFC 9112, Section 3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHead {
    /// Number of wire bytes occupied by the start line, fields, and terminating empty line.
    pub head_length: usize,

    /// Request method exactly as received.
    pub method: Box<str>,

    /// Request target exactly as received.
    pub target: Box<str>,

    /// HTTP/1 protocol version from the request line.
    pub version: Version,

    /// Request fields in their original wire order.
    pub headers: Vec<HeaderField>,
}

/// A parsed HTTP/1 status line and its ordered fields.
///
/// Status-line syntax is defined by
/// [RFC 9112, Section 4](https://www.rfc-editor.org/rfc/rfc9112.html#section-4).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseHead {
    /// Number of wire bytes occupied by the status line, fields, and terminating empty line.
    pub head_length: usize,

    /// HTTP/1 protocol version from the status line.
    pub version: Version,

    /// Three-digit response status code.
    pub status_code: u16,

    /// Reason phrase bytes exactly as received, excluding its separator and line ending.
    ///
    /// An omitted reason phrase is represented by an empty slice. Valid UTF-8 is serialized as a
    /// JSON string; other bytes use an object containing lowercase hexadecimal.
    #[serde(with = "wire_bytes")]
    pub reason_phrase: Box<[u8]>,

    /// Response fields in their original wire order.
    pub headers: Vec<HeaderField>,
}

impl ResponseHead {
    /// Returns the reason phrase as UTF-8 when it contains valid text.
    pub fn reason_phrase_as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.reason_phrase).ok()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{HeaderField, Version};

    #[test]
    fn version_uses_the_wire_spelling_in_json() {
        assert_eq!(serde_json::to_value(Version::HTTP_11).unwrap(), "HTTP/1.1");
        assert_eq!(
            serde_json::from_value::<Version>(json!("HTTP/1.0")).unwrap(),
            Version::HTTP_10
        );
        assert!(serde_json::from_value::<Version>(json!("HTTP/2.0")).is_err());
        assert!(serde_json::from_value::<Version>(json!("HTTP/1.10")).is_err());
    }

    #[test]
    fn non_utf8_header_values_roundtrip_without_loss() {
        let field = HeaderField::new("X-Raw", [0xff, 0x00]);
        let json = serde_json::to_value(&field).unwrap();

        assert_eq!(json, json!({"name": "X-Raw", "value": {"hex": "ff00"}}));
        assert_eq!(serde_json::from_value::<HeaderField>(json).unwrap(), field);
    }
}
