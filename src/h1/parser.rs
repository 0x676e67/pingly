use super::{HeadKind, HeaderField, Http1Head, RequestHead, ResponseHead, Version};

/// Initial allocation used by [Http1HeadBuffer::new] and [Http1Parser::new].
pub const DEFAULT_HTTP1_HEAD_CAPACITY: usize = 4 * 1024;

/// Maximum request or response head size accepted by the default buffer and parser.
pub const DEFAULT_HTTP1_HEAD_LIMIT: usize = 64 * 1024;

/// Maximum number of fields accepted by the default buffer and parser.
pub const DEFAULT_HTTP1_HEADER_LIMIT: usize = 128;

/// Errors returned while parsing an HTTP/1 request or response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Http1ParseError {
    /// The head violates the HTTP/1 wire format.
    #[error("invalid HTTP/1 head: {0}")]
    InvalidMessage(#[source] httparse::Error),

    /// A complete head did not contain every required start-line component.
    #[error("incomplete HTTP/1 start line")]
    InvalidStartLine,

    /// The head exceeded the configured byte limit before it was complete.
    #[error("HTTP/1 head exceeds the configured {limit}-byte limit")]
    HeadTooLarge {
        /// Maximum accepted head size in bytes.
        limit: usize,
    },

    /// The head contained more fields than the configured limit.
    #[error("HTTP/1 head exceeds the configured {limit}-field limit")]
    TooManyHeaders {
        /// Maximum accepted number of fields.
        limit: usize,
    },

    /// A finite input ended before the head was complete.
    #[error("incomplete HTTP/1 input ({buffered_bytes} buffered bytes)")]
    IncompleteInput {
        /// Bytes retained because they do not yet form a complete head.
        buffered_bytes: usize,
    },

    /// More input was supplied after this parser completed a head.
    #[error("HTTP/1 parser has already completed a head")]
    AlreadyComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    Active,
    Complete,
    Invalid(Http1ParseError),
}

/// Incrementally captures one HTTP/1 request or response head without parsing its fields.
///
/// HTTP/1 messages consist of a start line, field lines, and an empty line. This type only finds
/// that boundary while bytes arrive; call [Http1HeadBuffer::parse] later to validate and own the
/// message data. See [RFC 9112, Section 2.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.1).
#[derive(Debug)]
pub struct Http1HeadBuffer {
    /// Whether the captured bytes represent a request or response head.
    kind: HeadKind,

    /// Bytes retained through the empty line ending the field section.
    buffer: Vec<u8>,

    /// Maximum number of bytes retained for one message head.
    head_limit: usize,

    /// Maximum number of fields accepted during delayed parsing.
    header_limit: usize,

    /// Earliest buffer position that has not yet been checked for a line ending.
    scan_offset: usize,

    /// Start of the current line in the retained buffer.
    line_start: usize,

    /// Whether a non-empty start line has been observed.
    saw_start_line: bool,

    /// Whether the empty line ending the field section has been captured.
    complete: bool,
}

impl Http1HeadBuffer {
    /// Creates a head buffer for the selected HTTP/1 head kind.
    pub fn new(kind: HeadKind) -> Self {
        Self::with_capacity(kind, DEFAULT_HTTP1_HEAD_CAPACITY)
    }

    /// Creates a buffer for an HTTP/1 request head.
    pub fn request() -> Self {
        Self::new(HeadKind::Request)
    }

    /// Creates a buffer for an HTTP/1 response head.
    pub fn response() -> Self {
        Self::new(HeadKind::Response)
    }

    /// Creates a head buffer with at least the requested initial capacity.
    ///
    /// Requesting more than [DEFAULT_HTTP1_HEAD_LIMIT] raises the head limit to the requested
    /// capacity.
    pub fn with_capacity(kind: HeadKind, capacity: usize) -> Self {
        Self::with_capacity_and_limits(
            kind,
            capacity,
            DEFAULT_HTTP1_HEAD_LIMIT.max(capacity),
            DEFAULT_HTTP1_HEADER_LIMIT,
        )
    }

    /// Creates a head buffer with custom byte and field-count limits.
    pub fn with_limits(kind: HeadKind, head_limit: usize, header_limit: usize) -> Self {
        Self::with_capacity_and_limits(
            kind,
            DEFAULT_HTTP1_HEAD_CAPACITY.min(head_limit),
            head_limit,
            header_limit,
        )
    }

    /// Creates a head buffer with explicit allocation, byte, and field-count limits.
    ///
    /// The effective head limit is never smaller than the requested initial capacity.
    pub fn with_capacity_and_limits(
        kind: HeadKind,
        capacity: usize,
        head_limit: usize,
        header_limit: usize,
    ) -> Self {
        let head_limit = head_limit.max(capacity);
        Self {
            kind,
            buffer: Vec::with_capacity(capacity),
            head_limit,
            header_limit,
            scan_offset: 0,
            line_start: 0,
            saw_start_line: false,
            complete: false,
        }
    }

    /// Returns the kind of head captured by this buffer.
    pub const fn kind(&self) -> HeadKind {
        self.kind
    }

    /// Returns the configured maximum head size in bytes.
    pub const fn head_limit(&self) -> usize {
        self.head_limit
    }

    /// Returns the configured maximum number of fields.
    pub const fn header_limit(&self) -> usize {
        self.header_limit
    }

    /// Returns the current allocation capacity.
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Returns the retained HTTP/1 head bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns the number of retained bytes.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether no bytes have been retained.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns whether the empty line ending the field section has been captured.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns whether the byte limit has been reached.
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.head_limit
    }

    /// Retains bytes through the first complete HTTP/1 head and returns the bytes consumed.
    ///
    /// A recipient may recognize a lone LF as a line ending and ignore a preceding CR. A server
    /// may also ignore leading empty lines before a request line. These robustness rules come from
    /// [RFC 9112, Section 2.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.2).
    pub fn extend(&mut self, data: &[u8]) -> usize {
        if self.complete || self.is_full() {
            return 0;
        }

        let initial_len = self.buffer.len();
        let accepted = data.len().min(self.head_limit.saturating_sub(initial_len));
        self.buffer.extend_from_slice(&data[..accepted]);

        for index in self.scan_offset..self.buffer.len() {
            if self.buffer[index] != b'\n' {
                continue;
            }

            let content_end = if index > self.line_start && self.buffer[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            let is_empty_line = content_end == self.line_start;
            let line_end = index.saturating_add(1);
            self.line_start = line_end;

            if is_empty_line && (self.saw_start_line || self.kind == HeadKind::Response) {
                self.buffer.truncate(line_end);
                self.scan_offset = line_end;
                self.complete = true;
                return self.buffer.len().saturating_sub(initial_len);
            }

            if !is_empty_line {
                self.saw_start_line = true;
            }
        }

        self.scan_offset = self.buffer.len();
        accepted
    }

    /// Parses the captured head when its terminating empty line is available.
    pub fn try_parse(&self) -> Result<Option<Http1Head>, Http1ParseError> {
        if self.complete {
            return parse_head(self.kind, &self.buffer, self.header_limit).map(Some);
        }

        if self.is_full() {
            return Err(Http1ParseError::HeadTooLarge {
                limit: self.head_limit,
            });
        }

        Ok(None)
    }

    /// Parses a complete captured head.
    pub fn parse(&self) -> Result<Http1Head, Http1ParseError> {
        self.try_parse()?.ok_or(Http1ParseError::IncompleteInput {
            buffered_bytes: self.buffer.len(),
        })
    }

    /// Drops captured bytes and framing state while retaining the allocation.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.scan_offset = 0;
        self.line_start = 0;
        self.saw_start_line = false;
        self.complete = false;
    }
}

/// Incrementally parses one HTTP/1 request or response head from arbitrary byte chunks.
///
/// Use [Http1HeadBuffer] when parsing should be deferred to another thread.
#[derive(Debug)]
pub struct Http1Parser {
    /// Raw head capture and framing state.
    buffer: Http1HeadBuffer,

    /// Current parsing lifecycle state.
    state: ParserState,
}

impl Http1Parser {
    /// Creates a parser for the selected HTTP/1 head kind.
    pub fn new(kind: HeadKind) -> Self {
        Self::from_buffer(Http1HeadBuffer::new(kind))
    }

    /// Creates a parser for an HTTP/1 request head.
    pub fn request() -> Self {
        Self::new(HeadKind::Request)
    }

    /// Creates a parser for an HTTP/1 response head.
    pub fn response() -> Self {
        Self::new(HeadKind::Response)
    }

    /// Creates a parser with at least the requested initial buffer capacity.
    ///
    /// Requesting more than [DEFAULT_HTTP1_HEAD_LIMIT] raises the head limit to the requested
    /// capacity.
    pub fn with_capacity(kind: HeadKind, capacity: usize) -> Self {
        Self::from_buffer(Http1HeadBuffer::with_capacity(kind, capacity))
    }

    /// Creates a parser with custom head-size and field-count limits.
    pub fn with_limits(kind: HeadKind, head_limit: usize, header_limit: usize) -> Self {
        Self::from_buffer(Http1HeadBuffer::with_limits(kind, head_limit, header_limit))
    }

    /// Creates a parser with explicit allocation, head-size, and field-count limits.
    ///
    /// The effective head limit is never smaller than the requested initial capacity.
    pub fn with_capacity_and_limits(
        kind: HeadKind,
        capacity: usize,
        head_limit: usize,
        header_limit: usize,
    ) -> Self {
        Self::from_buffer(Http1HeadBuffer::with_capacity_and_limits(
            kind,
            capacity,
            head_limit,
            header_limit,
        ))
    }

    /// Returns the kind of head accepted by this parser.
    pub const fn kind(&self) -> HeadKind {
        self.buffer.kind()
    }

    /// Returns the configured maximum head size in bytes.
    pub const fn head_limit(&self) -> usize {
        self.buffer.head_limit()
    }

    /// Returns the configured maximum number of fields.
    pub const fn header_limit(&self) -> usize {
        self.buffer.header_limit()
    }

    /// Returns bytes retained for the current head.
    ///
    /// After parsing completes, this is the exact head through its terminating empty line.
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer.as_bytes()
    }

    /// Returns the number of bytes retained for the current head.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether this parser has completed a head.
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, ParserState::Complete)
    }

    /// Returns whether this parser stopped after invalid input or a configured limit was reached.
    pub const fn is_invalid(&self) -> bool {
        matches!(self.state, ParserState::Invalid(_))
    }

    /// Appends one byte chunk and returns the head when it becomes complete.
    ///
    /// The chunk may stop inside the start line, a field line, or the terminating empty line.
    /// Field syntax follows
    /// [RFC 9112, Section 5](https://www.rfc-editor.org/rfc/rfc9112.html#section-5).
    pub fn push(&mut self, data: &[u8]) -> Result<Option<Http1Head>, Http1ParseError> {
        match self.state {
            ParserState::Active => {}
            ParserState::Complete => return Err(Http1ParseError::AlreadyComplete),
            ParserState::Invalid(error) => return Err(error),
        }

        self.buffer.extend(data);

        if self.buffer.is_complete() {
            match self.buffer.parse() {
                Ok(head) => {
                    self.state = ParserState::Complete;
                    return Ok(Some(head));
                }
                Err(error) => return Err(self.fail(error)),
            }
        }

        if self.buffer.is_full() {
            let error = Http1ParseError::HeadTooLarge {
                limit: self.buffer.head_limit(),
            };
            return Err(self.fail(error));
        }

        Ok(None)
    }

    /// Verifies that a finite input ended after a complete head.
    pub fn finish(&self) -> Result<(), Http1ParseError> {
        match self.state {
            ParserState::Complete => Ok(()),
            ParserState::Invalid(error) => Err(error),
            ParserState::Active => Err(Http1ParseError::IncompleteInput {
                buffered_bytes: self.buffer.len(),
            }),
        }
    }

    /// Drops buffered input and parsing state so this parser can be reused in the same mode.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.state = ParserState::Active;
    }

    fn from_buffer(buffer: Http1HeadBuffer) -> Self {
        Self {
            buffer,
            state: ParserState::Active,
        }
    }

    fn fail(&mut self, error: Http1ParseError) -> Http1ParseError {
        self.state = ParserState::Invalid(error);
        error
    }
}

/// Parses one complete HTTP/1 request head.
///
/// Use [Http1Parser] directly when bytes arrive incrementally.
pub fn parse_request_head(data: &[u8]) -> Result<RequestHead, Http1ParseError> {
    match parse_complete(Http1Parser::request(), data)? {
        Http1Head::Request(request) => Ok(request),
        Http1Head::Response(_) => Err(Http1ParseError::InvalidStartLine),
    }
}

/// Parses one complete HTTP/1 response head.
///
/// Use [Http1Parser] directly when bytes arrive incrementally.
pub fn parse_response_head(data: &[u8]) -> Result<ResponseHead, Http1ParseError> {
    match parse_complete(Http1Parser::response(), data)? {
        Http1Head::Request(_) => Err(Http1ParseError::InvalidStartLine),
        Http1Head::Response(response) => Ok(response),
    }
}

fn parse_complete(mut parser: Http1Parser, data: &[u8]) -> Result<Http1Head, Http1ParseError> {
    let head = parser.push(data)?.ok_or(Http1ParseError::IncompleteInput {
        buffered_bytes: parser.buffered_len(),
    })?;
    parser.finish()?;
    Ok(head)
}

fn parse_head(
    kind: HeadKind,
    data: &[u8],
    header_limit: usize,
) -> Result<Http1Head, Http1ParseError> {
    match kind {
        HeadKind::Request => parse_request(data, header_limit).map(Http1Head::Request),
        HeadKind::Response => parse_response(data, header_limit).map(Http1Head::Response),
    }
}

fn parse_request(data: &[u8], header_limit: usize) -> Result<RequestHead, Http1ParseError> {
    let mut header_storage = Vec::<httparse::Header<'_>>::with_capacity(header_limit);
    let mut request = httparse::Request::new(&mut []);
    let status = httparse::ParserConfig::default().parse_request_with_uninit_headers(
        &mut request,
        data,
        header_storage.spare_capacity_mut(),
    );
    let head_length = parse_status(status, header_limit)?;

    let method = request
        .method
        .ok_or(Http1ParseError::InvalidStartLine)?
        .into();
    let target = request
        .path
        .ok_or(Http1ParseError::InvalidStartLine)?
        .into();
    let version = request
        .version
        .and_then(Version::from_minor)
        .ok_or(Http1ParseError::InvalidStartLine)?;

    Ok(RequestHead {
        head_length,
        method,
        target,
        version,
        headers: own_headers(request.headers),
    })
}

fn parse_response(data: &[u8], header_limit: usize) -> Result<ResponseHead, Http1ParseError> {
    let mut header_storage = Vec::<httparse::Header<'_>>::with_capacity(header_limit);
    let mut response = httparse::Response::new(&mut []);
    let status = httparse::ParserConfig::default().parse_response_with_uninit_headers(
        &mut response,
        data,
        header_storage.spare_capacity_mut(),
    );
    let head_length = parse_status(status, header_limit)?;

    let version = response
        .version
        .and_then(Version::from_minor)
        .ok_or(Http1ParseError::InvalidStartLine)?;
    let status_code = response.code.ok_or(Http1ParseError::InvalidStartLine)?;
    let reason_phrase = response_reason(data)?;

    Ok(ResponseHead {
        head_length,
        version,
        status_code,
        reason_phrase,
        headers: own_headers(response.headers),
    })
}

fn response_reason(data: &[u8]) -> Result<Box<[u8]>, Http1ParseError> {
    let line_end = data
        .iter()
        .position(|byte| *byte == b'\r' || *byte == b'\n')
        .ok_or(Http1ParseError::InvalidStartLine)?;
    let status_line = &data[..line_end];
    let version_end = status_line
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(Http1ParseError::InvalidStartLine)?;
    let code_start = version_end
        .checked_add(1)
        .ok_or(Http1ParseError::InvalidStartLine)?;
    let code_end = code_start
        .checked_add(3)
        .ok_or(Http1ParseError::InvalidStartLine)?;
    let suffix = status_line
        .get(code_end..)
        .ok_or(Http1ParseError::InvalidStartLine)?;

    match suffix.split_first() {
        None => Ok(Vec::new().into_boxed_slice()),
        Some((separator, reason)) if *separator == b' ' => Ok(reason.into()),
        Some(_) => Err(Http1ParseError::InvalidStartLine),
    }
}

fn parse_status(
    status: Result<httparse::Status<usize>, httparse::Error>,
    header_limit: usize,
) -> Result<usize, Http1ParseError> {
    match status {
        Ok(httparse::Status::Complete(head_length)) => Ok(head_length),
        Ok(httparse::Status::Partial) => Err(Http1ParseError::InvalidStartLine),
        Err(httparse::Error::TooManyHeaders) => Err(Http1ParseError::TooManyHeaders {
            limit: header_limit,
        }),
        Err(error) => Err(Http1ParseError::InvalidMessage(error)),
    }
}

fn own_headers(headers: &[httparse::Header<'_>]) -> Vec<HeaderField> {
    headers
        .iter()
        .map(|header| HeaderField {
            name: header.name.into(),
            value: header.value.into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        parse_request_head, parse_response_head, HeadKind, Http1Head, Http1HeadBuffer,
        Http1ParseError, Http1Parser, DEFAULT_HTTP1_HEAD_LIMIT,
    };

    #[test]
    fn head_buffer_defers_validation_and_discards_body_bytes() {
        let mut buffer = Http1HeadBuffer::request();
        let head = b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\n";

        assert_eq!(
            buffer.extend(b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\nbody"),
            head.len()
        );
        assert!(buffer.is_complete());
        assert_eq!(buffer.as_bytes(), head);
        assert!(matches!(
            buffer.parse(),
            Err(Http1ParseError::InvalidMessage(_))
        ));
    }

    #[test]
    fn head_buffer_follows_rfc_line_ending_robustness_rules() {
        let wire = b"\r\nGET /lf HTTP/1.1\nHoSt: localhost\n\nbody";
        let expected = b"\r\nGET /lf HTTP/1.1\nHoSt: localhost\n\n";
        let mut buffer = Http1HeadBuffer::request();

        for chunk in wire.chunks(1) {
            buffer.extend(chunk);
        }

        assert!(buffer.is_complete());
        assert_eq!(buffer.as_bytes(), expected);

        let request = buffer.parse().unwrap().into_request().unwrap();
        assert_eq!(request.target.as_ref(), "/lf");
        assert_eq!(request.headers[0].name.as_ref(), "HoSt");
        assert_eq!(request.head_length, expected.len());
    }

    #[test]
    fn response_buffer_does_not_ignore_a_leading_empty_line() {
        let mut buffer = Http1HeadBuffer::response();

        assert_eq!(buffer.extend(b"\r\nHTTP/1.1 200 OK\r\n\r\n"), 2);
        assert!(buffer.is_complete());
        assert_eq!(buffer.as_bytes(), b"\r\n");
        assert_eq!(
            buffer.parse().unwrap_err(),
            Http1ParseError::InvalidStartLine
        );
    }

    #[test]
    fn head_buffer_leaves_bare_carriage_return_for_strict_validation() {
        let mut buffer = Http1HeadBuffer::request();
        buffer.extend(b"GET / HTTP/1.1\nX-Test: a\rb\n\n");

        assert!(buffer.is_complete());
        assert!(matches!(
            buffer.parse(),
            Err(Http1ParseError::InvalidMessage(_))
        ));
    }

    #[test]
    fn head_buffer_reports_an_incomplete_head_at_the_byte_limit() {
        let mut buffer = Http1HeadBuffer::with_limits(HeadKind::Request, 8, 16);

        assert_eq!(buffer.extend(b"GET / HTTP/1.1\r\n"), 8);
        assert!(buffer.is_full());
        assert_eq!(
            buffer.parse().unwrap_err(),
            Http1ParseError::HeadTooLarge { limit: 8 }
        );
    }

    #[test]
    fn request_parser_accepts_arbitrary_chunks_and_preserves_fields() {
        let wire = b"GET /search?q=rust HTTP/1.1\r\nHoSt: localhost\r\nuSeR-aGeNt: test\r\n\r\n";
        let mut parser = Http1Parser::request();
        let mut parsed = None;

        for chunk in wire.chunks(7) {
            if let Some(head) = parser.push(chunk).unwrap() {
                parsed = head.into_request();
            }
        }

        parser.finish().unwrap();
        let request = parsed.unwrap();
        assert_eq!(request.method.as_ref(), "GET");
        assert_eq!(request.target.as_ref(), "/search?q=rust");
        assert_eq!(request.headers[0].name.as_ref(), "HoSt");
        assert_eq!(request.headers[1].name.as_ref(), "uSeR-aGeNt");
        assert_eq!(request.headers[1].value.as_ref(), b"test");
        assert_eq!(request.head_length, wire.len());
        assert_eq!(parser.as_bytes(), wire);
    }

    #[test]
    fn response_parser_retains_status_and_reason_phrase() {
        let response = parse_response_head(
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nbody",
        )
        .unwrap();

        assert_eq!(response.status_code, 103);
        assert_eq!(response.reason_phrase_as_str(), Some("Early Hints"));
        assert_eq!(response.headers[0].name.as_ref(), "Link");
        assert_eq!(response.head_length, 61);
    }

    #[test]
    fn response_reason_phrase_roundtrips_obs_text_without_loss() {
        let response =
            parse_response_head(b"HTTP/1.1 200 OK\xff\r\nServer: pingly\r\n\r\n").unwrap();
        let json = serde_json::to_value(&response).unwrap();
        let restored: crate::h1::ResponseHead = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(response.reason_phrase.as_ref(), b"OK\xff");
        assert_eq!(response.reason_phrase_as_str(), None);
        assert_eq!(json["reason_phrase"], json!({"hex": "4f4bff"}));
        assert_eq!(restored, response);
    }

    #[test]
    fn parser_discards_bytes_after_the_head_boundary() {
        let mut parser = Http1Parser::request();
        let head = parser
            .push(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata")
            .unwrap()
            .unwrap();

        assert!(matches!(head, Http1Head::Request(_)));
        assert_eq!(
            parser.as_bytes(),
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n"
        );
    }

    #[test]
    fn complete_helpers_reject_incomplete_and_wrong_start_lines() {
        assert!(matches!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: localhost\r\n"),
            Err(Http1ParseError::IncompleteInput { .. })
        ));
        assert!(parse_request_head(b"HTTP/1.1 200 OK\r\n\r\n").is_err());
        assert!(parse_response_head(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn configured_limits_stop_unbounded_capture() {
        let mut fields = Http1Parser::with_limits(HeadKind::Request, 1024, 1);
        let error = fields
            .push(b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n")
            .unwrap_err();
        assert_eq!(error, Http1ParseError::TooManyHeaders { limit: 1 });
        assert!(fields.is_invalid());

        let mut bytes = Http1Parser::with_limits(HeadKind::Request, 8, 16);
        let error = bytes.push(b"GET / HTTP/1.1\r\n").unwrap_err();
        assert_eq!(error, Http1ParseError::HeadTooLarge { limit: 8 });
    }

    #[test]
    fn zero_header_limit_accepts_empty_sections_and_rejects_fields() {
        let mut empty = Http1Parser::with_limits(HeadKind::Request, 1024, 0);
        let request = empty
            .push(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap()
            .and_then(Http1Head::into_request)
            .unwrap();
        assert!(request.headers.is_empty());

        let mut field = Http1Parser::with_limits(HeadKind::Request, 1024, 0);
        let error = field
            .push(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap_err();
        assert_eq!(error, Http1ParseError::TooManyHeaders { limit: 0 });
    }

    #[test]
    fn requested_capacity_raises_the_effective_head_limit() {
        let requested = DEFAULT_HTTP1_HEAD_LIMIT + 1;
        let parser = Http1Parser::with_capacity(HeadKind::Request, requested);

        assert!(parser.buffer.capacity() >= requested);
        assert_eq!(parser.head_limit(), requested);

        let parser = Http1Parser::with_capacity_and_limits(HeadKind::Response, 128, 64, 8);
        assert!(parser.buffer.capacity() >= 128);
        assert_eq!(parser.head_limit(), 128);
        assert_eq!(parser.header_limit(), 8);
    }

    #[test]
    fn clear_reuses_the_parser_after_completion_or_failure() {
        let mut parser = Http1Parser::request();
        parser.push(b"GET /one HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            parser.push(b"GET /two HTTP/1.1\r\n\r\n"),
            Err(Http1ParseError::AlreadyComplete)
        );

        parser.clear();
        let request = parser
            .push(b"GET /two HTTP/1.1\r\n\r\n")
            .unwrap()
            .and_then(Http1Head::into_request)
            .unwrap();
        assert_eq!(request.target.as_ref(), "/two");
    }

    #[test]
    fn request_model_roundtrips_through_json() {
        let request = parse_request_head(b"GET / HTTP/1.1\r\nX-Raw: \xff\r\n\r\n").unwrap();
        let json = serde_json::to_value(&request).unwrap();
        let restored: crate::h1::RequestHead = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(restored, request);
        assert_eq!(json["headers"][0]["value"], json!({"hex": "ff"}));
    }
}
