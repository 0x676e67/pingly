/// Errors that can occur during parsing an HTTP/2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A length value other than 8 was set on a PING message.
    BadFrameSize,

    /// The padding length was larger than the frame-header-specified
    /// length of the payload.
    TooMuchPadding,

    /// An invalid stream identifier was provided.
    ///
    /// This is returned if a SETTINGS or PING frame is received with a stream
    /// identifier other than zero.
    InvalidStreamId,

    /// A request is malformed.
    MalformedMessage,
}
