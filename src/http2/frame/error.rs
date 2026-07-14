/// Errors that can occur during parsing an HTTP/2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A frame payload did not satisfy the size required by its frame type.
    BadFrameSize,

    /// The padding length was larger than the frame-header-specified
    /// length of the payload.
    TooMuchPadding,

    /// An invalid stream identifier was provided.
    ///
    /// This includes connection frames sent on a stream and stream frames sent
    /// with the connection stream identifier zero.
    InvalidStreamId,

    /// A request is malformed.
    MalformedMessage,
}
