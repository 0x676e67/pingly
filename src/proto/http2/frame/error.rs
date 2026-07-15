/// Errors that can occur during parsing an HTTP/2 frame.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// A frame payload did not satisfy the size required by its frame type.
    #[error("the HTTP/2 frame payload has an invalid size")]
    BadFrameSize,

    /// The padding length was larger than the frame-header-specified
    /// length of the payload.
    #[error("the HTTP/2 padding exceeds the frame payload")]
    TooMuchPadding,

    /// An invalid stream identifier was provided.
    ///
    /// This includes connection frames sent on a stream and stream frames sent
    /// with the connection stream identifier zero.
    #[error("the HTTP/2 frame uses an invalid stream ID")]
    InvalidStreamId,

    /// A stream was declared as depending on itself.
    #[error("an HTTP/2 stream cannot depend on itself")]
    InvalidStreamDependency,

    /// A WINDOW_UPDATE frame used the prohibited zero increment.
    #[error("an HTTP/2 WINDOW_UPDATE increment cannot be zero")]
    InvalidWindowIncrement,

    /// A field block was interrupted before its CONTINUATION frame arrived.
    #[error("an HTTP/2 field block requires the next frame to be CONTINUATION")]
    ExpectedContinuation,

    /// A CONTINUATION frame did not match an open field block.
    #[error("an HTTP/2 CONTINUATION frame does not match an open field block")]
    UnexpectedContinuation,

    /// A request is malformed.
    #[error("the HTTP/2 frame payload is malformed")]
    MalformedMessage,
}
