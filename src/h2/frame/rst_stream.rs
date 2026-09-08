//! HTTP/2 RST_STREAM frame and error-code decoding.

use serde::{Deserialize, Serialize};

use super::{FrameError, FrameType};

const RST_STREAM_PAYLOAD_LENGTH: usize = 4;

/// A decoded HTTP/2 `RST_STREAM` frame.
///
/// `RST_STREAM` terminates one stream without closing the HTTP/2 connection. See
/// [RFC 9113, Section 6.4](https://www.rfc-editor.org/rfc/rfc9113#section-6.4).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RstStreamFrameRepr")]
pub struct RstStreamFrame {
    /// The frame category, always [`FrameType::RstStream`].
    pub frame_type: FrameType,

    /// Nonzero stream identifier terminated by this frame.
    pub stream_id: u32,

    /// Payload length, always four bytes.
    pub length: usize,

    /// Original unused flag byte retained for wire analysis.
    pub flags: u8,

    /// Reason the endpoint terminated the stream.
    pub error_code: ErrorCode,
}

/// An HTTP/2 connection or stream error code.
///
/// The numeric value is retained alongside its registered meaning so unknown future codes remain
/// representable. See [RFC 9113, Section 7](https://www.rfc-editor.org/rfc/rfc9113#section-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ErrorCodeRepr")]
pub struct ErrorCode {
    /// Original 32-bit error code from the wire.
    pub id: u32,

    /// Registered or unrecognized meaning of the code.
    pub name: ErrorCodeName,
}

registry_enum! {
    /// Semantic name of an HTTP/2 error code.
    #[serde(rename_all = "PascalCase")]
    #[non_exhaustive]
    pub enum ErrorCodeName: u32 {
        /// Graceful completion without an error (`0x00`).
        NoError => 0x00,

        /// A generic protocol violation (`0x01`).
        ProtocolError => 0x01,

        /// An unexpected internal failure (`0x02`).
        InternalError => 0x02,

        /// A flow-control violation (`0x03`).
        FlowControlError => 0x03,

        /// SETTINGS acknowledgement was not received in time (`0x04`).
        SettingsTimeout => 0x04,

        /// A frame was received after the stream was half-closed (`0x05`).
        StreamClosed => 0x05,

        /// A frame had an invalid size (`0x06`).
        FrameSizeError => 0x06,

        /// The stream was refused before application processing (`0x07`).
        RefusedStream => 0x07,

        /// The stream is no longer needed (`0x08`).
        Cancel => 0x08,

        /// The endpoint could not maintain the HPACK context (`0x09`).
        CompressionError => 0x09,

        /// A CONNECT tunnel was reset or closed abnormally (`0x0a`).
        ConnectError => 0x0a,

        /// The endpoint asks its peer to reduce its load (`0x0b`).
        EnhanceYourCalm => 0x0b,

        /// The negotiated security properties are insufficient (`0x0c`).
        InadequateSecurity => 0x0c,

        /// The endpoint requires HTTP/1.1 (`0x0d`).
        Http11Required => 0x0d,
    }

    fallback(_id) {
        /// An unregistered or unsupported error code.
        Other,
    } => Self::Other;
}

/// Deserialization shape validated before constructing [`RstStreamFrame`].
#[derive(Deserialize)]
struct RstStreamFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved stream identifier.
    stream_id: u32,

    /// Saved payload length.
    length: usize,

    /// Saved unused flag byte.
    flags: u8,

    /// Saved stream error code.
    error_code: ErrorCode,
}

/// Deserialization shape used to validate an [`ErrorCode`] name against its numeric value.
#[derive(Deserialize)]
struct ErrorCodeRepr {
    /// Saved numeric error code.
    id: u32,

    /// Saved semantic name.
    name: ErrorCodeName,
}

impl From<u32> for ErrorCode {
    fn from(id: u32) -> Self {
        Self {
            id,
            name: ErrorCodeName::from(id),
        }
    }
}

impl TryFrom<ErrorCodeRepr> for ErrorCode {
    type Error = &'static str;

    fn try_from(repr: ErrorCodeRepr) -> Result<Self, Self::Error> {
        if repr.name != ErrorCodeName::from(repr.id) {
            return Err("HTTP/2 error code name does not match its identifier");
        }

        Ok(Self {
            id: repr.id,
            name: repr.name,
        })
    }
}

impl TryFrom<RstStreamFrameRepr> for RstStreamFrame {
    type Error = &'static str;

    fn try_from(repr: RstStreamFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::RstStream {
            return Err("RST_STREAM frame_type must be RstStream");
        }
        if repr.stream_id == 0 || repr.stream_id > 0x7fff_ffff {
            return Err("RST_STREAM stream_id must be a nonzero 31-bit value");
        }
        if repr.length != RST_STREAM_PAYLOAD_LENGTH {
            return Err("RST_STREAM payload length must be four");
        }

        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            error_code: repr.error_code,
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for RstStreamFrame {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        if stream_id == 0 || stream_id > 0x7fff_ffff {
            return Err(FrameError::InvalidStreamId);
        }
        let payload: [u8; RST_STREAM_PAYLOAD_LENGTH] =
            payload.try_into().map_err(|_| FrameError::BadFrameSize)?;

        Ok(Self {
            frame_type: FrameType::RstStream,
            stream_id,
            length: payload.len(),
            flags,
            error_code: u32::from_be_bytes(payload).into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ErrorCodeName, RstStreamFrame};
    use crate::h2::frame::{Frame, FrameError, FrameParser};

    #[test]
    fn rst_stream_decodes_cancel_and_enforces_its_wire_shape() {
        let wire = [0, 0, 4, 0x03, 0xa5, 0, 0, 0, 5, 0, 0, 0, 8];
        let Some(Frame::RstStream(frame)) =
            FrameParser::default().parse(&wire).unwrap().into_frame()
        else {
            panic!("expected an RST_STREAM frame");
        };

        assert_eq!(frame.stream_id, 5);
        assert_eq!(frame.flags, 0xa5);
        assert_eq!(frame.error_code.id, 8);
        assert_eq!(frame.error_code.name, ErrorCodeName::Cancel);

        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(
            json,
            json!({
                "frame_type": "RstStream",
                "stream_id": 5,
                "length": 4,
                "flags": 165,
                "error_code": {"id": 8, "name": "Cancel"}
            })
        );
        assert_eq!(
            serde_json::from_value::<RstStreamFrame>(json).unwrap(),
            frame
        );

        assert_eq!(
            RstStreamFrame::try_from((0, 0, &[0; 4][..])).unwrap_err(),
            FrameError::InvalidStreamId
        );
        assert_eq!(
            RstStreamFrame::try_from((0, 1, &[0; 3][..])).unwrap_err(),
            FrameError::BadFrameSize
        );
    }
}
