//! HTTP/2 pushed-request field sections.

use httlib_hpack::Decoder;
use serde::{Deserialize, Serialize};

use super::{
    headers::{validate_continuations, FieldBlock},
    ContinuationFrame, FrameError, FrameType, HeaderField,
};

const END_HEADERS: u8 = 0x04;
const PADDED: u8 = 0x08;

/// A promised request, including the CONTINUATION frames that complete its field section.
/// See [RFC 9113, Section 6.6](https://www.rfc-editor.org/rfc/rfc9113#section-6.6).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PushPromiseFrameRepr")]
pub struct PushPromiseFrame {
    /// Frame category, always [`FrameType::PushPromise`].
    pub frame_type: FrameType,

    /// Client-initiated stream carrying the promise, not the promised stream itself.
    pub stream_id: u32,

    /// Opening PUSH_PROMISE payload length, excluding CONTINUATION frames.
    pub length: usize,

    /// Original flags; only END_HEADERS (`0x04`) and PADDED (`0x08`) are defined.
    pub flags: u8,

    /// Server-initiated stream reserved for the pushed response.
    pub promised_stream_id: u32,

    /// Padding count when the PADDED flag is set, including an explicit zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding_length: Option<u8>,

    /// Promised request fields in their original order.
    pub headers: Vec<HeaderField>,

    /// Continuations on the carrying stream, in wire order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub continuations: Vec<ContinuationFrame>,
}

/// Saved PUSH_PROMISE fields validated before construction.
#[derive(Deserialize)]
struct PushPromiseFrameRepr {
    /// Saved frame category.
    frame_type: FrameType,

    /// Saved carrying stream.
    stream_id: u32,

    /// Saved opening payload length.
    length: usize,

    /// Original flags.
    flags: u8,

    /// Saved promised stream.
    promised_stream_id: u32,

    /// Saved optional padding count.
    #[serde(default)]
    padding_length: Option<u8>,

    /// Decoded fields in wire order.
    headers: Vec<HeaderField>,

    /// Saved continuation metadata.
    #[serde(default)]
    continuations: Vec<ContinuationFrame>,
}

impl TryFrom<PushPromiseFrameRepr> for PushPromiseFrame {
    type Error = &'static str;

    fn try_from(repr: PushPromiseFrameRepr) -> Result<Self, Self::Error> {
        if repr.frame_type != FrameType::PushPromise
            || !valid_stream_ids(repr.stream_id, repr.promised_stream_id)
        {
            return Err(
                "PUSH_PROMISE requires an odd carrying stream and a nonzero even promised stream",
            );
        }
        let padded = repr.flags & PADDED != 0;
        if padded != repr.padding_length.is_some()
            || repr.length < 4 + usize::from(padded) + usize::from(repr.padding_length.unwrap_or(0))
            || repr.length > 0x00ff_ffff
        {
            return Err("PUSH_PROMISE length or padding is inconsistent");
        }
        if repr.headers.iter().any(|field| field.name.as_ref() == b":") {
            return Err("a pseudo-header name cannot contain only a colon");
        }
        validate_continuations(
            repr.stream_id,
            repr.flags & END_HEADERS != 0,
            &repr.continuations,
        )?;
        Ok(Self {
            frame_type: repr.frame_type,
            stream_id: repr.stream_id,
            length: repr.length,
            flags: repr.flags,
            promised_stream_id: repr.promised_stream_id,
            padding_length: repr.padding_length,
            headers: repr.headers,
            continuations: repr.continuations,
        })
    }
}

/// A promised request whose HPACK field block might require more frames.
#[derive(Debug)]
pub(super) struct PendingPushPromise {
    /// Opening frame metadata, populated with decoded fields on completion.
    frame: PushPromiseFrame,

    /// Compressed field block and continuation metadata.
    block: FieldBlock,
}

impl PendingPushPromise {
    pub(super) fn is_complete(&self) -> bool {
        self.frame.flags & END_HEADERS != 0
    }

    pub(super) fn push_continuation(
        &mut self,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<bool, FrameError> {
        self.block.push_continuation(flags, stream_id, payload)
    }

    pub(super) fn finish(
        mut self,
        decoder: &mut Decoder<'_>,
    ) -> Result<PushPromiseFrame, FrameError> {
        (self.frame.headers, self.frame.continuations) = self.block.decode(decoder)?;
        Ok(self.frame)
    }
}

impl TryFrom<(u8, u32, &[u8])> for PendingPushPromise {
    type Error = FrameError;

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        let padded = flags & PADDED != 0;
        let offset = usize::from(padded);
        let prefix = payload
            .get(offset..offset + 4)
            .ok_or(FrameError::BadFrameSize)?;
        let promised_stream_id =
            u32::from_be_bytes([prefix[0] & 0x7f, prefix[1], prefix[2], prefix[3]]);
        if !valid_stream_ids(stream_id, promised_stream_id) {
            return Err(FrameError::InvalidStreamId);
        }
        if payload.len() > 0x00ff_ffff {
            return Err(FrameError::BadFrameSize);
        }
        let padding_length = padded.then(|| payload[0]);
        let data = &payload[offset + 4..];
        let block_end = data
            .len()
            .checked_sub(usize::from(padding_length.unwrap_or(0)))
            .ok_or(FrameError::TooMuchPadding)?;
        Ok(Self {
            frame: PushPromiseFrame {
                frame_type: FrameType::PushPromise,
                stream_id,
                length: payload.len(),
                flags,
                promised_stream_id,
                padding_length,
                headers: Vec::new(),
                continuations: Vec::new(),
            },
            block: FieldBlock::new(stream_id, &data[..block_end]),
        })
    }
}

impl TryFrom<(u8, u32, &[u8])> for PushPromiseFrame {
    type Error = FrameError;

    /// Decodes a complete standalone promise using the initial HPACK table.
    /// Use [`super::FrameParser`] for a connection's dynamic table or continuation sequences.
    fn try_from(value: (u8, u32, &[u8])) -> Result<Self, Self::Error> {
        let pending = PendingPushPromise::try_from(value)?;
        if !pending.is_complete() {
            return Err(FrameError::ExpectedContinuation);
        }
        pending.finish(&mut Decoder::default())
    }
}

fn valid_stream_ids(stream_id: u32, promised_stream_id: u32) -> bool {
    stream_id <= 0x7fff_ffff
        && stream_id & 1 == 1
        && promised_stream_id != 0
        && promised_stream_id <= 0x7fff_ffff
        && promised_stream_id & 1 == 0
}
