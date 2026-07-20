//! TCP/IP packet models, link-layer parsing, and passive client fingerprinting.
//!
//! The parser accepts complete packets captured from common libpcap link types. It does not
//! perform TCP stream reassembly. TCP fields follow [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293),
//! while the IP models follow [RFC 791](https://www.rfc-editor.org/rfc/rfc791) and
//! [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200).

mod fingerprint;
mod parser;

use std::net::SocketAddr;

pub use fingerprint::{
    Ja4tFingerprint, LinkEstimate, LinkKind, NetworkEstimate, SatoriFingerprint, TcpFingerprint,
};
pub use parser::{LinkLayer, TcpPacketParseError};
use serde::{Deserialize, Serialize, Serializer};

// IANA TCP Option Kind registry values decoded by this crate.
const TCP_OPTION_END_OF_OPTIONS: u8 = 0;
const TCP_OPTION_NO_OPERATION: u8 = 1;
const TCP_OPTION_MAXIMUM_SEGMENT_SIZE: u8 = 2;
const TCP_OPTION_WINDOW_SCALE: u8 = 3;
const TCP_OPTION_SACK_PERMITTED: u8 = 4;
const TCP_OPTION_SACK: u8 = 5;
const TCP_OPTION_TIMESTAMP: u8 = 8;
const MAX_SACK_BLOCKS: usize = 4;

/// A decoded IP packet carrying one complete TCP segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpPacket {
    /// Source IP address and TCP port.
    pub source: SocketAddr,

    /// Destination IP address and TCP port.
    pub destination: SocketAddr,

    /// Number of bytes captured at the link layer.
    pub wire_length: usize,

    /// Decoded IPv4 or IPv6 header metadata.
    pub ip: IpHeader,

    /// Decoded TCP header, options, and payload length.
    pub tcp: TcpHeader,
}

impl TcpPacket {
    /// Returns whether this packet starts a client-side TCP connection.
    #[inline]
    pub fn is_initial_syn(&self) -> bool {
        self.tcp.flags.syn() && !self.tcp.flags.ack()
    }

    /// Returns whether this packet is a SYN-ACK response.
    #[inline]
    pub fn is_syn_ack(&self) -> bool {
        self.tcp.flags.syn() && self.tcp.flags.ack()
    }

    /// Returns whether this packet can complete the three-way handshake.
    #[inline]
    pub fn is_handshake_ack(&self) -> bool {
        self.tcp.flags.ack()
            && !self.tcp.flags.syn()
            && !self.tcp.flags.fin()
            && !self.tcp.flags.rst()
    }
}

/// Internet Protocol version carried by a decoded packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpVersion {
    /// Internet Protocol version 4.
    Ipv4,

    /// Internet Protocol version 6.
    Ipv6,
}

/// Decoded IP metadata needed for inspection and passive fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpHeader {
    /// IP version used by the packet.
    pub version: IpVersion,

    /// IP header length in bytes, including decoded IPv6 extension headers.
    pub header_length: usize,

    /// Total IP packet length in bytes, excluding link-layer framing.
    pub packet_length: usize,

    /// Observed IPv4 TTL or IPv6 hop-limit value.
    pub hop_limit: u8,

    /// Differentiated Services Code Point value.
    pub dscp: u8,

    /// Explicit Congestion Notification value.
    pub ecn: u8,

    /// IPv6 flow label, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_label: Option<u32>,

    /// IPv4 identification value, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification: Option<u16>,

    /// IPv4 fragmentation flags, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Ipv4Flags>,

    /// Fragment offset in eight-byte units.
    pub fragment_offset: u16,

    /// IPv4 header checksum, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<u16>,

    /// Hexadecimal IPv4 option bytes, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Box<str>>,
}

/// IPv4 fragmentation flags in their wire representation and decoded order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Ipv4FlagsRepr")]
pub struct Ipv4Flags {
    /// Raw three-bit IPv4 flags value.
    raw: u8,

    /// Flags set in the raw value.
    values: Vec<Ipv4Flag>,
}

#[derive(Deserialize)]
/// Saved IPv4 flag representation validated before constructing [`Ipv4Flags`].
struct Ipv4FlagsRepr {
    /// Original three-bit flags field.
    raw: u8,

    /// Decoded flags stored alongside the raw field.
    values: Vec<Ipv4Flag>,
}

impl Ipv4Flags {
    const RESERVED_MASK: u8 = 0x04;
    const DONT_FRAGMENT_MASK: u8 = 0x02;
    const MORE_FRAGMENTS_MASK: u8 = 0x01;
    const VALID_MASK: u8 = 0x07;

    pub(crate) fn from_raw(raw: u8) -> Self {
        let values = [
            (Self::RESERVED_MASK, Ipv4Flag::Reserved),
            (Self::DONT_FRAGMENT_MASK, Ipv4Flag::DontFragment),
            (Self::MORE_FRAGMENTS_MASK, Ipv4Flag::MoreFragments),
        ]
        .into_iter()
        .filter_map(|(mask, flag)| (raw & mask != 0).then_some(flag))
        .collect();

        Self { raw, values }
    }

    /// Returns the original three-bit IPv4 flags value.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.raw
    }

    /// Returns the set IPv4 flags in wire-bit order.
    #[inline]
    pub fn values(&self) -> &[Ipv4Flag] {
        &self.values
    }

    /// Returns whether the reserved IPv4 flag is set.
    #[inline]
    pub fn reserved(&self) -> bool {
        self.raw & Self::RESERVED_MASK != 0
    }

    /// Returns whether the sender requested that the packet not be fragmented.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.raw & Self::DONT_FRAGMENT_MASK != 0
    }

    /// Returns whether more fragments follow this IPv4 packet.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.raw & Self::MORE_FRAGMENTS_MASK != 0
    }
}

impl TryFrom<Ipv4FlagsRepr> for Ipv4Flags {
    type Error = &'static str;

    fn try_from(repr: Ipv4FlagsRepr) -> Result<Self, Self::Error> {
        if repr.raw & !Self::VALID_MASK != 0 {
            return Err("IPv4 flags contain bits outside the three-bit wire field");
        }

        let expected = Self::from_raw(repr.raw);
        if repr.values != expected.values {
            return Err("IPv4 flag values do not match the raw flag field");
        }

        Ok(expected)
    }
}

/// A named IPv4 fragmentation flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv4Flag {
    /// Reserved flag bit.
    Reserved,

    /// Don't Fragment flag.
    DontFragment,

    /// More Fragments flag.
    MoreFragments,
}

/// Decoded TCP header metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpHeader {
    /// Segment sequence number.
    pub sequence_number: u32,

    /// Segment acknowledgment number.
    pub acknowledgment_number: u32,

    /// TCP header length in bytes.
    pub header_length: usize,

    /// Reserved header bits.
    pub reserved: u8,

    /// TCP control flags.
    pub flags: TcpFlags,

    /// Advertised receive window before applying the window scale.
    pub window_size: u16,

    /// TCP checksum from the wire.
    pub checksum: u16,

    /// Urgent pointer from the wire.
    pub urgent_pointer: u16,

    /// TCP options in their original wire order.
    pub options: Vec<TcpOption>,

    /// Whether option decoding stopped on malformed or truncated bytes.
    pub options_truncated: bool,

    /// TCP payload length in bytes.
    pub payload_length: usize,
}

/// TCP control flags in their wire representation and decoded order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TcpFlagsRepr")]
pub struct TcpFlags {
    /// Raw nine-bit TCP flags value, including the NS flag.
    raw: u16,

    /// Flags set in the raw value.
    values: Vec<TcpFlag>,
}

#[derive(Deserialize)]
/// Saved TCP flag representation validated before constructing [`TcpFlags`].
struct TcpFlagsRepr {
    /// Original nine-bit flags field.
    raw: u16,

    /// Decoded flags stored alongside the raw field.
    values: Vec<TcpFlag>,
}

impl TcpFlags {
    const NS_MASK: u16 = 0x100;
    const CWR_MASK: u16 = 0x080;
    const ECE_MASK: u16 = 0x040;
    const URG_MASK: u16 = 0x020;
    const ACK_MASK: u16 = 0x010;
    const PSH_MASK: u16 = 0x008;
    const RST_MASK: u16 = 0x004;
    const SYN_MASK: u16 = 0x002;
    const FIN_MASK: u16 = 0x001;
    const VALID_MASK: u16 = 0x01ff;

    pub(crate) fn from_raw(raw: u16) -> Self {
        let values = [
            (Self::NS_MASK, TcpFlag::Ns),
            (Self::CWR_MASK, TcpFlag::Cwr),
            (Self::ECE_MASK, TcpFlag::Ece),
            (Self::URG_MASK, TcpFlag::Urg),
            (Self::ACK_MASK, TcpFlag::Ack),
            (Self::PSH_MASK, TcpFlag::Psh),
            (Self::RST_MASK, TcpFlag::Rst),
            (Self::SYN_MASK, TcpFlag::Syn),
            (Self::FIN_MASK, TcpFlag::Fin),
        ]
        .into_iter()
        .filter_map(|(mask, flag)| (raw & mask != 0).then_some(flag))
        .collect();

        Self { raw, values }
    }

    /// Returns the original nine-bit TCP flag value.
    #[inline]
    pub const fn raw(&self) -> u16 {
        self.raw
    }

    /// Returns the set TCP flags in wire-bit order.
    #[inline]
    pub fn values(&self) -> &[TcpFlag] {
        &self.values
    }

    /// Returns whether the NS flag is set.
    #[inline]
    pub fn ns(&self) -> bool {
        self.raw & Self::NS_MASK != 0
    }

    /// Returns whether the FIN flag is set.
    #[inline]
    pub fn fin(&self) -> bool {
        self.raw & Self::FIN_MASK != 0
    }

    /// Returns whether the SYN flag is set.
    #[inline]
    pub fn syn(&self) -> bool {
        self.raw & Self::SYN_MASK != 0
    }

    /// Returns whether the RST flag is set.
    #[inline]
    pub fn rst(&self) -> bool {
        self.raw & Self::RST_MASK != 0
    }

    /// Returns whether the PSH flag is set.
    #[inline]
    pub fn psh(&self) -> bool {
        self.raw & Self::PSH_MASK != 0
    }

    /// Returns whether the ACK flag is set.
    #[inline]
    pub fn ack(&self) -> bool {
        self.raw & Self::ACK_MASK != 0
    }

    /// Returns whether the URG flag is set.
    #[inline]
    pub fn urg(&self) -> bool {
        self.raw & Self::URG_MASK != 0
    }

    /// Returns whether the ECE flag is set.
    #[inline]
    pub fn ece(&self) -> bool {
        self.raw & Self::ECE_MASK != 0
    }

    /// Returns whether the CWR flag is set.
    #[inline]
    pub fn cwr(&self) -> bool {
        self.raw & Self::CWR_MASK != 0
    }
}

impl TryFrom<TcpFlagsRepr> for TcpFlags {
    type Error = &'static str;

    fn try_from(repr: TcpFlagsRepr) -> Result<Self, Self::Error> {
        if repr.raw & !Self::VALID_MASK != 0 {
            return Err("TCP flags contain bits outside the nine-bit wire field");
        }

        let expected = Self::from_raw(repr.raw);
        if repr.values != expected.values {
            return Err("TCP flag values do not match the raw flag field");
        }

        Ok(expected)
    }
}

/// A named TCP control flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpFlag {
    /// Accurate ECN nonce sum flag.
    Ns,

    /// Congestion Window Reduced flag.
    Cwr,

    /// ECN-Echo flag.
    Ece,

    /// Urgent pointer field is significant.
    Urg,

    /// Acknowledgment field is significant.
    Ack,

    /// Push function.
    Psh,

    /// Reset the connection.
    Rst,

    /// Synchronize sequence numbers.
    Syn,

    /// No more data from the sender.
    Fin,
}

/// A decoded TCP option from the IANA TCP Option Kind registry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "TcpOptionRepr")]
pub enum TcpOption {
    /// End of option list (`kind = 0`).
    EndOfOptions,

    /// No-operation padding (`kind = 1`).
    NoOperation,

    /// Maximum segment size (`kind = 2`).
    MaximumSegmentSize {
        /// Advertised maximum segment size.
        value: u16,
    },

    /// Window scale (`kind = 3`).
    WindowScale {
        /// Binary window-scale shift count.
        value: u8,
    },

    /// Selective acknowledgment permitted (`kind = 4`).
    SackPermitted,

    /// Selective acknowledgment blocks (`kind = 5`).
    Sack {
        /// Acknowledged sequence-number ranges.
        blocks: Vec<SackBlock>,
    },

    /// TCP timestamps (`kind = 8`).
    Timestamp {
        /// Sender timestamp value.
        value: u32,

        /// Timestamp echo reply value.
        echo_reply: u32,
    },

    /// An option not decoded by this crate.
    Other {
        /// Numeric TCP option kind.
        id: u8,

        /// Hexadecimal option payload, excluding kind and length bytes.
        value: Box<str>,
    },

    /// A recognized option kind whose payload has an invalid wire length.
    Malformed {
        /// Numeric TCP option kind.
        id: u8,

        /// Hexadecimal option payload, excluding kind and length bytes.
        value: Box<str>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "name")]
/// Saved TCP option representation whose IDs are validated during conversion.
enum TcpOptionRepr {
    EndOfOptions { id: u8 },
    NoOperation { id: u8 },
    MaximumSegmentSize { id: u8, value: u16 },
    WindowScale { id: u8, value: u8 },
    SackPermitted { id: u8 },
    Sack { id: u8, blocks: Vec<SackBlock> },
    Timestamp { id: u8, value: u32, echo_reply: u32 },
    Other { id: u8, value: Box<str> },
    Malformed { id: u8, value: Box<str> },
}

#[derive(Serialize)]
#[serde(tag = "name")]
/// Borrowed serialization representation that includes canonical option IDs.
enum TcpOptionRef<'a> {
    EndOfOptions { id: u8 },
    NoOperation { id: u8 },
    MaximumSegmentSize { id: u8, value: u16 },
    WindowScale { id: u8, value: u8 },
    SackPermitted { id: u8 },
    Sack { id: u8, blocks: &'a [SackBlock] },
    Timestamp { id: u8, value: u32, echo_reply: u32 },
    Other { id: u8, value: &'a str },
    Malformed { id: u8, value: &'a str },
}

impl TcpOption {
    /// Returns the numeric TCP option kind.
    pub fn id(&self) -> u8 {
        match self {
            Self::EndOfOptions => TCP_OPTION_END_OF_OPTIONS,
            Self::NoOperation => TCP_OPTION_NO_OPERATION,
            Self::MaximumSegmentSize { .. } => TCP_OPTION_MAXIMUM_SEGMENT_SIZE,
            Self::WindowScale { .. } => TCP_OPTION_WINDOW_SCALE,
            Self::SackPermitted => TCP_OPTION_SACK_PERMITTED,
            Self::Sack { .. } => TCP_OPTION_SACK,
            Self::Timestamp { .. } => TCP_OPTION_TIMESTAMP,
            Self::Other { id, .. } | Self::Malformed { id, .. } => *id,
        }
    }
}

impl TryFrom<TcpOptionRepr> for TcpOption {
    type Error = &'static str;

    fn try_from(repr: TcpOptionRepr) -> Result<Self, Self::Error> {
        match repr {
            TcpOptionRepr::EndOfOptions { id } => {
                require_option_id(id, TCP_OPTION_END_OF_OPTIONS).map(|()| Self::EndOfOptions)
            }
            TcpOptionRepr::NoOperation { id } => {
                require_option_id(id, TCP_OPTION_NO_OPERATION).map(|()| Self::NoOperation)
            }
            TcpOptionRepr::MaximumSegmentSize { id, value } => {
                require_option_id(id, TCP_OPTION_MAXIMUM_SEGMENT_SIZE)
                    .map(|()| Self::MaximumSegmentSize { value })
            }
            TcpOptionRepr::WindowScale { id, value } => {
                require_option_id(id, TCP_OPTION_WINDOW_SCALE).map(|()| Self::WindowScale { value })
            }
            TcpOptionRepr::SackPermitted { id } => {
                require_option_id(id, TCP_OPTION_SACK_PERMITTED).map(|()| Self::SackPermitted)
            }
            TcpOptionRepr::Sack { id, blocks } => {
                require_option_id(id, TCP_OPTION_SACK)?;
                if !(1..=MAX_SACK_BLOCKS).contains(&blocks.len()) {
                    return Err("SACK requires between one and four blocks");
                }
                Ok(Self::Sack { blocks })
            }
            TcpOptionRepr::Timestamp {
                id,
                value,
                echo_reply,
            } => require_option_id(id, TCP_OPTION_TIMESTAMP)
                .map(|()| Self::Timestamp { value, echo_reply }),
            TcpOptionRepr::Other { id, value } => {
                if is_decoded_option(id) {
                    return Err("decoded TCP option kinds cannot be represented as Other");
                }
                if !is_canonical_hex(value.as_ref()) {
                    return Err("TCP option payloads must use canonical lowercase hexadecimal");
                }
                Ok(Self::Other { id, value })
            }
            TcpOptionRepr::Malformed { id, value } => {
                if !is_length_encoded_option(id) {
                    return Err("Malformed requires a recognized length-encoded TCP option kind");
                }
                if !is_canonical_hex(value.as_ref()) {
                    return Err("TCP option payloads must use canonical lowercase hexadecimal");
                }
                if option_payload_is_valid(id, value.len() / 2) {
                    return Err("a valid TCP option payload cannot be represented as Malformed");
                }
                Ok(Self::Malformed { id, value })
            }
        }
    }
}

impl Serialize for TcpOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let repr = match self {
            Self::EndOfOptions => TcpOptionRef::EndOfOptions {
                id: TCP_OPTION_END_OF_OPTIONS,
            },
            Self::NoOperation => TcpOptionRef::NoOperation {
                id: TCP_OPTION_NO_OPERATION,
            },
            Self::MaximumSegmentSize { value } => TcpOptionRef::MaximumSegmentSize {
                id: TCP_OPTION_MAXIMUM_SEGMENT_SIZE,
                value: *value,
            },
            Self::WindowScale { value } => TcpOptionRef::WindowScale {
                id: TCP_OPTION_WINDOW_SCALE,
                value: *value,
            },
            Self::SackPermitted => TcpOptionRef::SackPermitted {
                id: TCP_OPTION_SACK_PERMITTED,
            },
            Self::Sack { blocks } => TcpOptionRef::Sack {
                id: TCP_OPTION_SACK,
                blocks,
            },
            Self::Timestamp { value, echo_reply } => TcpOptionRef::Timestamp {
                id: TCP_OPTION_TIMESTAMP,
                value: *value,
                echo_reply: *echo_reply,
            },
            Self::Other { id, value } => TcpOptionRef::Other { id: *id, value },
            Self::Malformed { id, value } => TcpOptionRef::Malformed { id: *id, value },
        };

        repr.serialize(serializer)
    }
}

fn require_option_id(id: u8, expected: u8) -> Result<(), &'static str> {
    (id == expected)
        .then_some(())
        .ok_or("TCP option id does not match its name")
}

const fn is_decoded_option(id: u8) -> bool {
    matches!(
        id,
        TCP_OPTION_END_OF_OPTIONS
            | TCP_OPTION_NO_OPERATION
            | TCP_OPTION_MAXIMUM_SEGMENT_SIZE
            | TCP_OPTION_WINDOW_SCALE
            | TCP_OPTION_SACK_PERMITTED
            | TCP_OPTION_SACK
            | TCP_OPTION_TIMESTAMP
    )
}

const fn is_length_encoded_option(id: u8) -> bool {
    matches!(
        id,
        TCP_OPTION_MAXIMUM_SEGMENT_SIZE
            | TCP_OPTION_WINDOW_SCALE
            | TCP_OPTION_SACK_PERMITTED
            | TCP_OPTION_SACK
            | TCP_OPTION_TIMESTAMP
    )
}

fn is_canonical_hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn option_payload_is_valid(id: u8, length: usize) -> bool {
    match id {
        TCP_OPTION_MAXIMUM_SEGMENT_SIZE => length == 2,
        TCP_OPTION_WINDOW_SCALE => length == 1,
        TCP_OPTION_SACK_PERMITTED => length == 0,
        TCP_OPTION_SACK => length > 0 && length.is_multiple_of(8),
        TCP_OPTION_TIMESTAMP => length == 8,
        _ => false,
    }
}

/// One SACK left-edge/right-edge sequence-number pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SackBlock {
    /// First sequence number in the acknowledged block.
    pub left_edge: u32,

    /// Sequence number immediately after the acknowledged block.
    pub right_edge: u32,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Ipv4Flag, Ipv4Flags, TcpFlag, TcpFlags, TcpOption};

    #[test]
    fn tcp_flags_roundtrip_in_canonical_form() {
        let flags = TcpFlags::from_raw(0x012);
        let json = serde_json::to_value(&flags).unwrap();
        let restored = serde_json::from_value(json).unwrap();

        assert_eq!(flags, restored);
        assert_eq!(flags.raw(), 0x012);
        assert_eq!(flags.values(), [TcpFlag::Ack, TcpFlag::Syn]);
    }

    #[test]
    fn tcp_flags_reject_inconsistent_or_out_of_range_values() {
        assert!(serde_json::from_value::<TcpFlags>(json!({
            "raw": 0,
            "values": ["Syn"]
        }))
        .is_err());
        assert!(serde_json::from_value::<TcpFlags>(json!({
            "raw": 512,
            "values": []
        }))
        .is_err());
    }

    #[test]
    fn ipv4_flags_reject_inconsistent_values() {
        let flags = Ipv4Flags::from_raw(0x02);
        assert_eq!(flags.raw(), 0x02);
        assert_eq!(flags.values(), [Ipv4Flag::DontFragment]);
        assert!(serde_json::from_value::<Ipv4Flags>(json!({
            "raw": 2,
            "values": ["MoreFragments"]
        }))
        .is_err());
    }

    #[test]
    fn known_tcp_options_serialize_their_canonical_id() {
        let option = TcpOption::MaximumSegmentSize { value: 1_460 };
        let json = serde_json::to_value(&option).unwrap();

        assert_eq!(
            json,
            json!({
                "name": "MaximumSegmentSize",
                "id": 2,
                "value": 1460
            })
        );
        assert_eq!(serde_json::from_value::<TcpOption>(json).unwrap(), option);
    }

    #[test]
    fn tcp_options_reject_mismatched_or_disguised_ids() {
        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "MaximumSegmentSize",
            "id": 3,
            "value": 1460
        }))
        .is_err());
        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "Other",
            "id": 2,
            "value": "05b4"
        }))
        .is_err());
        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "Other",
            "id": 30,
            "value": "AB"
        }))
        .is_err());
        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "Other",
            "id": 30,
            "value": "a"
        }))
        .is_err());
        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "Malformed",
            "id": 2,
            "value": "05b4"
        }))
        .is_err());
    }

    #[test]
    fn sack_options_require_between_one_and_four_blocks() {
        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "Sack",
            "id": 5,
            "blocks": []
        }))
        .is_err());

        assert!(serde_json::from_value::<TcpOption>(json!({
            "name": "Sack",
            "id": 5,
            "blocks": (0..5)
                .map(|value| json!({
                    "left_edge": value,
                    "right_edge": value + 1
                }))
                .collect::<Vec<_>>()
        }))
        .is_err());
    }

    #[test]
    fn malformed_known_tcp_options_roundtrip_explicitly() {
        let option = TcpOption::Malformed {
            id: 5,
            value: Box::from(""),
        };
        let json = serde_json::to_vec(&option).unwrap();

        assert_eq!(serde_json::from_slice::<TcpOption>(&json).unwrap(), option);
    }
}
