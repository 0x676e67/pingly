use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

use super::{
    IpHeader, IpVersion, Ipv4Flags, SackBlock, TcpFlags, TcpHeader, TcpOption, TcpPacket,
    TCP_OPTION_END_OF_OPTIONS, TCP_OPTION_MAXIMUM_SEGMENT_SIZE, TCP_OPTION_NO_OPERATION,
    TCP_OPTION_SACK, TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TIMESTAMP, TCP_OPTION_WINDOW_SCALE,
};

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_PROVIDER_VLAN: u16 = 0x88a8;
const IP_PROTOCOL_TCP: u8 = 6;

/// Link-layer framing surrounding an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    /// BSD loopback/null framing with a four-byte address family.
    Null,

    /// Ethernet II framing, optionally containing VLAN tags.
    Ethernet,

    /// Linux cooked capture version 1 framing.
    LinuxSll,

    /// Linux cooked capture version 2 framing.
    LinuxSll2,

    /// A raw packet whose first nibble identifies the IP version.
    RawIp,

    /// An unframed IPv4 packet.
    Ipv4,

    /// An unframed IPv6 packet.
    Ipv6,
}

/// Error returned when a captured frame cannot produce a complete TCP packet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TcpPacketParseError {
    /// A link, IP, or TCP header ended before its declared length.
    #[error("truncated {0}")]
    Truncated(&'static str),

    /// A header contains an invalid version or length field.
    #[error("invalid {0}")]
    Invalid(&'static str),

    /// The link-layer payload is not IPv4 or IPv6.
    #[error("unsupported EtherType 0x{0:04x}")]
    UnsupportedEtherType(u16),

    /// The IP payload does not carry TCP.
    #[error("IP protocol {0} is not TCP")]
    NotTcp(u8),

    /// A non-initial IP fragment does not contain the beginning of the TCP header.
    #[error("cannot parse TCP from IP fragment at offset {0}")]
    NonInitialFragment(u16),

    /// An initial IP fragment does not contain the complete TCP segment.
    #[error("cannot parse a complete TCP segment from an initial IP fragment")]
    IncompleteInitialFragment,

    /// IPv6 jumbograms exceed the complete-packet size supported by this parser.
    ///
    /// See [RFC 2675](https://www.rfc-editor.org/rfc/rfc2675.html).
    #[error("IPv6 jumbo payloads are not supported")]
    UnsupportedIpv6Jumbogram,

    /// An encrypted or unsupported IPv6 extension prevents locating TCP.
    #[error("unsupported IPv6 extension header {0}")]
    UnsupportedIpv6Extension(u8),
}

impl TcpPacket {
    /// Parses one complete captured frame using the supplied link-layer format.
    pub fn parse(data: &[u8], link_layer: LinkLayer) -> Result<Self, TcpPacketParseError> {
        let wire_length = data.len();
        let (version, ip_packet) = ip_payload(data, link_layer)?;

        match version {
            IpVersion::Ipv4 => parse_ipv4(ip_packet, wire_length),
            IpVersion::Ipv6 => parse_ipv6(ip_packet, wire_length),
        }
    }
}

fn ip_payload(
    data: &[u8],
    link_layer: LinkLayer,
) -> Result<(IpVersion, &[u8]), TcpPacketParseError> {
    match link_layer {
        LinkLayer::Null => {
            let family = bytes::<4>(data, 0, "null link-layer header")?;
            let native = u32::from_ne_bytes(family);
            let swapped = u32::from_be_bytes(family);
            let version = match (native, swapped) {
                (2, _) | (_, 2) => IpVersion::Ipv4,
                (10 | 24 | 28 | 30, _) | (_, 10 | 24 | 28 | 30) => IpVersion::Ipv6,
                _ => return Err(TcpPacketParseError::Invalid("null address family")),
            };
            Ok((version, tail(data, 4, "null link-layer payload")?))
        }
        LinkLayer::Ethernet => {
            require_len(data, 14, "Ethernet header")?;
            let mut ether_type = u16_at(data, 12, "Ethernet EtherType")?;
            let mut offset = 14;
            while matches!(ether_type, ETHER_TYPE_VLAN | ETHER_TYPE_PROVIDER_VLAN) {
                require_len(data, offset + 4, "VLAN header")?;
                ether_type = u16_at(data, offset + 2, "VLAN EtherType")?;
                offset += 4;
            }
            Ok((ip_version_from_ether_type(ether_type)?, &data[offset..]))
        }
        LinkLayer::LinuxSll => {
            require_len(data, 16, "Linux cooked capture header")?;
            let ether_type = u16_at(data, 14, "Linux cooked protocol")?;
            Ok((ip_version_from_ether_type(ether_type)?, &data[16..]))
        }
        LinkLayer::LinuxSll2 => {
            require_len(data, 20, "Linux cooked capture v2 header")?;
            let ether_type = u16_at(data, 0, "Linux cooked v2 protocol")?;
            Ok((ip_version_from_ether_type(ether_type)?, &data[20..]))
        }
        LinkLayer::RawIp => {
            let version = match data.first().map(|byte| byte >> 4) {
                Some(4) => IpVersion::Ipv4,
                Some(6) => IpVersion::Ipv6,
                Some(_) => return Err(TcpPacketParseError::Invalid("IP version")),
                None => return Err(TcpPacketParseError::Truncated("IP packet")),
            };
            Ok((version, data))
        }
        LinkLayer::Ipv4 => Ok((IpVersion::Ipv4, data)),
        LinkLayer::Ipv6 => Ok((IpVersion::Ipv6, data)),
    }
}

fn ip_version_from_ether_type(ether_type: u16) -> Result<IpVersion, TcpPacketParseError> {
    match ether_type {
        ETHER_TYPE_IPV4 => Ok(IpVersion::Ipv4),
        ETHER_TYPE_IPV6 => Ok(IpVersion::Ipv6),
        other => Err(TcpPacketParseError::UnsupportedEtherType(other)),
    }
}

fn parse_ipv4(data: &[u8], wire_length: usize) -> Result<TcpPacket, TcpPacketParseError> {
    require_len(data, 20, "IPv4 header")?;
    if data[0] >> 4 != 4 {
        return Err(TcpPacketParseError::Invalid("IPv4 version"));
    }

    let header_length = usize::from(data[0] & 0x0f) * 4;
    if header_length < 20 {
        return Err(TcpPacketParseError::Invalid("IPv4 header length"));
    }
    require_len(data, header_length, "IPv4 options")?;

    let packet_length = usize::from(u16_at(data, 2, "IPv4 total length")?);
    if packet_length < header_length {
        return Err(TcpPacketParseError::Invalid("IPv4 total length"));
    }
    require_len(data, packet_length, "IPv4 packet")?;

    let protocol = data[9];
    if protocol != IP_PROTOCOL_TCP {
        return Err(TcpPacketParseError::NotTcp(protocol));
    }

    let traffic_class = data[1];
    let fragment = u16_at(data, 6, "IPv4 fragmentation field")?;
    let fragment_offset = fragment & 0x1fff;
    let flags = Ipv4Flags::from_raw(((fragment >> 13) & 0x07) as u8);
    if fragment_offset != 0 {
        return Err(TcpPacketParseError::NonInitialFragment(fragment_offset));
    }
    if flags.more_fragments() {
        return Err(TcpPacketParseError::IncompleteInitialFragment);
    }
    let source = IpAddr::V4(Ipv4Addr::from(bytes::<4>(data, 12, "IPv4 source")?));
    let destination = IpAddr::V4(Ipv4Addr::from(bytes::<4>(data, 16, "IPv4 destination")?));
    let options =
        (header_length > 20).then(|| hex::encode(&data[20..header_length]).into_boxed_str());
    let (source, destination, tcp) =
        parse_tcp(&data[header_length..packet_length], source, destination)?;

    Ok(TcpPacket {
        source,
        destination,
        wire_length,
        ip: IpHeader {
            version: IpVersion::Ipv4,
            header_length,
            packet_length,
            hop_limit: data[8],
            dscp: traffic_class >> 2,
            ecn: traffic_class & 0x03,
            flow_label: None,
            identification: Some(u16_at(data, 4, "IPv4 identification")?),
            flags: Some(flags),
            fragment_offset,
            checksum: Some(u16_at(data, 10, "IPv4 checksum")?),
            options,
        },
        tcp,
    })
}

fn parse_ipv6(data: &[u8], wire_length: usize) -> Result<TcpPacket, TcpPacketParseError> {
    require_len(data, 40, "IPv6 header")?;
    if data[0] >> 4 != 6 {
        return Err(TcpPacketParseError::Invalid("IPv6 version"));
    }

    let declared_payload_length = usize::from(u16_at(data, 4, "IPv6 payload length")?);
    if declared_payload_length == 0 {
        return Err(TcpPacketParseError::UnsupportedIpv6Jumbogram);
    }
    let packet_length = 40 + declared_payload_length;
    require_len(data, packet_length, "IPv6 packet")?;

    let source = IpAddr::V6(Ipv6Addr::from(bytes::<16>(data, 8, "IPv6 source")?));
    let destination = IpAddr::V6(Ipv6Addr::from(bytes::<16>(data, 24, "IPv6 destination")?));
    let traffic_class = ((data[0] & 0x0f) << 4) | (data[1] >> 4);
    let flow_label =
        (u32::from(data[1] & 0x0f) << 16) | (u32::from(data[2]) << 8) | u32::from(data[3]);
    let (protocol, header_length, fragment_offset, more_fragments) =
        ipv6_payload_offset(&data[..packet_length], data[6])?;
    if protocol != IP_PROTOCOL_TCP {
        return Err(TcpPacketParseError::NotTcp(protocol));
    }
    if fragment_offset != 0 {
        return Err(TcpPacketParseError::NonInitialFragment(fragment_offset));
    }
    if more_fragments {
        return Err(TcpPacketParseError::IncompleteInitialFragment);
    }

    let (source, destination, tcp) =
        parse_tcp(&data[header_length..packet_length], source, destination)?;

    Ok(TcpPacket {
        source,
        destination,
        wire_length,
        ip: IpHeader {
            version: IpVersion::Ipv6,
            header_length,
            packet_length,
            hop_limit: data[7],
            dscp: traffic_class >> 2,
            ecn: traffic_class & 0x03,
            flow_label: Some(flow_label),
            identification: None,
            flags: None,
            fragment_offset,
            checksum: None,
            options: None,
        },
        tcp,
    })
}

fn ipv6_payload_offset(
    data: &[u8],
    mut next_header: u8,
) -> Result<(u8, usize, u16, bool), TcpPacketParseError> {
    let mut offset = 40;
    let mut fragment_offset = 0;
    let mut more_fragments = false;

    loop {
        match next_header {
            IP_PROTOCOL_TCP => {
                return Ok((next_header, offset, fragment_offset, more_fragments));
            }
            0 | 43 | 60 | 135 => {
                require_len(data, offset + 2, "IPv6 extension header")?;
                next_header = data[offset];
                let extension_length = (usize::from(data[offset + 1]) + 1) * 8;
                require_len(data, offset + extension_length, "IPv6 extension header")?;
                offset += extension_length;
            }
            44 => {
                require_len(data, offset + 8, "IPv6 fragment header")?;
                next_header = data[offset];
                let fragment = u16_at(data, offset + 2, "IPv6 fragment offset")?;
                fragment_offset = (fragment >> 3) & 0x1fff;
                more_fragments = fragment & 0x0001 != 0;
                offset += 8;
            }
            51 => {
                require_len(data, offset + 2, "IPv6 authentication header")?;
                next_header = data[offset];
                let extension_length = (usize::from(data[offset + 1]) + 2) * 4;
                require_len(
                    data,
                    offset + extension_length,
                    "IPv6 authentication header",
                )?;
                offset += extension_length;
            }
            50 | 59 => return Err(TcpPacketParseError::UnsupportedIpv6Extension(next_header)),
            other => return Ok((other, offset, fragment_offset, more_fragments)),
        }
    }
}

fn parse_tcp(
    data: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<(SocketAddr, SocketAddr, TcpHeader), TcpPacketParseError> {
    require_len(data, 20, "TCP header")?;
    let source_port = u16_at(data, 0, "TCP source port")?;
    let destination_port = u16_at(data, 2, "TCP destination port")?;
    let header_length = usize::from(data[12] >> 4) * 4;
    if header_length < 20 {
        return Err(TcpPacketParseError::Invalid("TCP header length"));
    }
    require_len(data, header_length, "TCP options")?;

    let (options, options_truncated) = parse_options(&data[20..header_length]);
    let raw_flags = (u16::from(data[12] & 0x01) << 8) | u16::from(data[13]);
    let tcp = TcpHeader {
        sequence_number: u32_at(data, 4, "TCP sequence number")?,
        acknowledgment_number: u32_at(data, 8, "TCP acknowledgment number")?,
        header_length,
        reserved: (data[12] >> 1) & 0x07,
        flags: TcpFlags::from_raw(raw_flags),
        window_size: u16_at(data, 14, "TCP window")?,
        checksum: u16_at(data, 16, "TCP checksum")?,
        urgent_pointer: u16_at(data, 18, "TCP urgent pointer")?,
        options,
        options_truncated,
        payload_length: data.len() - header_length,
    };

    Ok((
        SocketAddr::new(source_ip, source_port),
        SocketAddr::new(destination_ip, destination_port),
        tcp,
    ))
}

fn parse_options(data: &[u8]) -> (Vec<TcpOption>, bool) {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let id = data[offset];
        match id {
            TCP_OPTION_END_OF_OPTIONS => {
                options.push(TcpOption::EndOfOptions);
                return (options, false);
            }
            TCP_OPTION_NO_OPERATION => {
                options.push(TcpOption::NoOperation);
                offset += 1;
            }
            _ => {
                let Some(length) = data.get(offset + 1).copied().map(usize::from) else {
                    return (options, true);
                };
                if length < 2 || offset + length > data.len() {
                    return (options, true);
                }

                let value = &data[offset + 2..offset + length];
                let option = match (id, value) {
                    (TCP_OPTION_MAXIMUM_SEGMENT_SIZE, [a, b]) => TcpOption::MaximumSegmentSize {
                        value: u16::from_be_bytes([*a, *b]),
                    },
                    (TCP_OPTION_WINDOW_SCALE, [value]) => TcpOption::WindowScale { value: *value },
                    (TCP_OPTION_SACK_PERMITTED, []) => TcpOption::SackPermitted,
                    (TCP_OPTION_SACK, value) if !value.is_empty() && value.len() % 8 == 0 => {
                        TcpOption::Sack {
                            blocks: value
                                .chunks_exact(8)
                                .filter_map(|block| {
                                    let [a, b, c, d, e, f, g, h] = block else {
                                        return None;
                                    };
                                    Some(SackBlock {
                                        left_edge: u32::from_be_bytes([*a, *b, *c, *d]),
                                        right_edge: u32::from_be_bytes([*e, *f, *g, *h]),
                                    })
                                })
                                .collect(),
                        }
                    }
                    (TCP_OPTION_TIMESTAMP, [a, b, c, d, e, f, g, h]) => TcpOption::Timestamp {
                        value: u32::from_be_bytes([*a, *b, *c, *d]),
                        echo_reply: u32::from_be_bytes([*e, *f, *g, *h]),
                    },
                    (
                        TCP_OPTION_MAXIMUM_SEGMENT_SIZE
                        | TCP_OPTION_WINDOW_SCALE
                        | TCP_OPTION_SACK_PERMITTED
                        | TCP_OPTION_SACK
                        | TCP_OPTION_TIMESTAMP,
                        _,
                    ) => TcpOption::Malformed {
                        id,
                        value: hex::encode(value).into_boxed_str(),
                    },
                    _ => TcpOption::Other {
                        id,
                        value: hex::encode(value).into_boxed_str(),
                    },
                };
                options.push(option);
                offset += length;
            }
        }
    }

    (options, false)
}

fn require_len(
    data: &[u8],
    required: usize,
    name: &'static str,
) -> Result<(), TcpPacketParseError> {
    if data.len() < required {
        Err(TcpPacketParseError::Truncated(name))
    } else {
        Ok(())
    }
}

fn tail<'a>(
    data: &'a [u8],
    offset: usize,
    name: &'static str,
) -> Result<&'a [u8], TcpPacketParseError> {
    data.get(offset..)
        .ok_or(TcpPacketParseError::Truncated(name))
}

fn bytes<const N: usize>(
    data: &[u8],
    offset: usize,
    name: &'static str,
) -> Result<[u8; N], TcpPacketParseError> {
    let end = offset
        .checked_add(N)
        .ok_or(TcpPacketParseError::Truncated(name))?;
    data.get(offset..end)
        .ok_or(TcpPacketParseError::Truncated(name))?
        .try_into()
        .map_err(|_| TcpPacketParseError::Truncated(name))
}

fn u16_at(data: &[u8], offset: usize, name: &'static str) -> Result<u16, TcpPacketParseError> {
    bytes(data, offset, name).map(u16::from_be_bytes)
}

fn u32_at(data: &[u8], offset: usize, name: &'static str) -> Result<u32, TcpPacketParseError> {
    bytes(data, offset, name).map(u32::from_be_bytes)
}

#[cfg(test)]
pub(super) fn ipv4_syn_frame() -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 20 + 40];
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&60_u16.to_be_bytes());
    ip[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 20]);

    let tcp = &mut ip[20..];
    tcp[0..2].copy_from_slice(&50000_u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
    tcp[12] = 10 << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&64240_u16.to_be_bytes());
    tcp[20..].copy_from_slice(&[
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 8,
    ]);

    frame
}

#[cfg(test)]
mod tests {
    use super::{
        ipv4_syn_frame, LinkLayer, TcpPacket, TcpPacketParseError, ETHER_TYPE_IPV4, IP_PROTOCOL_TCP,
    };
    use crate::tcp::{IpVersion, TcpFlag, TcpOption};

    #[test]
    fn parses_ethernet_ipv4_syn_with_options() {
        let frame = ipv4_syn_frame();
        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();

        assert_eq!(packet.source.to_string(), "192.0.2.10:50000");
        assert_eq!(packet.destination.to_string(), "198.51.100.20:443");
        assert_eq!(packet.ip.version, IpVersion::Ipv4);
        assert_eq!(packet.ip.header_length, 20);
        assert_eq!(packet.ip.packet_length, 60);
        assert_eq!(packet.tcp.header_length, 40);
        assert_eq!(packet.tcp.flags.values(), [TcpFlag::Syn]);
        assert_eq!(packet.tcp.window_size, 64240);
        assert_eq!(packet.tcp.options.len(), 5);
        assert!(matches!(
            packet.tcp.options[0],
            TcpOption::MaximumSegmentSize { value: 1460, .. }
        ));
        assert!(packet.is_initial_syn());
    }

    #[test]
    fn parses_vlan_wrapped_ipv4() {
        let mut frame = ipv4_syn_frame();
        frame[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        frame.splice(14..14, [0, 1, 0x08, 0x00]);

        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();
        assert_eq!(packet.wire_length, 78);
        assert!(packet.is_initial_syn());
    }

    #[test]
    fn parses_supported_non_ethernet_ipv4_link_layers() {
        let ipv4 = ipv4_syn_frame()[14..].to_vec();
        let mut null = 2_u32.to_ne_bytes().to_vec();
        null.extend_from_slice(&ipv4);
        let mut linux_sll = vec![0_u8; 16];
        linux_sll[14..16].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
        linux_sll.extend_from_slice(&ipv4);
        let mut linux_sll2 = vec![0_u8; 20];
        linux_sll2[0..2].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
        linux_sll2.extend_from_slice(&ipv4);

        for (link_layer, frame) in [
            (LinkLayer::Null, null),
            (LinkLayer::LinuxSll, linux_sll),
            (LinkLayer::LinuxSll2, linux_sll2),
            (LinkLayer::RawIp, ipv4.clone()),
            (LinkLayer::Ipv4, ipv4),
        ] {
            let packet = TcpPacket::parse(&frame, link_layer).unwrap();
            assert!(packet.is_initial_syn());
            assert_eq!(packet.source.to_string(), "192.0.2.10:50000");
        }
    }

    #[test]
    fn parses_ipv6_syn_from_raw_and_direct_packets() {
        let packet = ipv6_syn_packet();

        for link_layer in [LinkLayer::RawIp, LinkLayer::Ipv6] {
            let parsed = TcpPacket::parse(&packet, link_layer).unwrap();
            assert_eq!(parsed.ip.version, IpVersion::Ipv6);
            assert_eq!(parsed.ip.header_length, 40);
            assert!(parsed.is_initial_syn());
        }
    }

    #[test]
    fn parses_ipv6_extension_chain_before_tcp() {
        let mut packet = ipv6_syn_packet();
        let tcp = packet.split_off(40);
        packet[4..6].copy_from_slice(&28_u16.to_be_bytes());
        packet[6] = 0;
        packet.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&tcp);

        let parsed = TcpPacket::parse(&packet, LinkLayer::Ipv6).unwrap();
        assert_eq!(parsed.ip.header_length, 48);
        assert!(parsed.is_initial_syn());
    }

    #[test]
    fn rejects_non_initial_ipv4_fragment() {
        let mut frame = ipv4_syn_frame();
        frame[14 + 6..14 + 8].copy_from_slice(&0x0001_u16.to_be_bytes());

        assert_eq!(
            TcpPacket::parse(&frame, LinkLayer::Ethernet),
            Err(TcpPacketParseError::NonInitialFragment(1))
        );
    }

    #[test]
    fn rejects_incomplete_initial_ipv4_fragment() {
        let mut frame = ipv4_syn_frame();
        frame[14 + 6..14 + 8].copy_from_slice(&0x2000_u16.to_be_bytes());

        assert_eq!(
            TcpPacket::parse(&frame, LinkLayer::Ethernet),
            Err(TcpPacketParseError::IncompleteInitialFragment)
        );
    }

    #[test]
    fn rejects_non_initial_ipv6_fragment() {
        let mut packet = vec![0_u8; 40 + 8 + 20];
        packet[0] = 6 << 4;
        packet[4..6].copy_from_slice(&28_u16.to_be_bytes());
        packet[6] = 44;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40] = 6;
        packet[42..44].copy_from_slice(&8_u16.to_be_bytes());

        assert_eq!(
            TcpPacket::parse(&packet, LinkLayer::Ipv6),
            Err(TcpPacketParseError::NonInitialFragment(1))
        );
    }

    #[test]
    fn rejects_incomplete_initial_ipv6_fragment() {
        let mut packet = ipv6_fragment_packet();
        packet[42..44].copy_from_slice(&1_u16.to_be_bytes());

        assert_eq!(
            TcpPacket::parse(&packet, LinkLayer::Ipv6),
            Err(TcpPacketParseError::IncompleteInitialFragment)
        );
    }

    #[test]
    fn rejects_ipv6_zero_payload_length_without_jumbo_support() {
        let mut packet = ipv6_syn_packet();
        packet[4..6].fill(0);

        assert_eq!(
            TcpPacket::parse(&packet, LinkLayer::Ipv6),
            Err(TcpPacketParseError::UnsupportedIpv6Jumbogram)
        );
    }

    #[test]
    fn preserves_malformed_known_tcp_option() {
        let mut frame = ipv4_syn_frame();
        frame.truncate(14 + 20 + 24);
        frame[14 + 2..14 + 4].copy_from_slice(&44_u16.to_be_bytes());
        frame[14 + 20 + 12] = 6 << 4;
        frame[14 + 20 + 20..].copy_from_slice(&[5, 2, 0, 0]);

        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();
        assert!(matches!(
            packet.tcp.options.first(),
            Some(TcpOption::Malformed { id: 5, value }) if value.is_empty()
        ));
        assert!(!packet.tcp.options_truncated);
    }

    #[test]
    fn marks_truncated_tcp_option_list() {
        let mut frame = ipv4_syn_frame();
        frame.truncate(14 + 20 + 24);
        frame[14 + 2..14 + 4].copy_from_slice(&44_u16.to_be_bytes());
        frame[14 + 20 + 12] = 6 << 4;
        frame[14 + 20 + 20..].copy_from_slice(&[2, 5, 0, 0]);

        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();
        assert!(packet.tcp.options.is_empty());
        assert!(packet.tcp.options_truncated);
    }

    #[test]
    fn packet_roundtrips_through_json() {
        let packet = TcpPacket::parse(&ipv4_syn_frame(), LinkLayer::Ethernet).unwrap();
        let json = serde_json::to_vec(&packet).unwrap();
        let restored = serde_json::from_slice(&json).unwrap();

        assert_eq!(packet, restored);
    }

    fn ipv6_syn_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 40 + 20];
        packet[0] = 6 << 4;
        packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
        packet[6] = IP_PROTOCOL_TCP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let tcp = &mut packet[40..];
        tcp[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&64_240_u16.to_be_bytes());
        packet
    }

    fn ipv6_fragment_packet() -> Vec<u8> {
        let mut packet = ipv6_syn_packet();
        let tcp = packet.split_off(40);
        packet[4..6].copy_from_slice(&28_u16.to_be_bytes());
        packet[6] = 44;
        packet.extend_from_slice(&[IP_PROTOCOL_TCP, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&tcp);
        packet
    }
}
