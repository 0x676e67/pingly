use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{IpVersion, TcpOption, TcpPacket};

/// JA4T-compatible TCP client fingerprint generated from an initial SYN.
///
/// JA4T is specified and licensed separately by FoxIO. See the
/// [JA4+ project](https://github.com/FoxIO-LLC/ja4#licensing) before redistributing or
/// monetizing this output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4tFingerprint {
    /// Human-readable window, option-order, MSS, and window-scale fingerprint.
    pub fingerprint: Box<str>,
}

/// Satori-compatible passive TCP signature generated from an initial IPv4 SYN.
///
/// The field order follows the Satori TCP implementation: window, estimated initial TTL,
/// Don't Fragment flag, IP+TCP header length, ordered TCP options, and quirks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatoriFingerprint {
    /// Human-readable Satori TCP signature.
    pub fingerprint: Box<str>,

    /// Compact Satori quirks field.
    pub quirks: Box<str>,
}

/// Estimated network distance derived from the observed TTL or hop limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEstimate {
    /// TTL or hop limit observed by the server.
    pub observed_hop_limit: u8,

    /// Nearest common initial TTL at or above the observed value.
    pub initial_hop_limit: u8,

    /// Estimated number of routed hops between peer and server.
    pub distance_hops: u8,
}

/// Probable link encapsulation inferred from the SYN MSS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkEstimate {
    /// Estimated link MTU after adding the IP and TCP base headers to MSS.
    pub mtu: u16,

    /// Human-readable link or tunnel family.
    pub kind: LinkKind,
}

/// Link or tunnel family inferred from a SYN maximum segment size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkKind {
    /// Local loopback-style MTU.
    Loopback,

    /// Common Ethernet or modem MTU.
    #[serde(rename = "Ethernet or modem")]
    EthernetOrModem,

    /// DSL or PPPoE encapsulation.
    #[serde(rename = "DSL or PPPoE")]
    DslOrPppoe,

    /// Generic tunnel MTU.
    Tunnel,

    /// Tunnel or VPN encapsulation.
    #[serde(rename = "Tunnel or VPN")]
    TunnelOrVpn,

    /// IPsec or GRE encapsulation.
    #[serde(rename = "IPsec or GRE")]
    IpsecOrGre,

    /// IP-in-IP or SIT encapsulation.
    #[serde(rename = "IP-in-IP or SIT")]
    IpInIpOrSit,

    /// Point-to-Point Tunneling Protocol.
    #[serde(rename = "PPTP")]
    Pptp,

    /// IEEE 802.1Q VLAN encapsulation.
    #[serde(rename = "VLAN")]
    Vlan,

    /// Conventional jumbo Ethernet MTU.
    #[serde(rename = "Jumbo Ethernet")]
    JumboEthernet,

    /// Non-standard jumbo frame or loopback MTU.
    #[serde(rename = "Jumbo frame or loopback")]
    JumboFrameOrLoopback,

    /// No known link family matched the estimated MTU.
    Unknown,
}

/// Passive TCP/IP analysis derived from an initial client SYN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFingerprint {
    /// JA4T-compatible TCP fingerprint.
    pub ja4t: Ja4tFingerprint,

    /// Satori-compatible signature for IPv4, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satori: Option<SatoriFingerprint>,

    /// TTL or hop-limit based distance estimate.
    pub network: NetworkEstimate,

    /// MSS-derived link MTU estimate.
    pub link: LinkEstimate,
}

impl TcpFingerprint {
    /// Calculates a passive fingerprint when `packet` is an initial client SYN.
    pub fn from_initial_syn(packet: &TcpPacket) -> Option<Self> {
        if !packet.is_initial_syn() {
            return None;
        }

        let network = network_estimate(packet.ip.hop_limit);
        let ja4t = Ja4tFingerprint {
            fingerprint: ja4t(packet).into_boxed_str(),
        };
        let satori = (packet.ip.version == IpVersion::Ipv4).then(|| satori(packet, network));
        let link = link_estimate(packet);

        Some(Self {
            ja4t,
            satori,
            network,
            link,
        })
    }
}

fn ja4t(packet: &TcpPacket) -> String {
    let option_ids = packet
        .tcp
        .options
        .iter()
        .filter(|option| !matches!(option, TcpOption::EndOfOptions))
        .fold(String::new(), |mut output, option| {
            if !output.is_empty() {
                output.push('-');
            }
            let _ = write!(output, "{}", option.id());
            output
        });

    let mut fingerprint = format!("{}_", packet.tcp.window_size);
    fingerprint.push_str(if option_ids.is_empty() {
        "00"
    } else {
        &option_ids
    });
    fingerprint.push('_');
    match maximum_segment_size(&packet.tcp.options) {
        Some(value) => {
            let _ = write!(fingerprint, "{value}");
        }
        None => fingerprint.push_str("00"),
    }
    fingerprint.push('_');
    match window_scale(&packet.tcp.options).filter(|value| *value != 0) {
        Some(value) => {
            let _ = write!(fingerprint, "{value}");
        }
        None => fingerprint.push_str("00"),
    }

    fingerprint
}

fn satori(packet: &TcpPacket, network: NetworkEstimate) -> SatoriFingerprint {
    let options = packet
        .tcp
        .options
        .iter()
        .fold(String::new(), |mut output, option| {
            if !output.is_empty() {
                output.push(',');
            }
            push_satori_option(&mut output, option);
            output
        });
    let quirks = satori_quirks(packet);
    let dont_fragment = packet
        .ip
        .flags
        .as_ref()
        .is_some_and(|flags| flags.dont_fragment());
    let fingerprint = format!(
        "{}:{}:{}:{}:{}:{}",
        packet.tcp.window_size,
        network.initial_hop_limit,
        u8::from(dont_fragment),
        packet.ip.header_length + packet.tcp.header_length,
        options,
        quirks,
    );

    SatoriFingerprint {
        fingerprint: fingerprint.into_boxed_str(),
        quirks: quirks.into_boxed_str(),
    }
}

fn push_satori_option(output: &mut String, option: &TcpOption) {
    match option {
        TcpOption::EndOfOptions => output.push('E'),
        TcpOption::NoOperation => output.push('N'),
        TcpOption::MaximumSegmentSize { value } => {
            let _ = write!(output, "M{value}");
        }
        TcpOption::WindowScale { value } => {
            let _ = write!(output, "W{value}");
        }
        TcpOption::SackPermitted => output.push('S'),
        TcpOption::Sack { .. } => output.push('K'),
        TcpOption::Timestamp { .. } => output.push('T'),
        TcpOption::Other { id: 6, .. } => output.push('J'),
        TcpOption::Other { id: 7, .. } => output.push('F'),
        TcpOption::Other { id: 9, .. } => output.push('P'),
        TcpOption::Other { id: 10, .. } => output.push('R'),
        TcpOption::Other { .. } | TcpOption::Malformed { .. } => output.push('U'),
    }
}

fn satori_quirks(packet: &TcpPacket) -> String {
    let mut quirks = String::new();
    if matches!(packet.tcp.options.last(), Some(TcpOption::EndOfOptions)) {
        quirks.push('P');
    }
    if packet.ip.identification == Some(0) {
        quirks.push('Z');
    }
    if packet.ip.header_length > 20 {
        quirks.push('I');
    }
    if packet.tcp.payload_length > 0 {
        quirks.push('D');
    }
    if packet.tcp.flags.urg() {
        quirks.push('U');
    }
    if packet.tcp.acknowledgment_number != 0 {
        quirks.push('A');
    }
    if packet.tcp.options.iter().any(|option| {
        matches!(
            option,
            TcpOption::Timestamp {
                echo_reply,
                ..
            } if *echo_reply != 0
        )
    }) {
        quirks.push('T');
    }
    if packet.tcp.flags.fin()
        || packet.tcp.flags.rst()
        || packet.tcp.flags.psh()
        || packet.tcp.flags.urg()
        || packet.tcp.flags.ece()
        || packet.tcp.flags.cwr()
    {
        quirks.push('F');
    }
    if quirks.is_empty() {
        quirks.push('.');
    }
    quirks
}

fn maximum_segment_size(options: &[TcpOption]) -> Option<u16> {
    options.iter().find_map(|option| match option {
        TcpOption::MaximumSegmentSize { value, .. } => Some(*value),
        _ => None,
    })
}

fn window_scale(options: &[TcpOption]) -> Option<u8> {
    options.iter().find_map(|option| match option {
        TcpOption::WindowScale { value, .. } => Some(*value),
        _ => None,
    })
}

fn network_estimate(observed_hop_limit: u8) -> NetworkEstimate {
    let initial_hop_limit = match observed_hop_limit {
        0 => 0,
        1..=16 => 16,
        17..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    };

    NetworkEstimate {
        observed_hop_limit,
        initial_hop_limit,
        distance_hops: initial_hop_limit.saturating_sub(observed_hop_limit),
    }
}

fn link_estimate(packet: &TcpPacket) -> LinkEstimate {
    let base_headers = match packet.ip.version {
        IpVersion::Ipv4 => 40,
        IpVersion::Ipv6 => 60,
    };
    let mtu = maximum_segment_size(&packet.tcp.options)
        .and_then(|mss| mss.checked_add(base_headers))
        .unwrap_or(0);
    let kind = match mtu {
        3924 | 16384 | 16436 => LinkKind::Loopback,
        576 | 1500 => LinkKind::EthernetOrModem,
        1452 | 1454 | 1492 => LinkKind::DslOrPppoe,
        1240 | 1280 => LinkKind::Tunnel,
        1300 | 1400 | 1420 | 1440 | 1450 | 1460 => LinkKind::TunnelOrVpn,
        1476 => LinkKind::IpsecOrGre,
        1480 => LinkKind::IpInIpOrSit,
        1490 => LinkKind::Pptp,
        1496 => LinkKind::Vlan,
        9000 => LinkKind::JumboEthernet,
        1501..=8999 => LinkKind::JumboFrameOrLoopback,
        1461..=1500 => LinkKind::EthernetOrModem,
        1400..=1460 => LinkKind::TunnelOrVpn,
        _ => LinkKind::Unknown,
    };

    LinkEstimate { mtu, kind }
}

#[cfg(test)]
mod tests {
    use super::{network_estimate, TcpFingerprint};
    use crate::tcp::{parser::ipv4_syn_frame, LinkLayer, TcpPacket};

    #[test]
    fn fingerprints_reference_ipv4_syn() {
        let packet = TcpPacket::parse(&ipv4_syn_frame(), LinkLayer::Ethernet).unwrap();
        let fingerprint = TcpFingerprint::from_initial_syn(&packet).unwrap();

        assert_eq!(
            fingerprint.ja4t.fingerprint.as_ref(),
            "64240_2-4-8-1-3_1460_8"
        );
        assert_eq!(
            fingerprint.satori.unwrap().fingerprint.as_ref(),
            "64240:64:1:60:M1460,S,T,N,W8:."
        );
        assert_eq!(fingerprint.network.distance_hops, 0);
        assert_eq!(fingerprint.link.mtu, 1500);
    }

    #[test]
    fn rejects_non_syn_packets() {
        let mut frame = ipv4_syn_frame();
        frame[14 + 20 + 13] = 0x10;
        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();

        assert!(TcpFingerprint::from_initial_syn(&packet).is_none());
    }

    #[test]
    fn ja4t_uses_zero_fields_for_missing_options() {
        let mut frame = ipv4_syn_frame();
        frame.truncate(14 + 20 + 20);
        frame[14 + 2..14 + 4].copy_from_slice(&40_u16.to_be_bytes());
        frame[14 + 20 + 12] = 5 << 4;
        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();

        assert_eq!(
            TcpFingerprint::from_initial_syn(&packet)
                .unwrap()
                .ja4t
                .fingerprint
                .as_ref(),
            "64240_00_00_00"
        );
    }

    #[test]
    fn ja4t_ignores_end_of_options_marker() {
        let mut frame = ipv4_syn_frame();
        frame[14 + 20 + 37] = 0;
        let packet = TcpPacket::parse(&frame, LinkLayer::Ethernet).unwrap();

        assert_eq!(
            TcpFingerprint::from_initial_syn(&packet)
                .unwrap()
                .ja4t
                .fingerprint
                .as_ref(),
            "64240_2-4-8-1_1460_00"
        );
    }

    #[test]
    fn network_estimate_includes_the_satori_sixteen_hop_bucket() {
        assert_eq!(network_estimate(0).initial_hop_limit, 0);
        assert_eq!(network_estimate(16).initial_hop_limit, 16);
        assert_eq!(network_estimate(17).initial_hop_limit, 32);
    }
}
