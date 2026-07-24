mod capture;
mod latency;
mod proxy;

use std::net::{IpAddr, SocketAddr};

pub use capture::{CapturedPacket, PacketDirection, TcpCapture};
use pingly::tcp::{TcpFingerprint, TcpPacket};
pub use proxy::ProxyAnalysis;
use serde::Serialize;

/// TCP/IP details associated with one HTTP connection.
#[derive(Debug, Clone, Serialize)]
pub struct TcpAnalysis {
    /// Passive fingerprint derived from the connection's initial client SYN.
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<TcpFingerprint>,

    /// Captured packets belonging to the connection.
    packets: Box<[CapturedPacket]>,
}

impl TcpAnalysis {
    /// Builds an analysis from packets captured for one remote socket.
    pub fn from_packets(packets: Vec<CapturedPacket>) -> Self {
        let fingerprint = packets
            .iter()
            .rev()
            .find(|packet| {
                packet.direction == PacketDirection::Inbound && packet.packet.is_initial_syn()
            })
            .and_then(|packet| TcpFingerprint::from_initial_syn(&packet.packet));

        Self {
            fingerprint,
            packets: packets.into(),
        }
    }

    /// Returns `true` when the connection has no captured packets.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

impl CapturedPacket {
    fn direction_for(packet: &TcpPacket, server_port: u16) -> Option<PacketDirection> {
        if packet.destination.port() == server_port {
            Some(PacketDirection::Inbound)
        } else if packet.source.port() == server_port {
            Some(PacketDirection::Outbound)
        } else {
            None
        }
    }

    fn remote_address(&self) -> SocketAddr {
        connection_key(match self.direction {
            PacketDirection::Inbound => self.packet.source,
            PacketDirection::Outbound => self.packet.destination,
        })
    }
}

fn normalized_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn connection_key(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalized_ip(address.ip()), address.port())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::connection_key;

    #[test]
    fn matches_ipv4_mapped_remote_address() {
        let captured = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000));
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 50_000));

        assert_eq!(connection_key(captured), connection_key(remote));
    }

    #[test]
    fn ignores_ipv6_scope_when_matching_captured_packets() {
        let captured = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 50_000);
        let remote = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            50_000,
            0,
            3,
        ));

        assert_eq!(connection_key(captured), connection_key(remote));
    }
}
