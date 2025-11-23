use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value as JsonValue;

use super::CapturedPacket;

pub fn parse_packet_with_pktparse(data: &[u8]) -> Option<JsonValue> {
    use pktparse::{ethernet, ip::IPProtocol, ipv4, ipv6, tcp};
    use serde_json::{json, to_value};

    // Try to parse the ethernet frame
    match ethernet::parse_ethernet_frame(data) {
        Ok((remaining, eth_frame)) => {
            let mut parsed = json!({
                "ethernet": {
                    "ethertype": to_value(&eth_frame.ethertype).unwrap_or_else(|_| json!("unknown"))
                }
            });

            // Parse IP layer
            match eth_frame.ethertype {
                ethernet::EtherType::IPv4 => {
                    if let Ok((tcp_udp_data, ipv4_hdr)) = ipv4::parse_ipv4_header(remaining) {
                        parsed["ipv4"] = to_value(&ipv4_hdr).unwrap_or_else(
                            |_| json!({"error": "Failed to serialize IPv4 header"}),
                        );

                        // Parse transport layer
                        match ipv4_hdr.protocol {
                            IPProtocol::TCP => {
                                if let Ok((payload, tcp_hdr)) = tcp::parse_tcp_header(tcp_udp_data)
                                {
                                    parsed["tcp"] = to_value(&tcp_hdr).unwrap_or_else(
                                        |_| json!({"error": "Failed to serialize TCP header"}),
                                    );

                                    // If there's application data, include a preview
                                    if !payload.is_empty() {
                                        let preview_len = std::cmp::min(payload.len(), 64);
                                        parsed["application_data"] = json!({
                                            "length": payload.len(),
                                            "preview_hex": hex::encode(&payload[..preview_len]),
                                            "preview_ascii": payload[..preview_len].iter()
                                                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                                .collect::<String>()
                                        });
                                    }
                                }
                            }
                            _ => {
                                parsed["unknown_transport"] = json!({
                                    "protocol": to_value(&ipv4_hdr.protocol).unwrap_or_else(|_| json!("unknown")),
                                    "data_length": tcp_udp_data.len()
                                });
                            }
                        }
                    }
                }
                ethernet::EtherType::IPv6 => {
                    if let Ok((tcp_udp_data, ipv6_hdr)) = ipv6::parse_ipv6_header(remaining) {
                        parsed["ipv6"] = to_value(&ipv6_hdr).unwrap_or_else(
                            |_| json!({"error": "Failed to serialize IPv6 header"}),
                        );

                        // Parse transport layer for IPv6
                        match ipv6_hdr.next_header {
                            IPProtocol::TCP => {
                                if let Ok((payload, tcp_hdr)) = tcp::parse_tcp_header(tcp_udp_data)
                                {
                                    parsed["tcp"] = to_value(&tcp_hdr).unwrap_or_else(
                                        |_| json!({"error": "Failed to serialize TCP header"}),
                                    );

                                    // If there's application data, include a preview
                                    if !payload.is_empty() {
                                        let preview_len = std::cmp::min(payload.len(), 64);
                                        parsed["application_data"] = json!({
                                            "length": payload.len(),
                                            "preview_hex": hex::encode(&payload[..preview_len]),
                                            "preview_ascii": payload[..preview_len].iter()
                                                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                                .collect::<String>()
                                        });
                                    }
                                }
                            }
                            _ => {
                                parsed["unknown_transport"] = json!({
                                    "protocol": to_value(&ipv6_hdr.next_header).unwrap_or_else(|_| json!("unknown")),
                                    "data_length": tcp_udp_data.len()
                                });
                            }
                        }
                    }
                }
                _ => {
                    parsed["unknown_protocol"] = json!({
                        "ethertype": to_value(&eth_frame.ethertype).unwrap_or_else(|_| json!("unknown")),
                        "data_length": remaining.len()
                    });
                }
            }

            Some(parsed)
        }
        Err(_) => Some(json!({
            "parse_error": "Failed to parse ethernet frame",
            "raw_data_length": data.len(),
            "raw_data_preview": hex::encode(&data[..std::cmp::min(data.len(), 32)])
        })),
    }
}

pub fn parse_packet(data: &[u8], server_port: u16) -> Option<CapturedPacket> {
    use pnet::packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        Packet,
    };

    let ethernet = EthernetPacket::new(data)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let parsed_info = parse_packet_with_pktparse(data);

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(ethernet.payload())?;

            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                let tcp = TcpPacket::new(ipv4.payload())?;
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();

                if dst_port == server_port {
                    return Some(CapturedPacket {
                        timestamp,
                        direction: "inbound".to_string(),
                        src_ip: ipv4.get_source().to_string(),
                        dst_ip: ipv4.get_destination().to_string(),
                        src_port,
                        dst_port,
                        protocol: "TCP".to_string(),
                        packet_size: data.len(),
                        parsed_info,
                    });
                }
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(ethernet.payload())?;

            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                let tcp = TcpPacket::new(ipv6.payload())?;
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();

                if dst_port == server_port {
                    return Some(CapturedPacket {
                        timestamp,
                        direction: "inbound".to_string(),
                        src_ip: ipv6.get_source().to_string(),
                        dst_ip: ipv6.get_destination().to_string(),
                        src_port,
                        dst_port,
                        protocol: "TCP".to_string(),
                        packet_size: data.len(),
                        parsed_info,
                    });
                }
            }
        }
        _ => {}
    }

    None
}
