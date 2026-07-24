//! TCP three-way handshake timing based on the RFC 9293 state transitions.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.3>.

use std::time::Duration;

use super::{CapturedPacket, PacketDirection};

const MAX_HANDSHAKE_RTT_US: u64 = 10_000_000;

/// Measures the server-to-peer handshake RTT from SYN-ACK transmission to final ACK receipt.
pub(super) fn tcp_handshake_rtt(packets: &[CapturedPacket]) -> Option<Duration> {
    handshake_rtt(packets.iter().map(Segment::from))
}

#[derive(Clone, Copy)]
struct Segment {
    timestamp_us: u64,
    direction: PacketDirection,
    sequence_number: u32,
    acknowledgment_number: u32,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

impl From<&CapturedPacket> for Segment {
    fn from(packet: &CapturedPacket) -> Self {
        let flags = &packet.packet.tcp.flags;
        Self {
            timestamp_us: packet.timestamp_us,
            direction: packet.direction,
            sequence_number: packet.packet.tcp.sequence_number,
            acknowledgment_number: packet.packet.tcp.acknowledgment_number,
            syn: flags.syn(),
            ack: flags.ack(),
            fin: flags.fin(),
            rst: flags.rst(),
        }
    }
}

fn handshake_rtt(segments: impl IntoIterator<Item = Segment>) -> Option<Duration> {
    let mut client_sequence = None;
    let mut syn_ack = None;
    let mut latest_rtt = None;

    for segment in segments {
        if segment.direction == PacketDirection::Inbound && segment.syn && !segment.ack {
            client_sequence = Some(segment.sequence_number);
            syn_ack = None;
            continue;
        }

        if segment.direction == PacketDirection::Outbound && segment.syn && segment.ack {
            let Some(sequence) = client_sequence else {
                continue;
            };
            if segment.acknowledgment_number == sequence.wrapping_add(1) {
                // Keep the most recent retransmission so packet loss is not counted as RTT.
                syn_ack = Some((
                    segment.timestamp_us,
                    segment.sequence_number,
                    segment.acknowledgment_number,
                ));
            }
            continue;
        }

        let Some((sent_at, server_sequence, expected_client_sequence)) = syn_ack else {
            continue;
        };
        let completes_handshake = segment.direction == PacketDirection::Inbound
            && segment.ack
            && !segment.syn
            && !segment.fin
            && !segment.rst
            && segment.acknowledgment_number == server_sequence.wrapping_add(1)
            && segment.sequence_number == expected_client_sequence;
        if !completes_handshake {
            continue;
        }

        let Some(elapsed) = segment.timestamp_us.checked_sub(sent_at) else {
            continue;
        };
        if elapsed <= MAX_HANDSHAKE_RTT_US {
            latest_rtt = Some(Duration::from_micros(elapsed));
            // The first matching ACK completes this SYN/SYN-ACK generation. Later data
            // commonly carries the same sequence and acknowledgment numbers.
            syn_ack = None;
        }
    }

    latest_rtt
}

#[cfg(test)]
mod tests {
    use super::{handshake_rtt, PacketDirection, Segment};

    #[test]
    fn measures_matching_three_way_handshake() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(1_750, PacketDirection::Inbound, 11, 21, false, true),
        ];

        assert_eq!(handshake_rtt(segments).unwrap().as_micros(), 650);
    }

    #[test]
    fn measures_from_latest_syn_ack_retransmission() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(2_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(2_500, PacketDirection::Inbound, 11, 21, false, true),
        ];

        assert_eq!(handshake_rtt(segments).unwrap().as_micros(), 400);
    }

    #[test]
    fn does_not_replace_handshake_rtt_with_later_data_ack() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(1_750, PacketDirection::Inbound, 11, 21, false, true),
            segment(3_500, PacketDirection::Inbound, 11, 21, false, true),
        ];

        assert_eq!(handshake_rtt(segments).unwrap().as_micros(), 650);
    }

    #[test]
    fn rejects_ack_for_another_sequence_space() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(1_750, PacketDirection::Inbound, 99, 42, false, true),
        ];

        assert!(handshake_rtt(segments).is_none());
    }

    #[test]
    fn returns_the_latest_complete_handshake_for_a_reused_socket() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(1_750, PacketDirection::Inbound, 11, 21, false, true),
            segment(5_000, PacketDirection::Inbound, 30, 0, true, false),
            segment(5_100, PacketDirection::Outbound, 40, 31, true, true),
            segment(5_500, PacketDirection::Inbound, 31, 41, false, true),
        ];

        assert_eq!(handshake_rtt(segments).unwrap().as_micros(), 400);
    }

    #[test]
    fn ignores_out_of_order_timestamps_before_a_valid_handshake() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(1_050, PacketDirection::Inbound, 11, 21, false, true),
            segment(5_000, PacketDirection::Inbound, 30, 0, true, false),
            segment(5_100, PacketDirection::Outbound, 40, 31, true, true),
            segment(5_500, PacketDirection::Inbound, 31, 41, false, true),
        ];

        assert_eq!(handshake_rtt(segments).unwrap().as_micros(), 400);
    }

    #[test]
    fn preserves_zero_microsecond_local_measurements() {
        let segments = [
            segment(1_000, PacketDirection::Inbound, 10, 0, true, false),
            segment(1_100, PacketDirection::Outbound, 20, 11, true, true),
            segment(1_100, PacketDirection::Inbound, 11, 21, false, true),
        ];

        assert_eq!(handshake_rtt(segments), Some(std::time::Duration::ZERO));
    }

    fn segment(
        timestamp_us: u64,
        direction: PacketDirection,
        sequence_number: u32,
        acknowledgment_number: u32,
        syn: bool,
        ack: bool,
    ) -> Segment {
        Segment {
            timestamp_us,
            direction,
            sequence_number,
            acknowledgment_number,
            syn,
            ack,
            fin: false,
            rst: false,
        }
    }
}
