use std::{
    collections::{HashMap, VecDeque},
    error::Error as StdError,
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use pcap::{Active, Capture, Device, Linktype, PacketHeader};
use pingly::tcp::{LinkLayer, TcpPacket};
use serde::{Deserialize, Serialize};

type CaptureError = Box<dyn StdError + Send + Sync>;

/// Direction of a captured packet relative to the Pingly listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDirection {
    /// Packet sent by the remote client to Pingly.
    Inbound,

    /// Packet sent by Pingly to the remote client.
    Outbound,
}

/// One timestamped TCP packet captured for the configured listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedPacket {
    /// Packet timestamp supplied by libpcap, in microseconds since the Unix epoch.
    pub timestamp_us: u64,

    /// Packet direction relative to the configured server port.
    pub direction: PacketDirection,

    /// Decoded IP and TCP wire fields.
    #[serde(flatten)]
    pub packet: TcpPacket,
}

struct CaptureInner {
    packets: Arc<Mutex<CaptureStore>>,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for CaptureInner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
    }
}

/// Shared handle to the background libpcap capture worker.
#[derive(Clone)]
pub struct TcpCapture {
    inner: Arc<CaptureInner>,
}

impl TcpCapture {
    /// Opens a capture device and starts a background worker with bounded storage.
    pub fn start(
        max_connections: usize,
        server_port: u16,
        interface: Option<&str>,
    ) -> Result<Self, CaptureError> {
        if max_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP capture connection capacity must be greater than zero",
            )
            .into());
        }

        let devices = Device::list()?;
        let device = choose_device(&devices, interface)?;
        let device_name = device.name.clone();
        let mut capture = Capture::from_device(device)?
            .promisc(device_name != "any")
            .snaplen(65_535)
            .timeout(100)
            .immediate_mode(true)
            .open()?;
        let link_layer = link_layer(capture.get_datalink())?;
        let filter = format!("tcp port {server_port}");
        capture.filter(&filter, true)?;
        let capture = capture.setnonblock()?;

        let packets = Arc::new(Mutex::new(CaptureStore::new(max_connections)));
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_packets = packets.clone();
        let worker_shutdown = shutdown.clone();
        let worker = thread::Builder::new()
            .name("pingly-tcp-capture".to_owned())
            .spawn(move || {
                if let Err(error) = capture_loop(
                    capture,
                    link_layer,
                    server_port,
                    worker_packets,
                    worker_shutdown,
                ) {
                    tracing::error!(%error, "TCP packet capture stopped");
                }
            })?;

        tracing::info!(interface = %device_name, %filter, "TCP packet capture started");
        Ok(Self {
            inner: Arc::new(CaptureInner {
                packets,
                shutdown,
                worker: Mutex::new(Some(worker)),
            }),
        })
    }

    /// Returns a copy of one remote socket's packets in wire order.
    pub fn connection_packets(&self, remote: SocketAddr) -> Vec<CapturedPacket> {
        lock(&self.inner.packets).connection_packets(remote)
    }

    /// Stops the worker and waits for its capture loop to exit.
    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Release);
        if let Some(worker) = lock(&self.inner.worker).take() {
            let _ = worker.join();
        }
    }
}

const MAX_PACKETS_PER_CONNECTION: usize = 64;

struct CaptureStore {
    /// Latest captured generation for each normalized remote socket.
    connections: HashMap<SocketAddr, VecDeque<CapturedPacket>>,

    /// Connection insertion order used for bounded FIFO eviction.
    insertion_order: VecDeque<SocketAddr>,

    /// Maximum number of remote connection generations retained at once.
    max_connections: usize,
}

impl CaptureStore {
    fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::with_capacity(max_connections),
            insertion_order: VecDeque::with_capacity(max_connections),
            max_connections,
        }
    }

    fn push(&mut self, packet: CapturedPacket) {
        let remote = packet.remote_address();
        let starts_connection =
            packet.direction == PacketDirection::Inbound && packet.packet.is_initial_syn();

        if starts_connection {
            self.remove(remote);
        }

        if !self.connections.contains_key(&remote) {
            self.evict_oldest_if_full();
            self.insertion_order.push_back(remote);
            self.connections.insert(remote, VecDeque::new());
        }

        if let Some(packets) = self.connections.get_mut(&remote) {
            if packets.len() < MAX_PACKETS_PER_CONNECTION {
                packets.push_back(packet);
            }
        }
    }

    fn connection_packets(&self, remote: SocketAddr) -> Vec<CapturedPacket> {
        self.connections
            .get(&super::connection_key(remote))
            .map(|packets| packets.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn remove(&mut self, remote: SocketAddr) {
        self.connections.remove(&remote);
        self.insertion_order
            .retain(|candidate| *candidate != remote);
    }

    fn evict_oldest_if_full(&mut self) {
        if self.connections.len() < self.max_connections {
            return;
        }

        if let Some(oldest) = self.insertion_order.pop_front() {
            self.connections.remove(&oldest);
        }
    }
}

fn choose_device(devices: &[Device], interface: Option<&str>) -> Result<Device, CaptureError> {
    if let Some(interface) = interface {
        return devices
            .iter()
            .find(|device| device.name == interface)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("packet capture interface {interface} was not found"),
                )
                .into()
            });
    }

    devices
        .iter()
        .find(|device| device.name == "any")
        .cloned()
        .or_else(|| Device::lookup().ok().flatten())
        .or_else(|| devices.first().cloned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no pcap devices found").into())
}

fn link_layer(linktype: Linktype) -> Result<LinkLayer, CaptureError> {
    let link_layer = match linktype {
        Linktype::NULL | Linktype::LOOP => LinkLayer::Null,
        Linktype::ETHERNET => LinkLayer::Ethernet,
        Linktype::LINUX_SLL => LinkLayer::LinuxSll,
        Linktype::LINUX_SLL2 => LinkLayer::LinuxSll2,
        Linktype::RAW => LinkLayer::RawIp,
        Linktype::IPV4 => LinkLayer::Ipv4,
        Linktype::IPV6 => LinkLayer::Ipv6,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported pcap link type {}", other.0),
            )
            .into())
        }
    };
    Ok(link_layer)
}

fn capture_loop(
    mut capture: Capture<Active>,
    link_layer: LinkLayer,
    server_port: u16,
    packets: Arc<Mutex<CaptureStore>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), pcap::Error> {
    while !shutdown.load(Ordering::Acquire) {
        match capture.next_packet() {
            Ok(captured) => {
                let Ok(packet) = TcpPacket::parse(captured.data, link_layer) else {
                    continue;
                };
                let Some(direction) = CapturedPacket::direction_for(&packet, server_port) else {
                    continue;
                };
                let captured = CapturedPacket {
                    timestamp_us: timestamp_us(captured.header),
                    direction,
                    packet,
                };
                lock(&packets).push(captured);
            }
            Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn timestamp_us(header: &PacketHeader) -> u64 {
    let seconds = u64::try_from(header.ts.tv_sec).unwrap_or_default();
    let micros = u64::try_from(header.ts.tv_usec).unwrap_or_default();
    seconds.saturating_mul(1_000_000).saturating_add(micros)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use pingly::tcp::{LinkLayer, TcpPacket};

    use super::{CaptureStore, CapturedPacket, PacketDirection, MAX_PACKETS_PER_CONNECTION};

    const SERVER_PORT: u16 = 443;

    #[test]
    fn new_syn_replaces_a_reused_remote_socket_generation() {
        let remote = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 50_000));
        let mut store = CaptureStore::new(2);
        store.push(packet(remote, 1, PacketDirection::Inbound, 10, 0, 0x02));
        store.push(packet(remote, 2, PacketDirection::Outbound, 20, 11, 0x12));
        store.push(packet(remote, 3, PacketDirection::Inbound, 11, 21, 0x10));
        store.push(packet(remote, 4, PacketDirection::Inbound, 30, 0, 0x02));

        let packets = store.connection_packets(remote);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet.tcp.sequence_number, 30);
    }

    #[test]
    fn evicts_the_oldest_connection_when_capacity_is_reached() {
        let first = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 50_001));
        let second = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 50_002));
        let third = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 3), 50_003));
        let mut store = CaptureStore::new(2);

        for (timestamp, remote) in [(1, first), (2, second), (3, third)] {
            store.push(packet(
                remote,
                timestamp,
                PacketDirection::Inbound,
                10,
                0,
                0x02,
            ));
        }

        assert!(store.connection_packets(first).is_empty());
        assert_eq!(store.connection_packets(second).len(), 1);
        assert_eq!(store.connection_packets(third).len(), 1);
    }

    #[test]
    fn per_connection_limit_preserves_the_initial_handshake() {
        let remote = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 50_000));
        let mut store = CaptureStore::new(1);
        store.push(packet(remote, 1, PacketDirection::Inbound, 10, 0, 0x02));
        store.push(packet(remote, 2, PacketDirection::Outbound, 20, 11, 0x12));
        store.push(packet(remote, 3, PacketDirection::Inbound, 11, 21, 0x10));

        for timestamp in 4..=(MAX_PACKETS_PER_CONNECTION as u64 + 10) {
            store.push(packet(
                remote,
                timestamp,
                PacketDirection::Inbound,
                11,
                21,
                0x10,
            ));
        }

        let packets = store.connection_packets(remote);
        assert_eq!(packets.len(), MAX_PACKETS_PER_CONNECTION);
        assert!(packets[0].packet.is_initial_syn());
        assert!(packets[1].packet.is_syn_ack());
        assert!(packets[2].packet.is_handshake_ack());
    }

    fn packet(
        remote: SocketAddr,
        timestamp_us: u64,
        direction: PacketDirection,
        sequence_number: u32,
        acknowledgment_number: u32,
        flags: u8,
    ) -> CapturedPacket {
        let server = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), SERVER_PORT));
        let (source, destination) = match direction {
            PacketDirection::Inbound => (remote, server),
            PacketDirection::Outbound => (server, remote),
        };
        let mut bytes = vec![0_u8; 40];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&40_u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        let (source_ip, destination_ip) = match (source.ip(), destination.ip()) {
            (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
                (source, destination)
            }
            _ => unreachable!("test fixture uses IPv4 endpoints"),
        };
        bytes[12..16].copy_from_slice(&source_ip.octets());
        bytes[16..20].copy_from_slice(&destination_ip.octets());
        let tcp = &mut bytes[20..];
        tcp[0..2].copy_from_slice(&source.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence_number.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgment_number.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;

        CapturedPacket {
            timestamp_us,
            direction,
            packet: TcpPacket::parse(&bytes, LinkLayer::Ipv4).unwrap(),
        }
    }
}
