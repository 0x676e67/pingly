mod parser;

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use pcap::{Capture, Device};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub timestamp: u64,
    pub direction: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_size: usize,
    pub parsed_info: Option<JsonValue>,
}

#[derive(Debug, Clone)]
pub struct TcpCaptureTrack {
    packets: Arc<Mutex<VecDeque<CapturedPacket>>>,
    max_packets: usize,
    server_port: u16,
    shutdown_flag: Arc<AtomicBool>,
}

impl TcpCaptureTrack {
    pub fn new(max_packets: usize, server_port: u16) -> Self {
        Self {
            packets: Arc::new(Mutex::new(VecDeque::new())),
            max_packets,
            server_port,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_capture(
        &self,
        interface: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let packets = self.packets.clone();
        let max_packets = self.max_packets;
        let server_port = self.server_port;
        let shutdown_flag = self.shutdown_flag.clone();

        tracing::info!("Attempting to start packet capture on port {}", server_port);

        // Test basic pcap functionality first
        match self.test_pcap_basic(interface.clone()) {
            Ok(device_name) => {
                tracing::info!("Packet capture test passed, using device: {}", device_name);

                // Spawn the actual capture task
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = run_capture_blocking(
                        packets,
                        max_packets,
                        server_port,
                        interface,
                        shutdown_flag,
                    ) {
                        tracing::error!("Packet capture task error: {}", e);
                    }
                });

                // Give the capture task a moment to initialize before returning
                std::thread::sleep(std::time::Duration::from_millis(500));
                tracing::info!("Packet capture background task started");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Packet capture initialization failed: {}", e);
                Err(e)
            }
        }
    }

    fn test_pcap_basic(
        &self,
        interface: Option<String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use pcap::{Capture, Device};

        let devices = Device::list()?;
        tracing::info!("Available network devices:");
        for (i, device) in devices.iter().enumerate() {
            tracing::info!(
                "  {}: {} ({})",
                i,
                device.name,
                device
                    .desc
                    .as_ref()
                    .unwrap_or(&"No description".to_string())
            );
        }

        let device = if let Some(iface) = interface {
            devices
                .into_iter()
                .find(|d| d.name == iface)
                .ok_or(format!("Interface {} not found", iface))?
        } else {
            // For localhost testing, prefer loopback interface over 'any'
            devices
                .iter()
                .find(|d| d.name == "lo")
                .cloned()
                .or_else(|| devices.iter().find(|d| d.name == "any").cloned())
                .unwrap_or_else(|| devices.into_iter().next().unwrap())
        };

        let use_promisc = device.name != "any";
        let _test_cap = Capture::from_device(device.clone())?
            .promisc(use_promisc)
            .snaplen(1500)
            .timeout(100)
            .open()?;

        Ok(device.name)
    }

    pub fn get_packets_for_client(&self, client_ip: &str, client_port: u16) -> Vec<CapturedPacket> {
        let packets_guard = self.packets.lock().unwrap();
        packets_guard
            .iter()
            .filter(|packet| packet.src_ip == client_ip && packet.src_port == client_port)
            .cloned()
            .collect()
    }

    pub fn clear_packets_for_client(&self, client_ip: &str, client_port: u16) {
        let mut packets_guard = self.packets.lock().unwrap();
        packets_guard
            .retain(|packet| !(packet.src_ip == client_ip && packet.src_port == client_port));
    }

    pub fn shutdown(&self) {
        tracing::info!("Signaling packet capture to shutdown");
        self.shutdown_flag.store(true, Ordering::SeqCst);
    }
}

fn run_capture_blocking(
    packets: Arc<Mutex<VecDeque<CapturedPacket>>>,
    max_packets: usize,
    server_port: u16,
    interface: Option<String>,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let devices = Device::list()?;
    let device = if let Some(iface) = interface {
        devices
            .into_iter()
            .find(|d| d.name == iface)
            .ok_or(format!("Interface {} not found", iface))?
    } else {
        devices
            .iter()
            .find(|d| d.name == "lo")
            .cloned()
            .or_else(|| devices.iter().find(|d| d.name == "any").cloned())
            .unwrap_or_else(|| devices.into_iter().next().unwrap())
    };

    tracing::info!("Starting packet capture on interface: {}", device.name);

    let use_promisc = device.name != "any";
    let mut cap = Capture::from_device(device)?
        .promisc(use_promisc)
        .snaplen(65535)
        .timeout(100)
        .open()?;

    let filter = format!("tcp and dst port {}", server_port);
    tracing::info!("Setting packet filter: {}", filter);
    cap.filter(&filter, true)?;

    tracing::info!("Packet capture loop started, waiting for packets...");
    let mut packet_count = 0;

    loop {
        if shutdown_flag.load(Ordering::SeqCst) {
            tracing::info!("Shutdown flag is set, terminating packet capture loop");
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                tracing::info!(
                    "Raw packet #{} captured, size: {} bytes",
                    packet_count,
                    packet.data.len()
                );

                if let Some(captured_packet) = parser::parse_packet(&packet.data, server_port) {
                    let mut packets_guard = packets.lock().unwrap();

                    if packets_guard.len() >= max_packets {
                        packets_guard.pop_front();
                    }

                    packets_guard.push_back(captured_packet.clone());
                    tracing::info!(
                        "Captured packet #{}: {} -> {} ({})",
                        packet_count,
                        captured_packet.src_ip,
                        captured_packet.dst_ip,
                        captured_packet.direction
                    );
                } else {
                    let parsed_info = parser::parse_packet_with_pktparse(&packet.data);
                    let raw_packet = CapturedPacket {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        direction: "unknown".to_string(),
                        src_ip: "unknown".to_string(),
                        dst_ip: "unknown".to_string(),
                        src_port: 0,
                        dst_port: server_port,
                        protocol: "RAW".to_string(),
                        packet_size: packet.data.len(),
                        parsed_info,
                    };

                    let mut packets_guard = packets.lock().unwrap();
                    if packets_guard.len() >= max_packets {
                        packets_guard.pop_front();
                    }
                    packets_guard.push_back(raw_packet);

                    tracing::warn!("Stored raw packet #{} (parsing failed)", packet_count);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is normal, continue
                continue;
            }
            Err(e) => {
                tracing::error!("Packet capture error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    tracing::info!(
        "Packet capture thread exiting, processed {} packets",
        packet_count
    );
    Ok(())
}
