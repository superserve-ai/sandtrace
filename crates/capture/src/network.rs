//! Network egress capture via Firecracker tap interface.
//!
//! Opens an AF_PACKET socket on the VM's tap device, parses TCP/UDP packets,
//! tracks per-connection byte counters, and emits `CapturedEvent`s of type
//! `network_egress`. All capture is host-side — no guest modification needed.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::packet::{self, ParsedPacket, Protocol};
use crate::tap::TapSniffer;
use crate::{CapturedEvent, EventType};

/// Configuration for network capture on a tap interface.
#[derive(Debug, Clone)]
pub struct NetworkCaptureConfig {
    /// Name of the tap device (e.g., "tap0", "vmtap0").
    pub tap_device: String,
    /// Agent identifier for event attribution.
    pub agent_id: String,
    /// Trace identifier for this capture session.
    pub trace_id: String,
    /// Optional VM MAC address for determining packet direction.
    /// If `None`, all packets are treated as VM-originated.
    pub vm_mac: Option<[u8; 6]>,
    /// How long to capture before returning results. `None` means capture
    /// until the socket timeout fires once with no traffic.
    pub capture_duration: Option<Duration>,
    /// Socket read timeout per individual recv call (default: 1 s).
    pub read_timeout: Duration,
}

impl Default for NetworkCaptureConfig {
    fn default() -> Self {
        Self {
            tap_device: String::new(),
            agent_id: String::new(),
            trace_id: String::new(),
            vm_mac: None,
            capture_duration: None,
            read_timeout: Duration::from_secs(1),
        }
    }
}

/// Captures network egress from a Firecracker tap interface.
///
/// Opens an AF_PACKET socket on `config.tap_device`, reads packets for the
/// configured duration, and returns one `CapturedEvent` per unique
/// (dest_ip, dest_port, protocol) tuple observed.
pub fn capture_egress(config: &NetworkCaptureConfig) -> Result<Vec<CapturedEvent>> {
    let mut sniffer = TapSniffer::open(&config.tap_device)?;
    sniffer.set_timeout(config.read_timeout)?;

    let mut tracker = ConnectionTracker::new();
    let start = Instant::now();

    loop {
        // Check duration limit.
        if let Some(dur) = config.capture_duration {
            if start.elapsed() >= dur {
                break;
            }
        }

        match sniffer.read_frame()? {
            Some(frame) => {
                if let Some(pkt) = packet::parse_frame(frame, config.vm_mac.as_ref()) {
                    tracker.record_packet(&pkt);
                }
            }
            None => {
                // Timeout with no traffic — if no duration set, stop now.
                if config.capture_duration.is_none() {
                    break;
                }
            }
        }
    }

    Ok(tracker.drain_events(&config.agent_id, &config.trace_id))
}

/// Parse a network egress event payload into structured fields.
pub fn parse_egress_payload(event: &CapturedEvent) -> Option<EgressInfo> {
    if event.event_type != EventType::NetworkEgress {
        return None;
    }
    serde_json::from_value(event.payload.clone()).ok()
}

/// Structured representation of a network egress event.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EgressInfo {
    pub dest_host: String,
    pub dest_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_count: u64,
    pub protocol: String,
}

// ── Connection tracking ───────────────────────────────────────────────

/// Key for aggregating packets into logical connections.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    dest_ip: Ipv4Addr,
    dest_port: u16,
    protocol: Protocol,
}

/// Accumulated statistics for a single connection.
#[derive(Debug, Clone)]
struct ConnectionStats {
    bytes_sent: u64,
    bytes_received: u64,
    packet_count: u64,
}

/// Tracks network connections and accumulates per-connection byte counters.
pub struct ConnectionTracker {
    connections: HashMap<ConnectionKey, ConnectionStats>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Record a parsed packet, updating the appropriate connection counters.
    pub fn record_packet(&mut self, pkt: &ParsedPacket) {
        let (key, is_outbound) = if pkt.from_vm {
            // VM → external: destination is the remote host.
            (
                ConnectionKey {
                    dest_ip: pkt.dst_ip,
                    dest_port: pkt.dst_port,
                    protocol: pkt.protocol,
                },
                true,
            )
        } else {
            // External → VM: source is the remote host (the "connection" destination).
            (
                ConnectionKey {
                    dest_ip: pkt.src_ip,
                    dest_port: pkt.src_port,
                    protocol: pkt.protocol,
                },
                false,
            )
        };

        let stats = self
            .connections
            .entry(key)
            .or_insert_with(|| ConnectionStats {
                bytes_sent: 0,
                bytes_received: 0,
                packet_count: 0,
            });

        if is_outbound {
            stats.bytes_sent += pkt.payload_len as u64;
        } else {
            stats.bytes_received += pkt.payload_len as u64;
        }
        stats.packet_count += 1;
    }

    /// Drain all tracked connections into `CapturedEvent`s.
    pub fn drain_events(&mut self, agent_id: &str, trace_id: &str) -> Vec<CapturedEvent> {
        let connections = std::mem::take(&mut self.connections);
        connections
            .into_iter()
            .map(|(key, stats)| {
                let payload = serde_json::json!({
                    "dest_host": key.dest_ip.to_string(),
                    "dest_port": key.dest_port,
                    "protocol": key.protocol.to_string(),
                    "bytes_sent": stats.bytes_sent,
                    "bytes_received": stats.bytes_received,
                    "packet_count": stats.packet_count,
                });
                CapturedEvent::new(EventType::NetworkEgress, agent_id, trace_id, payload)
            })
            .collect()
    }

    /// Number of unique connections currently tracked.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_aggregates_outbound() {
        let mut tracker = ConnectionTracker::new();

        let pkt = ParsedPacket {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(104, 16, 0, 1),
            src_port: 54321,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 100,
            from_vm: true,
        };

        tracker.record_packet(&pkt);
        tracker.record_packet(&pkt);

        assert_eq!(tracker.connection_count(), 1);

        let events = tracker.drain_events("agent-1", "trace-1");
        assert_eq!(events.len(), 1);

        let info: EgressInfo =
            serde_json::from_value(events[0].payload.clone()).expect("parse payload");
        assert_eq!(info.dest_host, "104.16.0.1");
        assert_eq!(info.dest_port, 443);
        assert_eq!(info.bytes_sent, 200);
        assert_eq!(info.bytes_received, 0);
        assert_eq!(info.packet_count, 2);
        assert_eq!(info.protocol, "tcp");
    }

    #[test]
    fn tracker_aggregates_bidirectional() {
        let mut tracker = ConnectionTracker::new();

        // Outbound packet
        tracker.record_packet(&ParsedPacket {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 5000,
            dst_port: 53,
            protocol: Protocol::Udp,
            payload_len: 40,
            from_vm: true,
        });

        // Inbound response (from same remote host:port)
        tracker.record_packet(&ParsedPacket {
            src_ip: Ipv4Addr::new(8, 8, 8, 8),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 53,
            dst_port: 5000,
            protocol: Protocol::Udp,
            payload_len: 512,
            from_vm: false,
        });

        assert_eq!(tracker.connection_count(), 1);

        let events = tracker.drain_events("agent-1", "trace-1");
        let info: EgressInfo =
            serde_json::from_value(events[0].payload.clone()).expect("parse payload");
        assert_eq!(info.dest_host, "8.8.8.8");
        assert_eq!(info.dest_port, 53);
        assert_eq!(info.bytes_sent, 40);
        assert_eq!(info.bytes_received, 512);
        assert_eq!(info.protocol, "udp");
    }

    #[test]
    fn tracker_separates_connections() {
        let mut tracker = ConnectionTracker::new();

        tracker.record_packet(&ParsedPacket {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(104, 16, 0, 1),
            src_port: 54321,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 100,
            from_vm: true,
        });

        tracker.record_packet(&ParsedPacket {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 54322,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 200,
            from_vm: true,
        });

        assert_eq!(tracker.connection_count(), 2);

        let events = tracker.drain_events("agent-1", "trace-1");
        assert_eq!(events.len(), 2);

        // All events should be NetworkEgress type
        for ev in &events {
            assert_eq!(ev.event_type, EventType::NetworkEgress);
            assert_eq!(ev.agent_id, "agent-1");
            assert_eq!(ev.trace_id, "trace-1");
        }
    }

    #[test]
    fn drain_clears_tracker() {
        let mut tracker = ConnectionTracker::new();
        tracker.record_packet(&ParsedPacket {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(8, 8, 4, 4),
            src_port: 1234,
            dst_port: 53,
            protocol: Protocol::Udp,
            payload_len: 50,
            from_vm: true,
        });

        let first = tracker.drain_events("a", "t");
        assert_eq!(first.len(), 1);

        let second = tracker.drain_events("a", "t");
        assert!(second.is_empty());
        assert_eq!(tracker.connection_count(), 0);
    }

    #[test]
    fn parse_egress_payload_roundtrip() {
        let event = CapturedEvent::new(
            EventType::NetworkEgress,
            "agent-1",
            "trace-1",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443,
                "protocol": "tcp",
                "bytes_sent": 1024,
                "bytes_received": 4096,
                "packet_count": 15,
            }),
        );

        let info = parse_egress_payload(&event).expect("should parse");
        assert_eq!(info.dest_host, "api.stripe.com");
        assert_eq!(info.dest_port, 443);
        assert_eq!(info.bytes_sent, 1024);
        assert_eq!(info.bytes_received, 4096);
        assert_eq!(info.packet_count, 15);
    }

    #[test]
    fn parse_egress_payload_wrong_type() {
        let event = CapturedEvent::new(
            EventType::FilesystemSummary,
            "agent-1",
            "trace-1",
            serde_json::json!({}),
        );
        assert!(parse_egress_payload(&event).is_none());
    }
}
