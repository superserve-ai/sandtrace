//! Network egress capture via Firecracker tap interface.
//!
//! Opens an AF_PACKET socket on the VM's tap device, parses TCP/UDP packets,
//! tracks per-connection byte counters, and emits `CapturedEvent`s of type
//! `network_egress`. All capture is host-side — no guest modification needed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
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
    let mut dns = DnsCache::new();
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
                    if pkt.transport_payload_offset < frame.len() {
                        dns.inspect_packet(&pkt, &frame[pkt.transport_payload_offset..]);
                    }
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

    Ok(tracker.drain_events_with_dns(&config.agent_id, &config.trace_id, &dns))
}

/// Continuously captures network egress and sends events through a channel.
///
/// Runs until `shutdown` is set to true or the channel is closed.
/// Flushes accumulated connection stats every `flush_interval`.
pub fn capture_egress_streaming(
    config: &NetworkCaptureConfig,
    tx: std::sync::mpsc::Sender<CapturedEvent>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    flush_interval: Duration,
) -> Result<()> {
    let mut sniffer = TapSniffer::open(&config.tap_device)?;
    sniffer.set_timeout(config.read_timeout)?;

    let mut tracker = ConnectionTracker::new();
    let mut dns = DnsCache::new();
    let mut last_flush = Instant::now();

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        match sniffer.read_frame() {
            Ok(Some(frame)) => {
                if let Some(pkt) = packet::parse_frame(frame, config.vm_mac.as_ref()) {
                    if pkt.transport_payload_offset < frame.len() {
                        dns.inspect_packet(&pkt, &frame[pkt.transport_payload_offset..]);
                    }
                    tracker.record_packet(&pkt);
                }
            }
            Ok(None) => {
                // Read timeout — no traffic, continue waiting
            }
            Err(e) => {
                // Transient errors (e.g., tap device briefly unavailable during
                // VM pause/resume) — log and retry rather than killing the thread.
                tracing::warn!(error = %e, "network capture read error, retrying");
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        // Periodically flush accumulated connections as events.
        if last_flush.elapsed() >= flush_interval && tracker.connection_count() > 0 {
            let events = tracker.drain_events_with_dns(
                &config.agent_id, &config.trace_id, &dns,
            );
            for event in events {
                if tx.send(event).is_err() {
                    return Ok(());
                }
            }
            last_flush = Instant::now();
        }
    }

    // Final flush on shutdown.
    if tracker.connection_count() > 0 {
        let events = tracker.drain_events_with_dns(
            &config.agent_id, &config.trace_id, &dns,
        );
        for event in events {
            let _ = tx.send(event);
        }
    }

    Ok(())
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

// ── DNS sniffing ─────────────────────────────────────────────────────

/// Passive DNS cache built by sniffing DNS response packets on the tap.
/// Maps IP addresses to hostnames observed in DNS A/AAAA responses.
pub struct DnsCache {
    /// IP → hostname mapping. Most recent answer wins.
    names: HashMap<IpAddr, String>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            names: HashMap::new(),
        }
    }

    /// Try to extract DNS answers from a UDP packet with dst/src port 53.
    /// Updates the internal cache with any A/AAAA records found.
    pub fn inspect_packet(&mut self, pkt: &ParsedPacket, transport_payload: &[u8]) {
        // Only inspect UDP port 53 responses (from DNS server back to VM).
        if pkt.protocol != Protocol::Udp {
            return;
        }
        // DNS responses come FROM port 53.
        let is_response = if pkt.from_vm {
            pkt.dst_port == 53
        } else {
            pkt.src_port == 53
        };
        if !is_response || pkt.from_vm {
            // We want responses (from server), not queries (from VM).
            return;
        }
        self.parse_dns_response(transport_payload);
    }

    /// Resolve an IP address to a hostname if known.
    pub fn resolve(&self, ip: &IpAddr) -> Option<&str> {
        self.names.get(ip).map(|s| s.as_str())
    }

    /// Parse a DNS response and extract A/AAAA answer records.
    fn parse_dns_response(&mut self, data: &[u8]) {
        // DNS header is 12 bytes minimum.
        if data.len() < 12 {
            return;
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        // Check QR bit (bit 15) — must be 1 for response.
        if flags & 0x8000 == 0 {
            return;
        }
        // Check RCODE (bits 0-3) — must be 0 (no error).
        if flags & 0x000F != 0 {
            return;
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        if ancount == 0 {
            return;
        }

        // Skip past the question section.
        let mut pos = 12;
        for _ in 0..qdcount {
            pos = match skip_dns_name(data, pos) {
                Some(p) => p,
                None => return,
            };
            pos += 4; // QTYPE (2) + QCLASS (2)
            if pos > data.len() {
                return;
            }
        }

        // Extract the query name from the first question (if available)
        // for attributing answer records.
        let query_name = parse_dns_name(data, 12);

        // Parse answer records.
        for _ in 0..ancount {
            if pos + 10 > data.len() {
                return;
            }

            // Skip the name (may be a pointer).
            pos = match skip_dns_name(data, pos) {
                Some(p) => p,
                None => return,
            };

            if pos + 10 > data.len() {
                return;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

            if pos + rdlength > data.len() {
                return;
            }

            if let Some(ref name) = query_name {
                match rtype {
                    1 if rdlength == 4 => {
                        // A record — IPv4
                        let ip = IpAddr::V4(Ipv4Addr::new(
                            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                        ));
                        self.names.insert(ip, name.clone());
                    }
                    28 if rdlength == 16 => {
                        // AAAA record — IPv6
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&data[pos..pos + 16]);
                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
                        self.names.insert(ip, name.clone());
                    }
                    _ => {}
                }
            }

            pos += rdlength;
        }
    }
}

/// Skip past a DNS name (handles compression pointers).
/// Returns the position after the name.
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes, name ends here.
            return Some(pos + 2);
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None; // Prevent infinite loops.
        }
    }
}

/// Parse a DNS name at the given position, following compression pointers.
/// Returns the decoded domain name (e.g., "api.stripe.com").
fn parse_dns_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut jumps = 0;

    loop {
        if pos >= data.len() || jumps > 128 {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= data.len() {
                return None;
            }
            let offset = ((len & 0x3F) << 8 | data[pos + 1] as usize) as usize;
            pos = offset;
            jumps += 1;
            continue;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
        jumps += 1;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

// ── Connection tracking ───────────────────────────────────────────────

/// Key for aggregating packets into logical connections.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    dest_ip: IpAddr,
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

/// Maximum number of unique connections to track per flush interval.
/// Prevents unbounded memory growth from port scans or connection floods.
const MAX_TRACKED_CONNECTIONS: usize = 10_000;

/// Tracks network connections and accumulates per-connection byte counters.
pub struct ConnectionTracker {
    connections: HashMap<ConnectionKey, ConnectionStats>,
    dropped: u64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            dropped: 0,
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

        // If this is a new connection, check the cap.
        if !self.connections.contains_key(&key)
            && self.connections.len() >= MAX_TRACKED_CONNECTIONS
        {
            self.dropped += 1;
            return;
        }

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
    /// Uses IP addresses as `dest_host`.
    pub fn drain_events(&mut self, agent_id: &str, trace_id: &str) -> Vec<CapturedEvent> {
        self.drain_events_with_dns(agent_id, trace_id, &DnsCache::new())
    }

    /// Drain all tracked connections into `CapturedEvent`s.
    /// Enriches `dest_host` with DNS hostnames when available.
    pub fn drain_events_with_dns(
        &mut self,
        agent_id: &str,
        trace_id: &str,
        dns: &DnsCache,
    ) -> Vec<CapturedEvent> {
        if self.dropped > 0 {
            tracing::warn!(
                dropped = self.dropped,
                "connection tracker overflow, some connections were not tracked"
            );
            self.dropped = 0;
        }
        let connections = std::mem::take(&mut self.connections);
        connections
            .into_iter()
            .map(|(key, stats)| {
                let dest_host = dns
                    .resolve(&key.dest_ip)
                    .unwrap_or(&key.dest_ip.to_string())
                    .to_string();
                let payload = serde_json::json!({
                    "dest_host": dest_host,
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
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)),
            src_port: 54321,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 100,
            from_vm: true,
            transport_payload_offset: 0,
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
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 5000,
            dst_port: 53,
            protocol: Protocol::Udp,
            payload_len: 40,
            from_vm: true,
            transport_payload_offset: 0,
        });

        // Inbound response (from same remote host:port)
        tracker.record_packet(&ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 53,
            dst_port: 5000,
            protocol: Protocol::Udp,
            payload_len: 512,
            from_vm: false,
            transport_payload_offset: 0,
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
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)),
            src_port: 54321,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 100,
            from_vm: true,
            transport_payload_offset: 0,
        });

        tracker.record_packet(&ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            src_port: 54322,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 200,
            from_vm: true,
            transport_payload_offset: 0,
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
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            src_port: 1234,
            dst_port: 53,
            protocol: Protocol::Udp,
            payload_len: 50,
            from_vm: true,
            transport_payload_offset: 0,
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

    #[test]
    fn dns_cache_parses_a_record() {
        let mut dns = DnsCache::new();

        // Minimal DNS response: api.stripe.com → 104.16.0.1
        // Header: ID=0x1234, QR=1 response, OPCODE=0, RCODE=0
        //         QDCOUNT=1, ANCOUNT=1
        let mut response = Vec::new();
        response.extend_from_slice(&[0x12, 0x34]); // ID
        response.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question: api.stripe.com IN A
        response.push(3); response.extend_from_slice(b"api");
        response.push(6); response.extend_from_slice(b"stripe");
        response.push(3); response.extend_from_slice(b"com");
        response.push(0); // end of name
        response.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        response.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        // Answer: (pointer to question name) IN A 104.16.0.1
        response.extend_from_slice(&[0xC0, 0x0C]); // name pointer to offset 12
        response.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        response.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL=300
        response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        response.extend_from_slice(&[104, 16, 0, 1]); // RDATA

        // Simulate a DNS response packet (from server, port 53)
        let pkt = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 53,
            dst_port: 5000,
            protocol: Protocol::Udp,
            payload_len: response.len(),
            from_vm: false,
            transport_payload_offset: 0,
        };

        dns.inspect_packet(&pkt, &response);

        let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1));
        assert_eq!(dns.resolve(&ip), Some("api.stripe.com"));
    }

    #[test]
    fn dns_cache_enriches_dest_host() {
        let mut dns = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1));
        dns.names.insert(ip, "api.stripe.com".to_string());

        let mut tracker = ConnectionTracker::new();
        tracker.record_packet(&ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)),
            src_port: 54321,
            dst_port: 443,
            protocol: Protocol::Tcp,
            payload_len: 100,
            from_vm: true,
            transport_payload_offset: 0,
        });

        let events = tracker.drain_events_with_dns("agent-1", "trace-1", &dns);
        let info: EgressInfo =
            serde_json::from_value(events[0].payload.clone()).expect("parse payload");
        assert_eq!(info.dest_host, "api.stripe.com");
    }

    #[test]
    fn dns_cache_ignores_queries() {
        let mut dns = DnsCache::new();

        // A DNS query (from VM to server) should not populate the cache.
        let pkt = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 5000,
            dst_port: 53,
            protocol: Protocol::Udp,
            payload_len: 30,
            from_vm: true,
            transport_payload_offset: 0,
        };

        // Minimal DNS query header (QR=0)
        let query = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00];
        dns.inspect_packet(&pkt, &query);

        assert_eq!(dns.names.len(), 0);
    }
}
