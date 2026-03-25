//! Minimal Ethernet/IPv4/IPv6/TCP/UDP packet parser.
//!
//! Extracts connection metadata from raw Ethernet frames without external
//! packet-parsing dependencies. Handles IPv4 and IPv6 with TCP and UDP —
//! other protocols are silently skipped.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parsed connection metadata extracted from a raw Ethernet frame.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    /// Application-layer payload size in bytes (total_len - IP header - transport header).
    pub payload_len: usize,
    /// True if the packet originated from the VM (source MAC matches VM MAC).
    pub from_vm: bool,
    /// Offset into the original frame where the transport payload starts.
    /// Used for DNS parsing. 0 if not available.
    pub transport_payload_offset: usize,
}

/// Transport-layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

const ETH_HEADER_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_IPV6: u16 = 0x86DD;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// Parse a raw Ethernet frame into connection metadata.
///
/// `vm_mac` identifies the VM's virtual NIC so we can determine packet direction.
/// If `None`, all packets are treated as VM-originated (outbound).
pub fn parse_frame(frame: &[u8], vm_mac: Option<&[u8; 6]>) -> Option<ParsedPacket> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }

    let eth_type = u16::from_be_bytes([frame[12], frame[13]]);
    let src_mac = &frame[6..12];
    let from_vm = vm_mac.map_or(true, |vm| src_mac == vm);

    match eth_type {
        ETH_TYPE_IPV4 => parse_ipv4(&frame[ETH_HEADER_LEN..], from_vm),
        ETH_TYPE_IPV6 => parse_ipv6(&frame[ETH_HEADER_LEN..], from_vm),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8], from_vm: bool) -> Option<ParsedPacket> {
    if data.len() < 20 {
        return None;
    }

    let version_ihl = data[0];
    if version_ihl >> 4 != 4 {
        return None;
    }

    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let protocol_num = data[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    let transport = &data[ihl..];
    let (src_port, dst_port, transport_header_len, protocol) =
        parse_transport(transport, protocol_num)?;

    let payload_len = total_len.saturating_sub(ihl + transport_header_len);
    // Offset from start of IP data: ETH_HEADER_LEN + ihl + transport_header_len
    let transport_payload_offset = ETH_HEADER_LEN + ihl + transport_header_len;

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        payload_len,
        from_vm,
        transport_payload_offset,
    })
}

fn parse_ipv6(data: &[u8], from_vm: bool) -> Option<ParsedPacket> {
    // IPv6 fixed header is 40 bytes.
    if data.len() < 40 {
        return None;
    }

    if data[0] >> 4 != 6 {
        return None;
    }

    let payload_length = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_header = data[6];

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    dst_bytes.copy_from_slice(&data[24..40]);

    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let transport = &data[40..];
    let (src_port, dst_port, transport_header_len, protocol) =
        parse_transport(transport, next_header)?;

    let payload_len = payload_length.saturating_sub(transport_header_len);
    let transport_payload_offset = ETH_HEADER_LEN + 40 + transport_header_len;

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        payload_len,
        from_vm,
        transport_payload_offset,
    })
}

/// Parse TCP or UDP transport header, shared by IPv4 and IPv6.
fn parse_transport(
    transport: &[u8],
    protocol_num: u8,
) -> Option<(u16, u16, usize, Protocol)> {
    match protocol_num {
        IP_PROTO_TCP => {
            if transport.len() < 20 {
                return None;
            }
            let sp = u16::from_be_bytes([transport[0], transport[1]]);
            let dp = u16::from_be_bytes([transport[2], transport[3]]);
            let data_offset = ((transport[12] >> 4) as usize) * 4;
            Some((sp, dp, data_offset, Protocol::Tcp))
        }
        IP_PROTO_UDP => {
            if transport.len() < 8 {
                return None;
            }
            let sp = u16::from_be_bytes([transport[0], transport[1]]);
            let dp = u16::from_be_bytes([transport[2], transport[3]]);
            Some((sp, dp, 8, Protocol::Udp))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet + IPv4 + TCP frame for testing.
    fn build_tcp_frame(
        src_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet header (14 bytes)
        frame.extend_from_slice(&[0xFF; 6]); // dst MAC (broadcast)
        frame.extend_from_slice(&src_mac); // src MAC
        frame.extend_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

        let ip_header_len: u8 = 20;
        let tcp_header_len: u8 = 20;
        let total_len =
            ip_header_len as u16 + tcp_header_len as u16 + payload.len() as u16;

        // IPv4 header (20 bytes, no options)
        frame.push(0x45); // version=4, IHL=5
        frame.push(0x00); // DSCP/ECN
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00; 4]); // ID, flags, fragment
        frame.push(64); // TTL
        frame.push(IP_PROTO_TCP);
        frame.extend_from_slice(&[0x00; 2]); // checksum (not validated)
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        // TCP header (20 bytes, no options)
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00; 4]); // seq
        frame.extend_from_slice(&[0x00; 4]); // ack
        frame.push(0x50); // data offset = 5 (20 bytes), no flags high nibble
        frame.push(0x02); // SYN flag
        frame.extend_from_slice(&[0xFF, 0xFF]); // window
        frame.extend_from_slice(&[0x00; 4]); // checksum + urgent

        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn parse_tcp_frame() {
        let vm_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let frame = build_tcp_frame(
            vm_mac,
            [10, 0, 0, 2],
            [104, 16, 0, 1],
            12345,
            443,
            b"hello",
        );

        let pkt = parse_frame(&frame, Some(&vm_mac)).expect("should parse");
        assert_eq!(pkt.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(pkt.dst_ip, IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)));
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 443);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.payload_len, 5);
        assert!(pkt.from_vm);
    }

    #[test]
    fn parse_inbound_packet() {
        let vm_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let other_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let frame = build_tcp_frame(
            other_mac,
            [104, 16, 0, 1],
            [10, 0, 0, 2],
            443,
            12345,
            b"response",
        );

        let pkt = parse_frame(&frame, Some(&vm_mac)).expect("should parse");
        assert!(!pkt.from_vm);
        assert_eq!(pkt.dst_port, 12345);
        assert_eq!(pkt.payload_len, 8);
    }

    #[test]
    fn reject_too_short() {
        assert!(parse_frame(&[0u8; 10], None).is_none());
    }

    #[test]
    fn reject_unknown_ethertype() {
        let mut frame = vec![0u8; 60];
        // Set EtherType to ARP (0x0806) — not handled
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert!(parse_frame(&frame, None).is_none());
    }

    /// Build a minimal Ethernet + IPv4 + UDP frame.
    fn build_udp_frame(
        src_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        frame.extend_from_slice(&[0xFF; 6]);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

        let ip_header_len: u8 = 20;
        let udp_header_len: u8 = 8;
        let total_len =
            ip_header_len as u16 + udp_header_len as u16 + payload.len() as u16;

        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00; 4]);
        frame.push(64);
        frame.push(IP_PROTO_UDP);
        frame.extend_from_slice(&[0x00; 2]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = udp_header_len as u16 + payload.len() as u16;
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0x00; 2]); // checksum

        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn parse_udp_frame() {
        let mac = [0x01; 6];
        let frame = build_udp_frame(mac, [10, 0, 0, 2], [8, 8, 8, 8], 5000, 53, b"dns query");

        let pkt = parse_frame(&frame, Some(&mac)).expect("should parse UDP");
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert_eq!(pkt.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(pkt.dst_port, 53);
        assert_eq!(pkt.payload_len, 9);
        assert!(pkt.from_vm);
    }

    /// Build a minimal Ethernet + IPv6 + TCP frame.
    fn build_ipv6_tcp_frame(
        src_mac: [u8; 6],
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet header
        frame.extend_from_slice(&[0xFF; 6]); // dst MAC
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

        let tcp_header_len: u16 = 20;
        let payload_length = tcp_header_len + payload.len() as u16;

        // IPv6 header (40 bytes)
        frame.push(0x60); // version=6, traffic class high nibble
        frame.extend_from_slice(&[0x00; 3]); // traffic class low + flow label
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame.push(IP_PROTO_TCP); // next header
        frame.push(64); // hop limit
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        // TCP header (20 bytes)
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00; 4]); // seq
        frame.extend_from_slice(&[0x00; 4]); // ack
        frame.push(0x50); // data offset = 5
        frame.push(0x02); // SYN
        frame.extend_from_slice(&[0xFF, 0xFF]); // window
        frame.extend_from_slice(&[0x00; 4]); // checksum + urgent

        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn parse_ipv6_tcp_frame() {
        let vm_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        // 2001:db8::1 → 2607:f8b0:4004:800::200e (Google)
        let src_ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let dst_ip: [u8; 16] = [
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x04, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0x20, 0x0e,
        ];

        let frame = build_ipv6_tcp_frame(vm_mac, src_ip, dst_ip, 54321, 443, b"hello6");

        let pkt = parse_frame(&frame, Some(&vm_mac)).expect("should parse IPv6");
        assert_eq!(
            pkt.src_ip,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(pkt.dst_port, 443);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.payload_len, 6);
        assert!(pkt.from_vm);
    }

    #[test]
    fn reject_ipv6_too_short() {
        let mut frame = vec![0u8; ETH_HEADER_LEN + 30]; // IPv6 header needs 40 bytes
        frame[12] = 0x86;
        frame[13] = 0xDD;
        frame[14] = 0x60; // version 6
        assert!(parse_frame(&frame, None).is_none());
    }
}
