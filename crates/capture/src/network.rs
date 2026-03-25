//! Network egress capture via Firecracker tap interface.
//!
//! Reads packets from the VM's tap device, extracts connection metadata
//! (destination host, port, payload size), and emits `CapturedEvent`s.

use anyhow::Result;
use crate::{CapturedEvent, EventType};

/// Configuration for network capture on a tap interface.
#[derive(Debug, Clone)]
pub struct NetworkCaptureConfig {
    /// Name of the tap device (e.g., "vmtap0")
    pub tap_device: String,
    /// Agent identifier for event attribution
    pub agent_id: String,
    /// Trace identifier for this capture session
    pub trace_id: String,
}

/// Captures network egress from a Firecracker tap interface.
///
/// Not yet implemented — requires raw socket access to the tap device
/// and packet parsing for TCP/TLS connection extraction.
pub fn capture_egress(_config: &NetworkCaptureConfig) -> Result<Vec<CapturedEvent>> {
    tracing::warn!("network capture not yet implemented");
    Ok(vec![])
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
    pub protocol: String,
}
