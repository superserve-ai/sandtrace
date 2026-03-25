pub mod network;
pub mod filesystem;
pub mod syscall;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A raw captured event from the hypervisor layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedEvent {
    pub event_id: String,
    pub event_type: EventType,
    pub agent_id: String,
    pub trace_id: String,
    pub wall_time: DateTime<Utc>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    NetworkEgress,
    FilesystemSummary,
    PolicyViolation,
}

impl CapturedEvent {
    pub fn new(
        event_type: EventType,
        agent_id: &str,
        trace_id: &str,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            agent_id: agent_id.to_string(),
            trace_id: trace_id.to_string(),
            wall_time: Utc::now(),
            payload,
        }
    }
}
