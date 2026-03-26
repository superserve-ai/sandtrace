pub mod filesystem;
pub mod network;
pub mod packet;
pub mod syscall;
pub mod tap;

use std::sync::mpsc;
use std::time::Duration;

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
    SyscallActivity,
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

/// A continuous stream of captured events backed by an mpsc channel.
///
/// Capture threads send events into the channel; the consumer iterates
/// via the `Iterator` impl which blocks on `recv` with a timeout so
/// the caller can check for shutdown signals between events.
pub struct CaptureStream {
    rx: mpsc::Receiver<CapturedEvent>,
}

impl CaptureStream {
    /// Create a new `CaptureStream` from an mpsc receiver.
    pub fn new(rx: mpsc::Receiver<CapturedEvent>) -> Self {
        Self { rx }
    }

    /// Create a sender/stream pair for feeding events into a stream.
    pub fn channel() -> (mpsc::Sender<CapturedEvent>, Self) {
        let (tx, rx) = mpsc::channel();
        (tx, Self { rx })
    }

    /// Try to receive the next event, blocking for up to `timeout`.
    /// Returns `None` if the timeout expires or all senders are dropped.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<CapturedEvent> {
        self.rx.recv_timeout(timeout).ok()
    }
}
