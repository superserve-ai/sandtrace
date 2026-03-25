//! Filesystem change tracking via block device or overlay diffs.
//!
//! Compares the filesystem state before and after agent execution to
//! produce a summary of created, modified, and deleted files.

use anyhow::Result;
use crate::{CapturedEvent, EventType};

/// Configuration for filesystem change tracking.
#[derive(Debug, Clone)]
pub struct FsTrackingConfig {
    /// Path to the overlay or block device to monitor
    pub overlay_path: String,
    /// Agent identifier for event attribution
    pub agent_id: String,
    /// Trace identifier for this capture session
    pub trace_id: String,
}

/// Capture filesystem changes by diffing overlay layers.
///
/// Not yet implemented — requires overlay filesystem support or
/// block device snapshotting.
pub fn capture_fs_changes(_config: &FsTrackingConfig) -> Result<Vec<CapturedEvent>> {
    tracing::warn!("filesystem capture not yet implemented");
    Ok(vec![])
}

/// Structured representation of a filesystem change summary.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FsSummary {
    pub files_created: Vec<String>,
    pub files_modified: Vec<String>,
    pub files_deleted: Vec<String>,
    pub total_bytes_written: u64,
}

impl FsSummary {
    pub fn to_event(&self, agent_id: &str, trace_id: &str) -> CapturedEvent {
        CapturedEvent::new(
            EventType::FilesystemSummary,
            agent_id,
            trace_id,
            serde_json::to_value(self).expect("FsSummary is always serializable"),
        )
    }
}
