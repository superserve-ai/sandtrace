//! Generic snapshot-based provider adapter.
//!
//! For providers that expose block-device snapshots or devcontainer
//! filesystems (E2B, Daytona), this adapter compares two
//! directory trees (before and after agent execution) to detect changes.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sandtrace_capture::CaptureStream;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, watch_fs_changes};

use crate::SandboxProvider;

/// Generic snapshot-diff provider for block devices and devcontainers.
///
/// Works with any provider that can mount or expose filesystem state at
/// two points in time: a "before" snapshot taken before agent execution,
/// and an "after" snapshot taken after.
#[derive(Debug, Clone)]
pub struct SnapshotProvider {
    /// Human-readable provider name (e.g., "e2b", "daytona", "generic").
    pub provider_name: String,
    /// Path to the mounted before-snapshot directory.
    pub before_dir: String,
    /// Path to the mounted after-snapshot directory.
    pub after_dir: String,
}

impl SandboxProvider for SnapshotProvider {
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream> {
        tracing::info!(
            sandbox_id,
            provider = %self.provider_name,
            before = %self.before_dir,
            after = %self.after_dir,
            "attaching via snapshot diff (continuous)"
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, stream) = CaptureStream::channel();

        let config = FsTrackingConfig {
            agent_id: sandbox_id.to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            method: FsTrackingMethod::SnapshotDiff {
                before: PathBuf::from(&self.before_dir),
                after: PathBuf::from(&self.after_dir),
            },
        };

        match watch_fs_changes(&config, tx.clone(), shutdown, Duration::from_secs(2)) {
            Ok(_) => tracing::info!("filesystem watch thread started"),
            Err(e) => tracing::warn!(error = %e, "filesystem watch failed"),
        }

        drop(tx);
        Ok(stream)
    }

    fn name(&self) -> &str {
        &self.provider_name
    }
}
