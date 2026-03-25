//! E2B provider adapter.
//!
//! E2B sandboxes are API-managed Firecracker microVMs with a specific
//! filesystem layout and tap device naming convention. Each sandbox gets
//! a unique ID, and the rootfs is exposed via snapshot-based block device
//! mounts at well-known paths.
//!
//! Conventions:
//! - Tap device: `tap{sandbox_index}` (e.g., `tap0`, `tap1`)
//! - Sandbox rootfs: `/e2b/sandboxes/{sandbox_id}/rootfs`
//! - Snapshot dir: `/e2b/sandboxes/{sandbox_id}/snapshots/{label}`
//! - VM metadata: `/e2b/sandboxes/{sandbox_id}/metadata.json`

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sandtrace_capture::CapturedEvent;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, capture_fs_changes};

use crate::SandboxProvider;

/// Default base directory where E2B stores sandbox data.
pub const E2B_SANDBOXES_DIR: &str = "/e2b/sandboxes";

/// E2B sandbox provider configuration.
#[derive(Debug, Clone)]
pub struct E2bProvider {
    /// Base directory for E2B sandboxes (default: `/e2b/sandboxes`).
    pub sandboxes_dir: String,
    /// Tap device name. If `None`, auto-derived from sandbox index.
    pub tap_device: Option<String>,
    /// Label for the "before" snapshot (e.g., "pre-execution").
    /// If `None`, defaults to "base".
    pub before_snapshot: Option<String>,
    /// Label for the "after" snapshot (e.g., "post-execution").
    /// If `None`, defaults to "current".
    pub after_snapshot: Option<String>,
}

impl Default for E2bProvider {
    fn default() -> Self {
        Self {
            sandboxes_dir: E2B_SANDBOXES_DIR.to_string(),
            tap_device: None,
            before_snapshot: None,
            after_snapshot: None,
        }
    }
}

impl E2bProvider {
    /// Resolve the snapshot directory for a given sandbox and label.
    fn snapshot_dir(&self, sandbox_id: &str, label: &str) -> PathBuf {
        Path::new(&self.sandboxes_dir)
            .join(sandbox_id)
            .join("snapshots")
            .join(label)
    }

    /// Resolve the rootfs directory for a given sandbox.
    fn rootfs_dir(&self, sandbox_id: &str) -> PathBuf {
        Path::new(&self.sandboxes_dir)
            .join(sandbox_id)
            .join("rootfs")
    }
}

impl SandboxProvider for E2bProvider {
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>> {
        let before_label = self.before_snapshot.as_deref().unwrap_or("base");
        let after_label = self.after_snapshot.as_deref().unwrap_or("current");

        let before_dir = self.snapshot_dir(sandbox_id, before_label);
        let after_dir = self.snapshot_dir(sandbox_id, after_label);

        // Fall back to rootfs as the "after" directory if snapshot dirs
        // don't exist (direct rootfs comparison mode).
        let after_dir = if after_dir.is_dir() {
            after_dir
        } else {
            self.rootfs_dir(sandbox_id)
        };

        tracing::info!(
            sandbox_id,
            before = %before_dir.display(),
            after = %after_dir.display(),
            "attaching to E2B sandbox"
        );

        let config = FsTrackingConfig {
            agent_id: sandbox_id.to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            method: FsTrackingMethod::SnapshotDiff {
                before: before_dir,
                after: after_dir,
            },
        };

        let fs_events = capture_fs_changes(&config)
            .context("E2B filesystem capture failed")?;

        Ok(Box::new(fs_events.into_iter()))
    }

    fn name(&self) -> &str {
        "e2b"
    }
}

/// Check whether the system looks like an E2B environment.
pub fn detect() -> bool {
    Path::new(E2B_SANDBOXES_DIR).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_dir_resolution() {
        let provider = E2bProvider::default();
        let dir = provider.snapshot_dir("sb-abc123", "base");
        assert_eq!(dir, PathBuf::from("/e2b/sandboxes/sb-abc123/snapshots/base"));
    }

    #[test]
    fn rootfs_dir_resolution() {
        let provider = E2bProvider::default();
        let dir = provider.rootfs_dir("sb-abc123");
        assert_eq!(dir, PathBuf::from("/e2b/sandboxes/sb-abc123/rootfs"));
    }

    #[test]
    fn provider_name() {
        let provider = E2bProvider::default();
        assert_eq!(provider.name(), "e2b");
    }

    #[test]
    fn attach_with_tempdir_snapshots() {
        let base = tempfile::tempdir().unwrap();
        let sandbox_dir = base.path().join("test-sb/snapshots");
        std::fs::create_dir_all(sandbox_dir.join("base")).unwrap();
        std::fs::create_dir_all(sandbox_dir.join("current")).unwrap();

        // Add a file to "current" only
        std::fs::write(
            base.path().join("test-sb/snapshots/current/new.txt"),
            "hello",
        )
        .unwrap();

        let provider = E2bProvider {
            sandboxes_dir: base.path().to_string_lossy().to_string(),
            before_snapshot: Some("base".to_string()),
            after_snapshot: Some("current".to_string()),
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("test-sb").unwrap().collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, sandtrace_capture::EventType::FilesystemSummary);
    }

    #[test]
    fn attach_empty_snapshots() {
        let base = tempfile::tempdir().unwrap();
        let sandbox_dir = base.path().join("test-sb/snapshots");
        std::fs::create_dir_all(sandbox_dir.join("base")).unwrap();
        std::fs::create_dir_all(sandbox_dir.join("current")).unwrap();

        let provider = E2bProvider {
            sandboxes_dir: base.path().to_string_lossy().to_string(),
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("test-sb").unwrap().collect();
        assert!(events.is_empty());
    }
}
