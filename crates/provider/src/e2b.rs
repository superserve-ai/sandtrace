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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sandtrace_capture::CaptureStream;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, watch_fs_changes};
use sandtrace_capture::network::{NetworkCaptureConfig, capture_egress_continuous};
use sandtrace_capture::syscall::{SyscallMonitorConfig, capture_syscalls_continuous};

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
    /// PID of the Firecracker jailer process for syscall monitoring.
    /// If `None`, syscall capture is skipped.
    pub jailer_pid: Option<u32>,
}

impl Default for E2bProvider {
    fn default() -> Self {
        Self {
            sandboxes_dir: E2B_SANDBOXES_DIR.to_string(),
            tap_device: None,
            before_snapshot: None,
            after_snapshot: None,
            jailer_pid: None,
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
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream> {
        let trace_id = uuid::Uuid::new_v4().to_string();
        let shutdown = Arc::new(AtomicBool::new(false));
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
            "attaching to E2B sandbox (continuous)"
        );

        let (tx, stream) = CaptureStream::channel();

        // Filesystem monitoring thread.
        let fs_config = FsTrackingConfig {
            agent_id: sandbox_id.to_string(),
            trace_id: trace_id.clone(),
            method: FsTrackingMethod::SnapshotDiff {
                before: before_dir,
                after: after_dir,
            },
        };
        match watch_fs_changes(&fs_config, tx.clone(), shutdown.clone(), Duration::from_secs(2)) {
            Ok(_) => tracing::info!("filesystem watch thread started"),
            Err(e) => tracing::warn!(error = %e, "filesystem watch failed, continuing without it"),
        }

        // Network capture thread (if configured).
        if let Some(tap) = &self.tap_device {
            let net_config = NetworkCaptureConfig {
                tap_device: tap.clone(),
                agent_id: sandbox_id.to_string(),
                trace_id: trace_id.clone(),
                ..Default::default()
            };
            match capture_egress_continuous(&net_config, tx.clone(), shutdown.clone(), Duration::from_secs(5)) {
                Ok(_) => tracing::info!("network capture thread started"),
                Err(e) => tracing::warn!(error = %e, "network capture failed, continuing without it"),
            }
        }

        // Syscall capture thread (if configured).
        if let Some(pid) = self.jailer_pid {
            let sc_config = SyscallMonitorConfig {
                jailer_pid: pid,
                agent_id: sandbox_id.to_string(),
                trace_id,
                ..Default::default()
            };
            match capture_syscalls_continuous(&sc_config, tx.clone(), shutdown.clone(), Duration::from_secs(5)) {
                Ok(_) => tracing::info!("syscall capture thread started"),
                Err(e) => tracing::warn!(error = %e, "syscall capture failed, continuing without it"),
            }
        }

        drop(tx);
        Ok(stream)
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

        let stream = provider.attach("test-sb").unwrap();
        // Continuous stream — collect events with a timeout
        let mut events = Vec::new();
        while let Some(ev) = stream.recv_timeout(std::time::Duration::from_secs(5)) {
            events.push(ev);
        }
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

        let stream = provider.attach("test-sb").unwrap();
        // No changes — stream should produce no events within the timeout
        let event = stream.recv_timeout(std::time::Duration::from_secs(4));
        assert!(event.is_none());
    }
}
