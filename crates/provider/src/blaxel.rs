//! Blaxel provider adapter.
//!
//! Blaxel manages Firecracker VMs with its own runtime and filesystem
//! layout. VMs are organized by function/deployment ID with rootfs
//! snapshots taken at checkpoint boundaries.
//!
//! Conventions:
//! - VM directory: `/var/lib/blaxel/vms/{vm_id}`
//! - Rootfs: `{vm_dir}/rootfs`
//! - Snapshots: `{vm_dir}/checkpoints/{label}`
//! - Tap device: `blx{vm_id_prefix}` (first 6 chars of VM ID)
//! - Config: `{vm_dir}/vm.json`

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sandtrace_capture::CapturedEvent;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, capture_fs_changes};

use crate::SandboxProvider;

/// Default base directory for Blaxel VM data.
pub const BLAXEL_VMS_DIR: &str = "/var/lib/blaxel/vms";

/// Blaxel VM provider configuration.
#[derive(Debug, Clone)]
pub struct BlaxelProvider {
    /// Base directory for Blaxel VMs.
    pub vms_dir: String,
    /// Tap device name. If `None`, auto-derived from VM ID.
    pub tap_device: Option<String>,
    /// Label for the "before" checkpoint. Defaults to "init".
    pub before_checkpoint: Option<String>,
    /// Label for the "after" checkpoint. Defaults to "latest".
    pub after_checkpoint: Option<String>,
}

impl Default for BlaxelProvider {
    fn default() -> Self {
        Self {
            vms_dir: BLAXEL_VMS_DIR.to_string(),
            tap_device: None,
            before_checkpoint: None,
            after_checkpoint: None,
        }
    }
}

impl BlaxelProvider {
    /// Resolve the checkpoint directory for a given VM and label.
    fn checkpoint_dir(&self, vm_id: &str, label: &str) -> PathBuf {
        Path::new(&self.vms_dir)
            .join(vm_id)
            .join("checkpoints")
            .join(label)
    }

    /// Resolve the rootfs directory for a given VM.
    fn rootfs_dir(&self, vm_id: &str) -> PathBuf {
        Path::new(&self.vms_dir).join(vm_id).join("rootfs")
    }
}

impl SandboxProvider for BlaxelProvider {
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>> {
        let before_label = self.before_checkpoint.as_deref().unwrap_or("init");
        let after_label = self.after_checkpoint.as_deref().unwrap_or("latest");

        let before_dir = self.checkpoint_dir(sandbox_id, before_label);
        let after_dir = self.checkpoint_dir(sandbox_id, after_label);

        // Fall back to rootfs as the "after" directory if the "latest"
        // checkpoint doesn't exist (live rootfs comparison mode).
        let after_dir = if after_dir.is_dir() {
            after_dir
        } else {
            self.rootfs_dir(sandbox_id)
        };

        tracing::info!(
            sandbox_id,
            before = %before_dir.display(),
            after = %after_dir.display(),
            "attaching to Blaxel VM"
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
            .context("Blaxel filesystem capture failed")?;

        Ok(Box::new(fs_events.into_iter()))
    }

    fn name(&self) -> &str {
        "blaxel"
    }
}

/// Check whether the system looks like a Blaxel environment.
pub fn detect() -> bool {
    Path::new(BLAXEL_VMS_DIR).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_dir_resolution() {
        let provider = BlaxelProvider::default();
        let dir = provider.checkpoint_dir("vm-xyz", "init");
        assert_eq!(dir, PathBuf::from("/var/lib/blaxel/vms/vm-xyz/checkpoints/init"));
    }

    #[test]
    fn rootfs_dir_resolution() {
        let provider = BlaxelProvider::default();
        let dir = provider.rootfs_dir("vm-xyz");
        assert_eq!(dir, PathBuf::from("/var/lib/blaxel/vms/vm-xyz/rootfs"));
    }

    #[test]
    fn provider_name() {
        let provider = BlaxelProvider::default();
        assert_eq!(provider.name(), "blaxel");
    }

    #[test]
    fn attach_with_checkpoints() {
        let base = tempfile::tempdir().unwrap();
        let vm_dir = base.path().join("vm-1/checkpoints");
        std::fs::create_dir_all(vm_dir.join("init")).unwrap();
        std::fs::create_dir_all(vm_dir.join("latest")).unwrap();
        std::fs::write(
            base.path().join("vm-1/checkpoints/latest/output.txt"),
            "results",
        )
        .unwrap();

        let provider = BlaxelProvider {
            vms_dir: base.path().to_string_lossy().to_string(),
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("vm-1").unwrap().collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, sandtrace_capture::EventType::FilesystemSummary);
    }

    #[test]
    fn attach_falls_back_to_rootfs() {
        let base = tempfile::tempdir().unwrap();

        // Create init checkpoint and rootfs, but no "latest" checkpoint
        let init_dir = base.path().join("vm-1/checkpoints/init");
        let rootfs = base.path().join("vm-1/rootfs");
        std::fs::create_dir_all(&init_dir).unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::write(rootfs.join("file.txt"), "data").unwrap();

        let provider = BlaxelProvider {
            vms_dir: base.path().to_string_lossy().to_string(),
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("vm-1").unwrap().collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn attach_empty_checkpoints() {
        let base = tempfile::tempdir().unwrap();
        let vm_dir = base.path().join("vm-1/checkpoints");
        std::fs::create_dir_all(vm_dir.join("init")).unwrap();
        std::fs::create_dir_all(vm_dir.join("latest")).unwrap();

        let provider = BlaxelProvider {
            vms_dir: base.path().to_string_lossy().to_string(),
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("vm-1").unwrap().collect();
        assert!(events.is_empty());
    }
}
