//! Daytona provider adapter.
//!
//! Daytona creates devcontainer-based workspaces backed by Firecracker VMs.
//! Each workspace has a well-known directory layout with project files
//! mounted from the host and a devcontainer overlay.
//!
//! Conventions:
//! - Workspace root: `/var/lib/daytona/workspaces/{workspace_id}`
//! - Project directory: `{workspace_root}/projects/{project_name}`
//! - Devcontainer overlay upper: `{workspace_root}/overlay/upper`
//! - Tap device: `dt-{workspace_id_prefix}` (first 8 chars of workspace ID)
//! - Metadata: `{workspace_root}/workspace.json`

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sandtrace_capture::CapturedEvent;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, capture_fs_changes};

use crate::SandboxProvider;

/// Default base directory for Daytona workspaces.
pub const DAYTONA_WORKSPACES_DIR: &str = "/var/lib/daytona/workspaces";

/// Daytona workspace provider configuration.
#[derive(Debug, Clone)]
pub struct DaytonaProvider {
    /// Base directory for Daytona workspaces.
    pub workspaces_dir: String,
    /// Tap device name. If `None`, auto-derived from workspace ID.
    pub tap_device: Option<String>,
    /// Tracking method: overlay (default) or snapshot diff.
    pub tracking: DaytonaTracking,
}

/// How to track filesystem changes in a Daytona workspace.
#[derive(Debug, Clone)]
pub enum DaytonaTracking {
    /// Use OverlayFS upper-dir scanning (default for devcontainers).
    Overlay,
    /// Use snapshot diff with explicit before/after directories.
    Snapshot {
        before_dir: PathBuf,
        after_dir: PathBuf,
    },
}

impl Default for DaytonaProvider {
    fn default() -> Self {
        Self {
            workspaces_dir: DAYTONA_WORKSPACES_DIR.to_string(),
            tap_device: None,
            tracking: DaytonaTracking::Overlay,
        }
    }
}

impl DaytonaProvider {
    /// Resolve the overlay upper directory for a workspace.
    fn overlay_upper(&self, workspace_id: &str) -> PathBuf {
        Path::new(&self.workspaces_dir)
            .join(workspace_id)
            .join("overlay")
            .join("upper")
    }

    /// Resolve the workspace root directory.
    pub fn workspace_root(&self, workspace_id: &str) -> PathBuf {
        Path::new(&self.workspaces_dir).join(workspace_id)
    }
}

impl SandboxProvider for DaytonaProvider {
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>> {
        let method = match &self.tracking {
            DaytonaTracking::Overlay => {
                let upper = self.overlay_upper(sandbox_id);
                tracing::info!(
                    sandbox_id,
                    upper = %upper.display(),
                    "attaching to Daytona workspace via overlay"
                );
                FsTrackingMethod::OverlayUpperDir { upper_dir: upper }
            }
            DaytonaTracking::Snapshot { before_dir, after_dir } => {
                tracing::info!(
                    sandbox_id,
                    before = %before_dir.display(),
                    after = %after_dir.display(),
                    "attaching to Daytona workspace via snapshot diff"
                );
                FsTrackingMethod::SnapshotDiff {
                    before: before_dir.clone(),
                    after: after_dir.clone(),
                }
            }
        };

        let config = FsTrackingConfig {
            agent_id: sandbox_id.to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            method,
        };

        let fs_events = capture_fs_changes(&config)
            .context("Daytona filesystem capture failed")?;

        Ok(Box::new(fs_events.into_iter()))
    }

    fn name(&self) -> &str {
        "daytona"
    }
}

/// Check whether the system looks like a Daytona environment.
pub fn detect() -> bool {
    Path::new(DAYTONA_WORKSPACES_DIR).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_upper_resolution() {
        let provider = DaytonaProvider::default();
        let upper = provider.overlay_upper("ws-abc123");
        assert_eq!(
            upper,
            PathBuf::from("/var/lib/daytona/workspaces/ws-abc123/overlay/upper")
        );
    }

    #[test]
    fn workspace_root_resolution() {
        let provider = DaytonaProvider::default();
        let root = provider.workspace_root("ws-abc123");
        assert_eq!(
            root,
            PathBuf::from("/var/lib/daytona/workspaces/ws-abc123")
        );
    }

    #[test]
    fn provider_name() {
        let provider = DaytonaProvider::default();
        assert_eq!(provider.name(), "daytona");
    }

    #[test]
    fn attach_overlay_mode() {
        let base = tempfile::tempdir().unwrap();
        let upper = base.path().join("ws-1/overlay/upper");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::write(upper.join("changed.txt"), "new content").unwrap();

        let provider = DaytonaProvider {
            workspaces_dir: base.path().to_string_lossy().to_string(),
            tracking: DaytonaTracking::Overlay,
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("ws-1").unwrap().collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, sandtrace_capture::EventType::FilesystemSummary);
    }

    #[test]
    fn attach_snapshot_mode() {
        let before = tempfile::tempdir().unwrap();
        let after = tempfile::tempdir().unwrap();
        std::fs::write(after.path().join("new.txt"), "hello").unwrap();

        let provider = DaytonaProvider {
            workspaces_dir: "/unused".to_string(),
            tracking: DaytonaTracking::Snapshot {
                before_dir: before.path().to_path_buf(),
                after_dir: after.path().to_path_buf(),
            },
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("ws-1").unwrap().collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn attach_empty_overlay() {
        let base = tempfile::tempdir().unwrap();
        let upper = base.path().join("ws-1/overlay/upper");
        std::fs::create_dir_all(&upper).unwrap();

        let provider = DaytonaProvider {
            workspaces_dir: base.path().to_string_lossy().to_string(),
            tracking: DaytonaTracking::Overlay,
            ..Default::default()
        };

        let events: Vec<_> = provider.attach("ws-1").unwrap().collect();
        assert!(events.is_empty());
    }
}
