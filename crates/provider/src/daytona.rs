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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sandtrace_capture::CaptureStream;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, watch_fs_changes};
use sandtrace_capture::network::{NetworkCaptureConfig, capture_egress_continuous};
use sandtrace_capture::syscall::{SyscallMonitorConfig, capture_syscalls_continuous};

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
    /// PID of the Firecracker jailer process for syscall monitoring.
    /// If `None`, syscall capture is skipped.
    pub jailer_pid: Option<u32>,
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
            jailer_pid: None,
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
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream> {
        let trace_id = uuid::Uuid::new_v4().to_string();
        let shutdown = Arc::new(AtomicBool::new(false));

        let method = match &self.tracking {
            DaytonaTracking::Overlay => {
                let upper = self.overlay_upper(sandbox_id);
                tracing::info!(
                    sandbox_id,
                    upper = %upper.display(),
                    "attaching to Daytona workspace via overlay (continuous)"
                );
                FsTrackingMethod::OverlayUpperDir { upper_dir: upper }
            }
            DaytonaTracking::Snapshot { before_dir, after_dir } => {
                tracing::info!(
                    sandbox_id,
                    before = %before_dir.display(),
                    after = %after_dir.display(),
                    "attaching to Daytona workspace via snapshot diff (continuous)"
                );
                FsTrackingMethod::SnapshotDiff {
                    before: before_dir.clone(),
                    after: after_dir.clone(),
                }
            }
        };

        let (tx, stream) = CaptureStream::channel();

        // Filesystem monitoring thread.
        let fs_config = FsTrackingConfig {
            sandbox_id: sandbox_id.to_string(),
            trace_id: trace_id.clone(),
            method,
        };
        match watch_fs_changes(&fs_config, tx.clone(), shutdown.clone(), Duration::from_secs(2)) {
            Ok(_) => tracing::info!("filesystem watch thread started"),
            Err(e) => tracing::warn!(error = %e, "filesystem watch failed, continuing without it"),
        }

        // Network capture thread (if configured).
        if let Some(tap) = &self.tap_device {
            let net_config = NetworkCaptureConfig {
                tap_device: tap.clone(),
                sandbox_id: sandbox_id.to_string(),
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
                sandbox_id: sandbox_id.to_string(),
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

    fn discover(&self) -> Result<Vec<crate::SandboxInfo>> {
        discover_daytona_workspaces(&self.workspaces_dir)
    }

    #[cfg(target_os = "linux")]
    fn watch_lifecycle(
        &self,
        tx: std::sync::mpsc::Sender<crate::LifecycleEvent>,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        watch_daytona_lifecycle(&self.workspaces_dir, tx, shutdown)
    }

    fn name(&self) -> &str {
        "daytona"
    }
}

/// Check whether the system looks like a Daytona environment.
pub fn detect() -> bool {
    Path::new(DAYTONA_WORKSPACES_DIR).is_dir()
}

/// Discover running Daytona workspaces by listing subdirectories.
pub fn discover_daytona_workspaces(workspaces_dir: &str) -> Result<Vec<crate::SandboxInfo>> {
    let base = Path::new(workspaces_dir);
    if !base.is_dir() {
        return Ok(vec![]);
    }

    let mut sandboxes = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let workspace_id = entry.file_name().to_string_lossy().to_string();

        // Must have overlay/upper/ or workspace.json
        let has_overlay = entry.path().join("overlay/upper").is_dir();
        let has_meta = entry.path().join("workspace.json").is_file();
        if !has_overlay && !has_meta {
            continue;
        }

        sandboxes.push(crate::SandboxInfo {
            sandbox_id: workspace_id.clone(),
            pid: None,
            provider: Box::new(DaytonaProvider {
                workspaces_dir: workspaces_dir.to_string(),
                ..Default::default()
            }),
        });
    }

    Ok(sandboxes)
}

/// Watch for Daytona workspace lifecycle events using inotify.
#[cfg(target_os = "linux")]
fn watch_daytona_lifecycle(
    workspaces_dir: &str,
    tx: std::sync::mpsc::Sender<crate::LifecycleEvent>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use std::collections::HashSet;
    use std::sync::atomic::Ordering;

    let base = Path::new(workspaces_dir);

    let mut known: HashSet<String> = HashSet::new();
    if let Ok(workspaces) = discover_daytona_workspaces(workspaces_dir) {
        for info in workspaces {
            known.insert(info.sandbox_id.clone());
            if tx.send(crate::LifecycleEvent::Attached(info)).is_err() {
                return Ok(());
            }
        }
    }

    let inotify = match inotify::Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "inotify unavailable, no continuous Daytona discovery");
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            return Ok(());
        }
    };

    let watch_mask = inotify::WatchMask::CREATE
        | inotify::WatchMask::DELETE
        | inotify::WatchMask::MOVED_TO
        | inotify::WatchMask::MOVED_FROM;

    if let Err(e) = inotify.watches().add(base, watch_mask) {
        tracing::warn!(error = %e, dir = %base.display(), "failed to watch workspaces dir");
        while !shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        return Ok(());
    }

    let fd = std::os::fd::AsRawFd::as_raw_fd(&inotify);
    let mut buf = [0u8; 4096];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pollfd, 1, 500) };

        if ret > 0 {
            if let Ok(events) = inotify.read_events(&mut buf) {
                for event in events {
                    let name = match &event.name {
                        Some(n) => n.to_string_lossy().to_string(),
                        None => continue,
                    };

                    if event.mask.contains(inotify::EventMask::CREATE)
                        || event.mask.contains(inotify::EventMask::MOVED_TO)
                    {
                        let ws_path = base.join(&name);
                        if ws_path.is_dir() && !known.contains(&name) {
                            let has_overlay = ws_path.join("overlay/upper").is_dir();
                            let has_meta = ws_path.join("workspace.json").is_file();
                            if has_overlay || has_meta {
                                known.insert(name.clone());
                                let info = crate::SandboxInfo {
                                    sandbox_id: name.clone(),
                                    pid: None,
                                    provider: Box::new(DaytonaProvider {
                                        workspaces_dir: workspaces_dir.to_string(),
                                        ..Default::default()
                                    }),
                                };
                                let _ = tx.send(crate::LifecycleEvent::Attached(info));
                            }
                        }
                    }

                    if event.mask.contains(inotify::EventMask::DELETE)
                        || event.mask.contains(inotify::EventMask::MOVED_FROM)
                    {
                        if known.remove(&name) {
                            let _ = tx.send(crate::LifecycleEvent::Detached {
                                sandbox_id: name,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(())
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

        let stream = provider.attach("ws-1").unwrap();
        let mut events = Vec::new();
        while let Some(ev) = stream.recv_timeout(std::time::Duration::from_secs(5)) {
            events.push(ev);
        }
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

        let stream = provider.attach("ws-1").unwrap();
        let mut events = Vec::new();
        while let Some(ev) = stream.recv_timeout(std::time::Duration::from_secs(5)) {
            events.push(ev);
        }
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

        let stream = provider.attach("ws-1").unwrap();
        let event = stream.recv_timeout(std::time::Duration::from_secs(4));
        assert!(event.is_none());
    }
}
