//! Firecracker provider adapter.
//!
//! Connects to a Firecracker microVM via its tap device and overlay
//! filesystem to capture network, filesystem, and syscall events.
//! Uses OverlayFS upper-dir scanning for filesystem change detection.

use std::path::PathBuf;

use anyhow::Result;
use sandtrace_capture::CapturedEvent;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, capture_fs_changes};

use crate::SandboxProvider;

/// Firecracker VM provider configuration.
#[derive(Debug, Clone)]
pub struct FirecrackerProvider {
    /// Path to the Firecracker socket.
    pub socket_path: String,
    /// Tap device name.
    pub tap_device: String,
    /// Overlay filesystem upper directory path.
    pub overlay_upper_dir: String,
}

impl SandboxProvider for FirecrackerProvider {
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>> {
        tracing::info!(
            sandbox_id,
            socket = %self.socket_path,
            "attaching to Firecracker VM"
        );

        let config = FsTrackingConfig {
            agent_id: sandbox_id.to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            method: FsTrackingMethod::OverlayUpperDir {
                upper_dir: PathBuf::from(&self.overlay_upper_dir),
            },
        };

        let fs_events = capture_fs_changes(&config)?;

        // Network and syscall capture are not yet implemented.
        // When ready, they will be appended to the event stream here.
        Ok(Box::new(fs_events.into_iter()))
    }

    fn name(&self) -> &str {
        "firecracker"
    }
}
