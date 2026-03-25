//! Firecracker provider adapter.
//!
//! Connects to a Firecracker microVM via its tap device and overlay
//! filesystem to capture network, filesystem, and syscall events.
//! Uses OverlayFS upper-dir scanning for filesystem change detection.

use std::path::PathBuf;

use anyhow::Result;
use sandtrace_capture::CapturedEvent;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, capture_fs_changes};
use sandtrace_capture::network::{NetworkCaptureConfig, capture_egress};
use sandtrace_capture::syscall::{SyscallMonitorConfig, capture_syscalls};

use crate::SandboxProvider;

/// Firecracker VM provider configuration.
#[derive(Debug, Clone)]
pub struct FirecrackerProvider {
    /// Path to the Firecracker socket.
    pub socket_path: String,
    /// Tap device name (e.g., "tap0").
    pub tap_device: String,
    /// Overlay filesystem upper directory path.
    pub overlay_upper_dir: String,
    /// PID of the Firecracker jailer process for syscall monitoring.
    /// If `None`, syscall capture is skipped.
    pub jailer_pid: Option<u32>,
}

impl SandboxProvider for FirecrackerProvider {
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>> {
        let trace_id = uuid::Uuid::new_v4().to_string();

        tracing::info!(
            sandbox_id,
            socket = %self.socket_path,
            "attaching to Firecracker VM"
        );

        let fs_config = FsTrackingConfig {
            agent_id: sandbox_id.to_string(),
            trace_id: trace_id.clone(),
            method: FsTrackingMethod::OverlayUpperDir {
                upper_dir: PathBuf::from(&self.overlay_upper_dir),
            },
        };

        let mut events = capture_fs_changes(&fs_config)?;

        // Network capture via tap device.
        let net_config = NetworkCaptureConfig {
            tap_device: self.tap_device.clone(),
            agent_id: sandbox_id.to_string(),
            trace_id: trace_id.clone(),
            ..Default::default()
        };
        match capture_egress(&net_config) {
            Ok(net_events) => events.extend(net_events),
            Err(e) => tracing::warn!(error = %e, "network capture failed, continuing without it"),
        }

        // Syscall capture via ptrace on the jailer process.
        if let Some(pid) = self.jailer_pid {
            let sc_config = SyscallMonitorConfig {
                jailer_pid: pid,
                agent_id: sandbox_id.to_string(),
                trace_id,
                ..Default::default()
            };
            match capture_syscalls(&sc_config) {
                Ok(sc_events) => events.extend(sc_events),
                Err(e) => tracing::warn!(error = %e, "syscall capture failed, continuing without it"),
            }
        }

        Ok(Box::new(events.into_iter()))
    }

    fn name(&self) -> &str {
        "firecracker"
    }
}
