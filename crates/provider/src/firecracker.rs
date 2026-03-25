//! Firecracker provider adapter.
//!
//! Connects to a Firecracker microVM via its tap device and overlay
//! filesystem to capture network, filesystem, and syscall events.

use anyhow::Result;
use sandtrace_capture::CapturedEvent;

use crate::SandboxProvider;

/// Firecracker VM provider configuration.
#[derive(Debug, Clone)]
pub struct FirecrackerProvider {
    /// Path to the Firecracker socket
    pub socket_path: String,
    /// Tap device name
    pub tap_device: String,
    /// Overlay filesystem path
    pub overlay_path: String,
}

impl SandboxProvider for FirecrackerProvider {
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>> {
        tracing::info!(
            sandbox_id,
            socket = %self.socket_path,
            "attaching to Firecracker VM"
        );

        // Not yet implemented — requires:
        // 1. Connecting to the Firecracker API socket
        // 2. Setting up tap device packet capture
        // 3. Mounting the overlay diff layer
        // 4. Optionally attaching seccomp-bpf to the jailer
        tracing::warn!("Firecracker provider not yet implemented");
        Ok(Box::new(std::iter::empty()))
    }

    fn name(&self) -> &str {
        "firecracker"
    }
}
