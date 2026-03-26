//! Provider adapters for different sandbox runtimes.
//!
//! Each provider implements attachment to a specific sandbox technology
//! and translates raw captures into `CapturedEvent`s.
//!
//! Supported providers:
//! - **Firecracker** — generic Firecracker microVM (overlay-based FS tracking)
//! - **E2B** — API-managed Firecracker sandboxes (snapshot-based)
//! - **Daytona** — devcontainer-based workspaces (overlay or snapshot)
//! - **Snapshot** — generic snapshot-diff for any block-device provider
//!
//! Use [`detect::detect_provider`] to auto-detect the active provider,
//! or [`detect::create_default_provider`] to get a ready-to-use adapter.

pub mod daytona;
pub mod detect;
pub mod e2b;
pub mod firecracker;
pub mod snapshot;

use anyhow::Result;
use sandtrace_capture::{CaptureStream, CapturedEvent};

/// Trait for sandbox provider adapters.
pub trait SandboxProvider: Send {
    /// Attach to a running sandbox and return a continuous stream of events.
    ///
    /// Spawns background capture threads (network, filesystem, syscall) that
    /// feed events into the returned [`CaptureStream`]. The stream remains
    /// open until the provider's capture threads finish or the shutdown flag
    /// is set.
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream>;

    /// Attach to a running sandbox and stream events continuously through a channel.
    /// Runs until the shutdown flag is set.
    fn attach_streaming(
        &self,
        sandbox_id: &str,
        tx: std::sync::mpsc::Sender<CapturedEvent>,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        // Default: fall back to CaptureStream-based capture, draining events
        // via recv_timeout until shutdown or the stream is exhausted.
        let stream = self.attach(sandbox_id)?;
        let timeout = std::time::Duration::from_secs(1);
        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match stream.recv_timeout(timeout) {
                Some(event) => {
                    if tx.send(event).is_err() {
                        break;
                    }
                }
                None => continue,
            }
        }
        Ok(())
    }

    /// Provider name for logging and identification.
    fn name(&self) -> &str;
}
