//! Provider adapters for different sandbox runtimes.
//!
//! Each provider implements attachment to a specific sandbox technology
//! and translates raw captures into `CapturedEvent`s.
//!
//! Supported providers:
//! - **Firecracker** — generic Firecracker microVM (overlay-based FS tracking)
//! - **E2B** — API-managed Firecracker sandboxes (snapshot-based)
//! - **Daytona** — devcontainer-based workspaces (overlay or snapshot)
//! - **Blaxel** — Blaxel VM management (checkpoint-based)
//! - **Snapshot** — generic snapshot-diff for any block-device provider
//!
//! Use [`detect::detect_provider`] to auto-detect the active provider,
//! or [`detect::create_default_provider`] to get a ready-to-use adapter.

pub mod blaxel;
pub mod daytona;
pub mod detect;
pub mod e2b;
pub mod firecracker;
pub mod snapshot;

use anyhow::Result;
use sandtrace_capture::CapturedEvent;

/// Trait for sandbox provider adapters.
pub trait SandboxProvider: Send {
    /// Attach to a running sandbox and return a snapshot of events.
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>>;

    /// Attach to a running sandbox and stream events continuously through a channel.
    /// Runs until the shutdown flag is set.
    fn attach_streaming(
        &self,
        sandbox_id: &str,
        tx: std::sync::mpsc::Sender<CapturedEvent>,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        // Default: fall back to point-in-time capture
        let events = self.attach(sandbox_id)?;
        for event in events {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if tx.send(event).is_err() {
                break;
            }
        }
        Ok(())
    }

    /// Provider name for logging and identification.
    fn name(&self) -> &str;
}
