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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use anyhow::Result;
use sandtrace_capture::{CaptureStream, CapturedEvent};

/// Trait for sandbox provider adapters.
pub trait SandboxProvider: Send {
    /// Attach to a running sandbox and return a continuous stream of events.
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream>;

    /// Attach to a running sandbox and stream events continuously through a channel.
    /// Runs until the shutdown flag is set.
    fn attach_streaming(
        &self,
        sandbox_id: &str,
        tx: mpsc::Sender<CapturedEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<()> {
        let stream = self.attach(sandbox_id)?;
        let timeout = Duration::from_secs(1);
        loop {
            if shutdown.load(Ordering::Relaxed) {
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

    /// Discover all running sandboxes managed by this provider.
    fn discover(&self) -> Result<Vec<SandboxInfo>> {
        Ok(vec![])
    }

    /// Watch for VM lifecycle events (attach/detach) and emit them through the channel.
    ///
    /// The default implementation does a one-time `discover()` and then blocks
    /// until shutdown. Providers should override this with event-driven
    /// detection (inotify + pidfd on Linux).
    fn watch_lifecycle(
        &self,
        tx: mpsc::Sender<LifecycleEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<()> {
        // One-time discovery.
        for info in self.discover()? {
            if tx.send(LifecycleEvent::Attached(info)).is_err() {
                return Ok(());
            }
        }
        // Block until shutdown.
        while !shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
        }
        Ok(())
    }

    /// Provider name for logging and identification.
    fn name(&self) -> &str;
}

/// Information about a discovered running sandbox.
pub struct SandboxInfo {
    /// Unique identifier for this sandbox.
    pub sandbox_id: String,
    /// Provider adapter configured for this specific sandbox.
    pub provider: Box<dyn SandboxProvider>,
    /// PID of the VM process (if known). Used for lifecycle monitoring via pidfd.
    pub pid: Option<u32>,
}

/// VM lifecycle event emitted by the provider's watcher.
pub enum LifecycleEvent {
    /// A new sandbox was discovered and is ready to attach.
    Attached(SandboxInfo),
    /// A sandbox has stopped and its capture should be cleaned up.
    Detached { sandbox_id: String },
}
