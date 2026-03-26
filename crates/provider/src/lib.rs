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
use sandtrace_capture::CaptureStream;

/// Trait for sandbox provider adapters.
pub trait SandboxProvider {
    /// Attach to a running sandbox and return a continuous stream of events.
    ///
    /// Spawns background capture threads (network, filesystem, syscall) that
    /// feed events into the returned [`CaptureStream`]. The stream remains
    /// open until the provider's capture threads finish or the shutdown flag
    /// is set.
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream>;

    /// Provider name for logging and identification.
    fn name(&self) -> &str;
}
