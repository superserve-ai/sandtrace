//! Provider adapters for different sandbox runtimes.
//!
//! Each provider implements attachment to a specific sandbox technology
//! (Firecracker, gVisor, etc.) and translates raw captures into
//! `CapturedEvent`s.

pub mod firecracker;
pub mod snapshot;

use anyhow::Result;
use sandtrace_capture::CapturedEvent;

/// Trait for sandbox provider adapters.
pub trait SandboxProvider {
    /// Attach to a running sandbox and return a stream of events.
    fn attach(&self, sandbox_id: &str) -> Result<Box<dyn Iterator<Item = CapturedEvent>>>;

    /// Provider name for logging and identification.
    fn name(&self) -> &str;
}
