//! Syscall monitoring via seccomp-bpf or eBPF on the jailer process.
//!
//! Attaches to the Firecracker jailer process to monitor system calls
//! made by the guest VM, enabling detection of unexpected behavior.

use anyhow::Result;

/// Configuration for syscall monitoring.
#[derive(Debug, Clone)]
pub struct SyscallMonitorConfig {
    /// PID of the jailer process to attach to
    pub jailer_pid: u32,
    /// Agent identifier for event attribution
    pub agent_id: String,
    /// Trace identifier for this capture session
    pub trace_id: String,
}

/// Attach syscall monitoring to a jailer process.
///
/// Not yet implemented — requires seccomp-bpf or eBPF attachment.
pub fn attach_monitor(_config: &SyscallMonitorConfig) -> Result<()> {
    tracing::warn!("syscall monitoring not yet implemented");
    Ok(())
}
