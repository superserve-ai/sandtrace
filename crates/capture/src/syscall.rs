//! Syscall monitoring via ptrace on the jailer process.
//!
//! Attaches to the Firecracker jailer/VM process to monitor system calls
//! using `ptrace(PTRACE_SYSCALL)`. Syscalls are aggregated by name and
//! categorised (process, file, network, privilege, memory) to enable
//! detection of unexpected behaviour such as privilege escalation or
//! covert network activity.
//!
//! Linux-only — returns an error on other platforms.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use anyhow::Result;

use crate::{CapturedEvent, EventType};

// ── Configuration ────────────────────────────────────────────────────

/// Configuration for syscall monitoring.
#[derive(Debug, Clone)]
pub struct SyscallMonitorConfig {
    /// PID of the jailer process to attach to.
    pub jailer_pid: u32,
    /// Agent identifier for event attribution.
    pub agent_id: String,
    /// Trace identifier for this capture session.
    pub trace_id: String,
    /// How long to capture syscalls. Defaults to 5 seconds.
    pub capture_duration: Option<Duration>,
}

impl Default for SyscallMonitorConfig {
    fn default() -> Self {
        Self {
            jailer_pid: 0,
            agent_id: String::new(),
            trace_id: String::new(),
            capture_duration: None,
        }
    }
}

// ── Summary types ────────────────────────────────────────────────────

/// Structured representation of a syscall monitoring summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyscallSummary {
    /// PID that was monitored.
    pub pid: u32,
    /// Total number of syscalls observed.
    pub total_syscalls: u64,
    /// Number of distinct syscall types observed.
    pub unique_syscalls: u64,
    /// Per-syscall invocation counts (syscall name → count).
    pub syscall_counts: BTreeMap<String, u64>,
    /// Per-category totals (e.g. "file", "network", "process").
    pub category_counts: BTreeMap<String, u64>,
    /// Syscalls that returned errors, keyed by name, value is error count.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub error_counts: BTreeMap<String, u64>,
    /// Potentially suspicious activity detected during monitoring.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious: Vec<SuspiciousActivity>,
}

/// A flagged suspicious syscall pattern.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuspiciousActivity {
    pub syscall: String,
    pub category: String,
    pub reason: String,
    pub count: u64,
}

impl SyscallSummary {
    /// Convert this summary into a `CapturedEvent`.
    pub fn to_event(&self, agent_id: &str, trace_id: &str) -> CapturedEvent {
        CapturedEvent::new(
            EventType::SyscallActivity,
            agent_id,
            trace_id,
            serde_json::to_value(self).expect("SyscallSummary is always serializable"),
        )
    }
}

/// Parse a syscall activity event payload into a typed summary.
pub fn parse_syscall_payload(event: &CapturedEvent) -> Option<SyscallSummary> {
    if event.event_type != EventType::SyscallActivity {
        return None;
    }
    serde_json::from_value(event.payload.clone()).ok()
}

// ── Tracker (platform-independent aggregation) ───────────────────────

/// Aggregates raw syscall observations into a summary.
pub struct SyscallTracker {
    pid: u32,
    syscall_counts: BTreeMap<String, u64>,
    error_counts: BTreeMap<String, u64>,
}

impl SyscallTracker {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            syscall_counts: BTreeMap::new(),
            error_counts: BTreeMap::new(),
        }
    }

    /// Record a syscall observation.
    ///
    /// `number` is the raw syscall number (architecture-dependent).
    /// `error` is `Some(errno)` if the syscall returned a negative value
    /// (indicates a failed syscall).
    pub fn record_syscall(&mut self, number: u64, error: Option<i64>) {
        let name = syscall_name(number);
        *self.syscall_counts.entry(name.clone()).or_insert(0) += 1;

        if error.is_some() {
            *self.error_counts.entry(name).or_insert(0) += 1;
        }
    }

    /// Record a syscall by name (useful for testing or non-ptrace sources).
    pub fn record_syscall_by_name(&mut self, name: &str, error: Option<i64>) {
        *self
            .syscall_counts
            .entry(name.to_string())
            .or_insert(0) += 1;

        if error.is_some() {
            *self
                .error_counts
                .entry(name.to_string())
                .or_insert(0) += 1;
        }
    }

    /// Number of distinct syscall types observed.
    pub fn unique_count(&self) -> usize {
        self.syscall_counts.len()
    }

    /// Total syscalls recorded.
    pub fn total_count(&self) -> u64 {
        self.syscall_counts.values().sum()
    }

    /// Drain the tracker into a `SyscallSummary`, resetting internal state.
    pub fn drain_summary(&mut self) -> SyscallSummary {
        let syscall_counts = std::mem::take(&mut self.syscall_counts);
        let error_counts = std::mem::take(&mut self.error_counts);

        // Build category counts.
        let mut category_counts = BTreeMap::new();
        for (name, count) in &syscall_counts {
            let cat = syscall_category(name).to_string();
            *category_counts.entry(cat).or_insert(0) += *count;
        }

        let total_syscalls: u64 = syscall_counts.values().sum();
        let unique_syscalls = syscall_counts.len() as u64;

        // Detect suspicious patterns.
        let suspicious = detect_suspicious(&syscall_counts);

        SyscallSummary {
            pid: self.pid,
            total_syscalls,
            unique_syscalls,
            syscall_counts,
            category_counts,
            error_counts,
            suspicious,
        }
    }
}

// ── Suspicious activity detection ────────────────────────────────────

/// Syscalls that are suspicious when made by a sandboxed jailer process.
const SUSPICIOUS_SYSCALLS: &[(&str, &str)] = &[
    ("execve", "process execution inside sandbox"),
    ("execveat", "process execution inside sandbox"),
    ("fork", "process spawning inside sandbox"),
    ("vfork", "process spawning inside sandbox"),
    ("clone3", "process/thread creation inside sandbox"),
    ("setuid", "privilege change attempt"),
    ("setgid", "privilege change attempt"),
    ("setreuid", "privilege change attempt"),
    ("setregid", "privilege change attempt"),
    ("setresuid", "privilege change attempt"),
    ("setresgid", "privilege change attempt"),
    ("mount", "filesystem mount attempt"),
    ("umount2", "filesystem unmount attempt"),
    ("pivot_root", "root filesystem change attempt"),
    ("chroot", "chroot escape attempt"),
    ("ptrace", "process tracing attempt"),
    ("process_vm_readv", "cross-process memory read"),
    ("process_vm_writev", "cross-process memory write"),
    ("init_module", "kernel module loading attempt"),
    ("finit_module", "kernel module loading attempt"),
    ("delete_module", "kernel module removal attempt"),
    ("kexec_load", "kernel replacement attempt"),
    ("kexec_file_load", "kernel replacement attempt"),
    ("unshare", "namespace manipulation"),
    ("setns", "namespace manipulation"),
];

fn detect_suspicious(counts: &BTreeMap<String, u64>) -> Vec<SuspiciousActivity> {
    let mut suspicious = Vec::new();
    for (name, reason) in SUSPICIOUS_SYSCALLS {
        if let Some(&count) = counts.get(*name) {
            suspicious.push(SuspiciousActivity {
                syscall: name.to_string(),
                category: syscall_category(name).to_string(),
                reason: reason.to_string(),
                count,
            });
        }
    }
    suspicious
}

// ── Capture entry points ─────────────────────────────────────────────

/// Capture syscalls made by the jailer process.
///
/// On Linux, attaches via `ptrace(PTRACE_SYSCALL)` for the configured
/// duration and returns an aggregated summary event. On other platforms,
/// returns an error.
#[cfg(target_os = "linux")]
pub fn capture_syscalls(config: &SyscallMonitorConfig) -> Result<Vec<CapturedEvent>> {
    linux_ptrace::capture(config)
}

#[cfg(not(target_os = "linux"))]
pub fn capture_syscalls(config: &SyscallMonitorConfig) -> Result<Vec<CapturedEvent>> {
    let _ = config;
    anyhow::bail!(
        "syscall monitoring requires Linux (ptrace/seccomp-bpf). \
         Current platform is not supported."
    )
}

/// Start continuous syscall monitoring on a background thread.
///
/// Attaches via ptrace and runs indefinitely, periodically draining
/// accumulated syscall summaries through `tx`. Runs until `shutdown`
/// is set or the traced process exits.
#[cfg(target_os = "linux")]
pub fn capture_syscalls_continuous(
    config: &SyscallMonitorConfig,
    tx: mpsc::Sender<CapturedEvent>,
    shutdown: Arc<AtomicBool>,
    flush_interval: Duration,
) -> Result<std::thread::JoinHandle<()>> {
    linux_ptrace::capture_continuous(config, tx, shutdown, flush_interval)
}

#[cfg(not(target_os = "linux"))]
pub fn capture_syscalls_continuous(
    config: &SyscallMonitorConfig,
    _tx: mpsc::Sender<CapturedEvent>,
    _shutdown: Arc<AtomicBool>,
    _flush_interval: Duration,
) -> Result<std::thread::JoinHandle<()>> {
    let _ = config;
    anyhow::bail!(
        "syscall monitoring requires Linux (ptrace/seccomp-bpf). \
         Current platform is not supported."
    )
}

/// Stub kept for backwards compatibility — prefer [`capture_syscalls`].
pub fn attach_monitor(config: &SyscallMonitorConfig) -> Result<()> {
    let _ = capture_syscalls(config)?;
    Ok(())
}

// ── Linux ptrace implementation ──────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_ptrace {
    use super::*;
    use anyhow::Context;
    use std::ptr;
    use std::time::Instant;

    // ptrace request types not always available in libc.
    const PTRACE_SEIZE: libc::c_uint = 0x4206;
    const PTRACE_INTERRUPT: libc::c_uint = 0x4207;

    /// RAII guard that detaches ptrace on drop.
    struct DetachGuard(libc::pid_t);

    impl Drop for DetachGuard {
        fn drop(&mut self) {
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, self.0, ptr::null_mut::<libc::c_void>(), ptr::null_mut::<libc::c_void>());
            }
        }
    }

    pub fn capture(config: &SyscallMonitorConfig) -> Result<Vec<CapturedEvent>> {
        let pid = config.jailer_pid as libc::pid_t;
        let duration = config.capture_duration.unwrap_or(Duration::from_secs(5));

        tracing::info!(pid, ?duration, "attaching ptrace syscall monitor");

        // Attach without stopping the process.
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SEIZE,
                pid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .context(format!("ptrace SEIZE on pid {pid}"));
        }

        let _guard = DetachGuard(pid);

        // Interrupt to configure options.
        let ret = unsafe {
            libc::ptrace(
                PTRACE_INTERRUPT,
                pid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .context(format!("ptrace INTERRUPT on pid {pid}"));
        }

        // Wait for the process to stop.
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, libc::__WALL);
        }

        // Enable TRACESYSGOOD so we can distinguish syscall stops.
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                pid,
                ptr::null_mut::<libc::c_void>(),
                libc::PTRACE_O_TRACESYSGOOD as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .context(format!("ptrace SETOPTIONS on pid {pid}"));
        }

        // Resume — stop at next syscall boundary.
        unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                pid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            );
        }

        let mut tracker = SyscallTracker::new(config.jailer_pid);
        let start = Instant::now();
        let mut at_entry = true;

        while start.elapsed() < duration {
            status = 0;
            let ret = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };

            if ret == 0 {
                // Not stopped yet — brief sleep to avoid busy-wait.
                std::thread::sleep(Duration::from_micros(100));
                continue;
            }
            if ret < 0 {
                // Process gone or error.
                tracing::debug!(pid, "waitpid returned error, stopping capture");
                break;
            }

            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                tracing::debug!(pid, "traced process exited");
                break;
            }

            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                if sig == (libc::SIGTRAP | 0x80) {
                    // Syscall stop.
                    if at_entry {
                        // Read registers to get syscall number.
                        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                        unsafe {
                            libc::ptrace(
                                libc::PTRACE_GETREGS,
                                pid,
                                ptr::null_mut::<libc::c_void>(),
                                &mut regs as *mut _ as *mut libc::c_void,
                            );
                        }
                        tracker.record_syscall(regs.orig_rax, None);
                    } else {
                        // Syscall exit — could read return value for error
                        // detection but kept simple for now.
                    }
                    at_entry = !at_entry;
                }
            }

            // Resume to next syscall boundary.
            unsafe {
                libc::ptrace(
                    libc::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut::<libc::c_void>(),
                    ptr::null_mut::<libc::c_void>(),
                );
            }
        }

        let summary = tracker.drain_summary();
        if summary.total_syscalls == 0 {
            tracing::info!(pid, "no syscalls captured");
            return Ok(vec![]);
        }

        tracing::info!(
            pid,
            total = summary.total_syscalls,
            unique = summary.unique_syscalls,
            suspicious = summary.suspicious.len(),
            "syscall capture complete"
        );

        Ok(vec![summary.to_event(&config.agent_id, &config.trace_id)])
    }

    pub fn capture_continuous(
        config: &SyscallMonitorConfig,
        tx: mpsc::Sender<CapturedEvent>,
        shutdown: Arc<AtomicBool>,
        flush_interval: Duration,
    ) -> Result<std::thread::JoinHandle<()>> {
        let pid = config.jailer_pid as libc::pid_t;

        tracing::info!(pid, "attaching continuous ptrace syscall monitor");

        // Attach without stopping the process.
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SEIZE,
                pid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .context(format!("ptrace SEIZE on pid {pid}"));
        }

        // Interrupt to configure options.
        let ret = unsafe {
            libc::ptrace(
                PTRACE_INTERRUPT,
                pid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if ret < 0 {
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, ptr::null_mut::<libc::c_void>(), ptr::null_mut::<libc::c_void>());
            }
            return Err(std::io::Error::last_os_error())
                .context(format!("ptrace INTERRUPT on pid {pid}"));
        }

        // Wait for the process to stop.
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, libc::__WALL);
        }

        // Enable TRACESYSGOOD.
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                pid,
                ptr::null_mut::<libc::c_void>(),
                libc::PTRACE_O_TRACESYSGOOD as *mut libc::c_void,
            )
        };
        if ret < 0 {
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, ptr::null_mut::<libc::c_void>(), ptr::null_mut::<libc::c_void>());
            }
            return Err(std::io::Error::last_os_error())
                .context(format!("ptrace SETOPTIONS on pid {pid}"));
        }

        // Resume — stop at next syscall boundary.
        unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                pid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            );
        }

        let jailer_pid = config.jailer_pid;
        let agent_id = config.agent_id.clone();
        let trace_id = config.trace_id.clone();

        let handle = std::thread::Builder::new()
            .name("sandtrace-sc-capture".into())
            .spawn(move || {
                let _guard = DetachGuard(pid);
                let mut tracker = SyscallTracker::new(jailer_pid);
                let mut last_flush = Instant::now();
                let mut at_entry = true;

                while !shutdown.load(Ordering::Relaxed) {
                    status = 0;
                    let ret = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };

                    if ret == 0 {
                        std::thread::sleep(Duration::from_micros(100));

                        // Check flush interval even when idle.
                        if last_flush.elapsed() >= flush_interval && tracker.total_count() > 0 {
                            let summary = tracker.drain_summary();
                            let event = summary.to_event(&agent_id, &trace_id);
                            if tx.send(event).is_err() {
                                return;
                            }
                            last_flush = Instant::now();
                        }
                        continue;
                    }
                    if ret < 0 {
                        tracing::debug!(pid, "waitpid returned error, stopping capture");
                        break;
                    }

                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        tracing::debug!(pid, "traced process exited");
                        break;
                    }

                    if libc::WIFSTOPPED(status) {
                        let sig = libc::WSTOPSIG(status);
                        if sig == (libc::SIGTRAP | 0x80) {
                            if at_entry {
                                let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                                unsafe {
                                    libc::ptrace(
                                        libc::PTRACE_GETREGS,
                                        pid,
                                        ptr::null_mut::<libc::c_void>(),
                                        &mut regs as *mut _ as *mut libc::c_void,
                                    );
                                }
                                tracker.record_syscall(regs.orig_rax, None);
                            }
                            at_entry = !at_entry;
                        }
                    }

                    // Resume to next syscall boundary.
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_SYSCALL,
                            pid,
                            ptr::null_mut::<libc::c_void>(),
                            ptr::null_mut::<libc::c_void>(),
                        );
                    }

                    // Periodic flush.
                    if last_flush.elapsed() >= flush_interval && tracker.total_count() > 0 {
                        let summary = tracker.drain_summary();
                        let event = summary.to_event(&agent_id, &trace_id);
                        if tx.send(event).is_err() {
                            return;
                        }
                        last_flush = Instant::now();
                    }
                }

                // Final flush on shutdown.
                if tracker.total_count() > 0 {
                    let summary = tracker.drain_summary();
                    let event = summary.to_event(&agent_id, &trace_id);
                    let _ = tx.send(event);
                }
            })?;

        Ok(handle)
    }
}

// ── Syscall name table (x86_64) ──────────────────────────────────────

/// Map a raw x86_64 syscall number to a human-readable name.
///
/// Covers the most security-relevant syscalls. Unknown numbers are
/// returned as `"syscall_NNN"`.
fn syscall_name(nr: u64) -> String {
    let name: &str = match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        28 => "madvise",
        32 => "dup",
        33 => "dup2",
        35 => "nanosleep",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        53 => "socketpair",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        81 => "fchdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        86 => "link",
        87 => "unlink",
        88 => "symlink",
        89 => "readlink",
        90 => "chmod",
        91 => "fchmod",
        92 => "chown",
        93 => "fchown",
        94 => "lchown",
        95 => "umask",
        96 => "gettimeofday",
        97 => "getrlimit",
        102 => "getuid",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        109 => "setpgid",
        110 => "getppid",
        112 => "setsid",
        113 => "setreuid",
        114 => "setregid",
        117 => "setresuid",
        119 => "setresgid",
        137 => "statfs",
        138 => "fstatfs",
        155 => "pivot_root",
        157 => "prctl",
        160 => "setrlimit",
        161 => "chroot",
        165 => "mount",
        166 => "umount2",
        186 => "gettid",
        200 => "tkill",
        202 => "futex",
        217 => "getdents64",
        218 => "set_tid_address",
        228 => "clock_gettime",
        231 => "exit_group",
        232 => "epoll_create",  // older variant
        233 => "epoll_ctl",     // older variant
        234 => "epoll_wait",    // older variant
        257 => "openat",
        258 => "mkdirat",
        259 => "mknodat",
        260 => "fchownat",
        261 => "futimesat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        265 => "linkat",
        266 => "symlinkat",
        267 => "readlinkat",
        268 => "fchmodat",
        269 => "faccessat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        281 => "epoll_pwait",
        284 => "eventfd",
        288 => "accept4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        302 => "prlimit64",
        308 => "setns",
        309 => "getcpu",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        313 => "finit_module",
        314 => "sched_setattr",
        316 => "renameat2",
        318 => "getrandom",
        320 => "kexec_file_load",
        322 => "execveat",
        332 => "statx",
        334 => "rseq",
        435 => "clone3",
        437 => "openat2",
        439 => "faccessat2",
        _ => return format!("syscall_{nr}"),
    };
    name.to_string()
}

/// Categorise a syscall name into a broad security-relevant category.
fn syscall_category(name: &str) -> &'static str {
    match name {
        // Process lifecycle
        "fork" | "vfork" | "clone" | "clone3" | "execve" | "execveat" | "exit"
        | "exit_group" | "wait4" | "kill" | "tkill" | "getpid" | "gettid"
        | "getppid" | "setsid" | "setpgid" | "prctl" => "process",

        // File operations
        "open" | "openat" | "openat2" | "creat" | "close" | "read" | "write"
        | "pread64" | "pwrite64" | "readv" | "writev" | "lseek" | "stat"
        | "fstat" | "lstat" | "newfstatat" | "statx" | "statfs" | "fstatfs"
        | "access" | "faccessat" | "faccessat2" | "truncate" | "ftruncate"
        | "rename" | "renameat" | "renameat2" | "unlink" | "unlinkat"
        | "link" | "linkat" | "symlink" | "symlinkat" | "readlink"
        | "readlinkat" | "mkdir" | "mkdirat" | "rmdir" | "getdents"
        | "getdents64" | "getcwd" | "chdir" | "fchdir" | "chmod" | "fchmod"
        | "fchmodat" | "chown" | "fchown" | "fchownat" | "lchown" | "umask"
        | "fcntl" | "flock" | "fsync" | "fdatasync" | "mknodat"
        | "futimesat" => "file",

        // Network
        "socket" | "connect" | "accept" | "accept4" | "bind" | "listen"
        | "sendto" | "recvfrom" | "sendmsg" | "recvmsg" | "shutdown"
        | "getsockname" | "getpeername" | "socketpair" | "setsockopt"
        | "getsockopt" => "network",

        // Memory management
        "mmap" | "mprotect" | "munmap" | "brk" | "mremap" | "madvise" => "memory",

        // Privilege / security
        "setuid" | "setgid" | "setreuid" | "setregid" | "setresuid"
        | "setresgid" | "getuid" | "getgid" | "geteuid" | "getegid"
        | "setrlimit" | "getrlimit" | "prlimit64" | "chroot" | "mount"
        | "umount2" | "pivot_root" | "unshare" | "setns" => "privilege",

        // Signals
        "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn" => "signal",

        // IPC / synchronisation
        "pipe" | "pipe2" | "dup" | "dup2" | "dup3" | "eventfd" | "eventfd2"
        | "epoll_create" | "epoll_create1" | "epoll_ctl" | "epoll_wait"
        | "epoll_pwait" | "select" | "pselect6" | "poll" | "ppoll"
        | "futex" | "ioctl" => "ipc",

        // Time
        "nanosleep" | "clock_gettime" | "gettimeofday" => "time",

        // System
        "uname" | "sched_yield" | "set_tid_address" | "getrandom" | "getcpu"
        | "rseq" | "sched_setattr" => "system",

        // Dangerous kernel operations
        "ptrace" | "process_vm_readv" | "process_vm_writev" | "init_module"
        | "finit_module" | "delete_module" | "kexec_load"
        | "kexec_file_load" => "dangerous",

        _ => "other",
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_records_and_counts() {
        let mut tracker = SyscallTracker::new(1234);

        tracker.record_syscall_by_name("read", None);
        tracker.record_syscall_by_name("read", None);
        tracker.record_syscall_by_name("write", None);
        tracker.record_syscall_by_name("openat", None);

        assert_eq!(tracker.total_count(), 4);
        assert_eq!(tracker.unique_count(), 3);
    }

    #[test]
    fn tracker_drain_resets() {
        let mut tracker = SyscallTracker::new(100);
        tracker.record_syscall_by_name("read", None);

        let summary = tracker.drain_summary();
        assert_eq!(summary.total_syscalls, 1);
        assert_eq!(summary.pid, 100);

        let second = tracker.drain_summary();
        assert_eq!(second.total_syscalls, 0);
        assert_eq!(tracker.total_count(), 0);
    }

    #[test]
    fn tracker_categories() {
        let mut tracker = SyscallTracker::new(1);
        tracker.record_syscall_by_name("read", None);
        tracker.record_syscall_by_name("write", None);
        tracker.record_syscall_by_name("connect", None);
        tracker.record_syscall_by_name("fork", None);
        tracker.record_syscall_by_name("mmap", None);

        let summary = tracker.drain_summary();
        assert_eq!(summary.category_counts["file"], 2);
        assert_eq!(summary.category_counts["network"], 1);
        assert_eq!(summary.category_counts["process"], 1);
        assert_eq!(summary.category_counts["memory"], 1);
    }

    #[test]
    fn tracker_errors() {
        let mut tracker = SyscallTracker::new(1);
        tracker.record_syscall_by_name("open", Some(-2)); // ENOENT
        tracker.record_syscall_by_name("open", None);
        tracker.record_syscall_by_name("open", Some(-13)); // EACCES

        let summary = tracker.drain_summary();
        assert_eq!(summary.syscall_counts["open"], 3);
        assert_eq!(summary.error_counts["open"], 2);
    }

    #[test]
    fn tracker_detects_suspicious() {
        let mut tracker = SyscallTracker::new(1);
        tracker.record_syscall_by_name("read", None);
        tracker.record_syscall_by_name("execve", None);
        tracker.record_syscall_by_name("setuid", None);
        tracker.record_syscall_by_name("mount", None);

        let summary = tracker.drain_summary();
        assert_eq!(summary.suspicious.len(), 3);

        let names: Vec<&str> = summary.suspicious.iter().map(|s| s.syscall.as_str()).collect();
        assert!(names.contains(&"execve"));
        assert!(names.contains(&"setuid"));
        assert!(names.contains(&"mount"));
    }

    #[test]
    fn tracker_no_suspicious_for_normal_syscalls() {
        let mut tracker = SyscallTracker::new(1);
        tracker.record_syscall_by_name("read", None);
        tracker.record_syscall_by_name("write", None);
        tracker.record_syscall_by_name("close", None);

        let summary = tracker.drain_summary();
        assert!(summary.suspicious.is_empty());
    }

    #[test]
    fn syscall_name_known() {
        assert_eq!(syscall_name(0), "read");
        assert_eq!(syscall_name(1), "write");
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(257), "openat");
        assert_eq!(syscall_name(435), "clone3");
    }

    #[test]
    fn syscall_name_unknown() {
        let name = syscall_name(9999);
        assert_eq!(name, "syscall_9999");
    }

    #[test]
    fn syscall_category_coverage() {
        assert_eq!(syscall_category("read"), "file");
        assert_eq!(syscall_category("socket"), "network");
        assert_eq!(syscall_category("fork"), "process");
        assert_eq!(syscall_category("mmap"), "memory");
        assert_eq!(syscall_category("setuid"), "privilege");
        assert_eq!(syscall_category("ptrace"), "dangerous");
        assert_eq!(syscall_category("totally_unknown"), "other");
    }

    #[test]
    fn summary_to_event_roundtrip() {
        let mut tracker = SyscallTracker::new(42);
        tracker.record_syscall_by_name("read", None);
        tracker.record_syscall_by_name("write", None);
        tracker.record_syscall_by_name("execve", None);

        let summary = tracker.drain_summary();
        let event = summary.to_event("agent-1", "trace-1");

        assert_eq!(event.event_type, EventType::SyscallActivity);
        assert_eq!(event.agent_id, "agent-1");
        assert_eq!(event.trace_id, "trace-1");

        let parsed = parse_syscall_payload(&event).expect("should parse");
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.total_syscalls, 3);
        assert_eq!(parsed.unique_syscalls, 3);
        assert_eq!(parsed.syscall_counts["read"], 1);
        assert_eq!(parsed.syscall_counts["write"], 1);
        assert_eq!(parsed.syscall_counts["execve"], 1);
        assert_eq!(parsed.suspicious.len(), 1);
        assert_eq!(parsed.suspicious[0].syscall, "execve");
    }

    #[test]
    fn parse_wrong_event_type() {
        let event = CapturedEvent::new(
            EventType::NetworkEgress,
            "agent-1",
            "trace-1",
            serde_json::json!({}),
        );
        assert!(parse_syscall_payload(&event).is_none());
    }

    #[test]
    fn summary_serialization_roundtrip() {
        let summary = SyscallSummary {
            pid: 100,
            total_syscalls: 42,
            unique_syscalls: 5,
            syscall_counts: BTreeMap::from([
                ("read".to_string(), 20),
                ("write".to_string(), 15),
                ("openat".to_string(), 5),
                ("close".to_string(), 1),
                ("execve".to_string(), 1),
            ]),
            category_counts: BTreeMap::from([
                ("file".to_string(), 41),
                ("process".to_string(), 1),
            ]),
            error_counts: BTreeMap::from([("openat".to_string(), 2)]),
            suspicious: vec![SuspiciousActivity {
                syscall: "execve".to_string(),
                category: "process".to_string(),
                reason: "process execution inside sandbox".to_string(),
                count: 1,
            }],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let restored: SyscallSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pid, summary.pid);
        assert_eq!(restored.total_syscalls, summary.total_syscalls);
        assert_eq!(restored.unique_syscalls, summary.unique_syscalls);
        assert_eq!(restored.syscall_counts, summary.syscall_counts);
        assert_eq!(restored.category_counts, summary.category_counts);
        assert_eq!(restored.error_counts, summary.error_counts);
        assert_eq!(restored.suspicious.len(), summary.suspicious.len());
    }

    #[test]
    fn record_by_number_maps_correctly() {
        let mut tracker = SyscallTracker::new(1);
        tracker.record_syscall(0, None); // read
        tracker.record_syscall(1, None); // write
        tracker.record_syscall(59, None); // execve

        let summary = tracker.drain_summary();
        assert_eq!(summary.syscall_counts["read"], 1);
        assert_eq!(summary.syscall_counts["write"], 1);
        assert_eq!(summary.syscall_counts["execve"], 1);
    }

    #[test]
    fn empty_tracker_produces_empty_summary() {
        let mut tracker = SyscallTracker::new(1);
        let summary = tracker.drain_summary();
        assert_eq!(summary.total_syscalls, 0);
        assert_eq!(summary.unique_syscalls, 0);
        assert!(summary.syscall_counts.is_empty());
        assert!(summary.category_counts.is_empty());
        assert!(summary.error_counts.is_empty());
        assert!(summary.suspicious.is_empty());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn capture_returns_error_on_non_linux() {
        let config = SyscallMonitorConfig {
            jailer_pid: 1,
            agent_id: "test".to_string(),
            trace_id: "test".to_string(),
            capture_duration: None,
        };
        let result = capture_syscalls(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Linux"));
    }
}
