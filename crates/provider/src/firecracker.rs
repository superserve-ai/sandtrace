//! Firecracker provider adapter.
//!
//! Connects to a Firecracker microVM via its tap device and overlay
//! filesystem to capture network, filesystem, and syscall events.
//! Uses OverlayFS upper-dir scanning for filesystem change detection.
//!
//! Each capture source runs on its own background thread, feeding events
//! into a shared mpsc channel for continuous monitoring.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sandtrace_capture::CapturedEvent;
use sandtrace_capture::CaptureStream;
use sandtrace_capture::filesystem::{FsTrackingConfig, FsTrackingMethod, watch_fs_changes};
use sandtrace_capture::network::{NetworkCaptureConfig, capture_egress_continuous};
use sandtrace_capture::syscall::{SyscallMonitorConfig, capture_syscalls_continuous};

use crate::SandboxProvider;

/// Default interval for flushing accumulated network events.
const NET_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// Default interval for re-scanning the overlay filesystem.
const FS_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Default interval for flushing accumulated syscall summaries.
const SC_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

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
    fn attach(&self, sandbox_id: &str) -> Result<CaptureStream> {
        let trace_id = uuid::Uuid::new_v4().to_string();
        let shutdown = Arc::new(AtomicBool::new(false));

        tracing::info!(
            sandbox_id,
            socket = %self.socket_path,
            "attaching to Firecracker VM (continuous)"
        );

        let (tx, stream) = CaptureStream::channel();

        // Filesystem monitoring thread — periodic overlay re-scan.
        let fs_config = FsTrackingConfig {
            sandbox_id: sandbox_id.to_string(),
            trace_id: trace_id.clone(),
            method: FsTrackingMethod::OverlayUpperDir {
                upper_dir: PathBuf::from(&self.overlay_upper_dir),
            },
        };
        match watch_fs_changes(&fs_config, tx.clone(), shutdown.clone(), FS_POLL_INTERVAL) {
            Ok(_handle) => tracing::info!("filesystem watch thread started"),
            Err(e) => tracing::warn!(error = %e, "filesystem watch failed, continuing without it"),
        }

        // Network capture thread — continuous AF_PACKET sniffing.
        let net_config = NetworkCaptureConfig {
            tap_device: self.tap_device.clone(),
            sandbox_id: sandbox_id.to_string(),
            trace_id: trace_id.clone(),
            ..Default::default()
        };
        match capture_egress_continuous(&net_config, tx.clone(), shutdown.clone(), NET_FLUSH_INTERVAL) {
            Ok(_handle) => tracing::info!("network capture thread started"),
            Err(e) => tracing::warn!(error = %e, "network capture failed, continuing without it"),
        }

        // Syscall capture thread — continuous ptrace monitoring.
        if let Some(pid) = self.jailer_pid {
            let sc_config = SyscallMonitorConfig {
                jailer_pid: pid,
                sandbox_id: sandbox_id.to_string(),
                trace_id,
                ..Default::default()
            };
            match capture_syscalls_continuous(&sc_config, tx.clone(), shutdown.clone(), SC_FLUSH_INTERVAL) {
                Ok(_handle) => tracing::info!("syscall capture thread started"),
                Err(e) => tracing::warn!(error = %e, "syscall capture failed, continuing without it"),
            }
        }

        // Drop the original sender so the stream ends when all capture
        // threads finish (their cloned senders are dropped).
        drop(tx);

        // Store shutdown flag in the stream so it can be triggered externally.
        // For now, the capture threads will run until the process exits or
        // their individual error conditions trigger.

        Ok(stream)
    }

    fn attach_streaming(
        &self,
        sandbox_id: &str,
        tx: std::sync::mpsc::Sender<CapturedEvent>,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        let trace_id = uuid::Uuid::new_v4().to_string();
        let sandbox_id = sandbox_id.to_string();

        tracing::info!(sandbox_id, "starting continuous capture");

        // Spawn network capture thread.
        let net_tx = tx.clone();
        let net_shutdown = shutdown.clone();
        let tap_device = self.tap_device.clone();
        let net_sandbox_id = sandbox_id.clone();
        let net_trace_id = trace_id.clone();

        let net_handle = std::thread::Builder::new()
            .name(format!("st-net-{}", sandbox_id))
            .spawn(move || {
                let config = NetworkCaptureConfig {
                    tap_device,
                    sandbox_id: net_sandbox_id,
                    trace_id: net_trace_id,
                    ..Default::default()
                };
                if let Err(e) = sandtrace_capture::network::capture_egress_streaming(
                    &config,
                    net_tx,
                    net_shutdown,
                    std::time::Duration::from_secs(2),
                ) {
                    tracing::warn!(error = %e, "network capture stopped");
                }
            })?;

        // Spawn filesystem watcher thread.
        let fs_tx = tx.clone();
        let fs_shutdown = shutdown.clone();
        let overlay_upper_dir = self.overlay_upper_dir.clone();
        let fs_sandbox_id = sandbox_id.clone();
        let fs_trace_id = trace_id.clone();

        let fs_handle = std::thread::Builder::new()
            .name(format!("st-fs-{}", sandbox_id))
            .spawn(move || {
                let config = FsTrackingConfig {
                    sandbox_id: fs_sandbox_id,
                    trace_id: fs_trace_id,
                    method: FsTrackingMethod::OverlayUpperDir {
                        upper_dir: std::path::PathBuf::from(overlay_upper_dir),
                    },
                };
                match sandtrace_capture::filesystem::watch_fs_changes(
                    &config,
                    fs_tx,
                    fs_shutdown,
                    std::time::Duration::from_secs(30),
                ) {
                    Ok(handle) => { let _ = handle.join(); }
                    Err(e) => tracing::warn!(error = %e, "filesystem watch stopped"),
                }
            })?;

        // Wait for both capture threads to finish.
        let _ = net_handle.join();
        let _ = fs_handle.join();

        Ok(())
    }

    fn discover(&self) -> Result<Vec<crate::SandboxInfo>> {
        discover_firecracker_vms()
    }

    #[cfg(target_os = "linux")]
    fn watch_lifecycle(
        &self,
        tx: std::sync::mpsc::Sender<crate::LifecycleEvent>,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        watch_firecracker_lifecycle(tx, shutdown)
    }

    fn name(&self) -> &str {
        "firecracker"
    }
}

/// Discover running Firecracker VMs by scanning `/proc` for firecracker processes.
#[cfg(target_os = "linux")]
pub fn discover_firecracker_vms() -> Result<Vec<crate::SandboxInfo>> {
    let mut sandboxes = Vec::new();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return Ok(vec![]),
    };

    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name().to_string_lossy().to_string();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Read /proc/{pid}/cmdline (NUL-separated)
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let cmdline = match std::fs::read(&cmdline_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
        let first_arg = std::str::from_utf8(args.first().copied().unwrap_or(&[])).unwrap_or("");
        if !first_arg.contains("firecracker") {
            continue;
        }

        // Extract --api-sock value
        let socket_path = args
            .windows(2)
            .find(|w| std::str::from_utf8(w[0]).ok() == Some("--api-sock"))
            .and_then(|w| std::str::from_utf8(w[1]).ok())
            .map(|s| s.to_string());

        let socket_path = match socket_path {
            Some(s) => s,
            None => continue,
        };

        // Derive sandbox_id: prefer socket filename (without extension),
        // then parent dir name, then fall back to fc-{pid}.
        let sock_path = std::path::Path::new(&socket_path);
        let sandbox_id = sock_path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| n != "api" && n != "firecracker" && !n.is_empty())
            .or_else(|| {
                sock_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .filter(|n| n != "tmp" && n != "run" && !n.is_empty())
            })
            .unwrap_or_else(|| format!("fc-{pid}"));

        // Try to query Firecracker API for tap device (best-effort).
        let tap_device = query_fc_tap_device(&socket_path).unwrap_or_else(|| {
            let fallback = format!("tap{}", sandboxes.len());
            tracing::debug!(
                socket = %socket_path,
                fallback = %fallback,
                "could not query Firecracker API for tap device"
            );
            fallback
        });

        // Derive overlay dir from socket dir convention.
        let overlay_upper_dir = sock_path
            .parent()
            .map(|p| p.join("overlay/upper").to_string_lossy().to_string())
            .unwrap_or_else(|| "/overlay/upper".to_string());

        tracing::info!(
            sandbox_id = %sandbox_id,
            pid,
            socket = %socket_path,
            tap = %tap_device,
            "discovered Firecracker VM"
        );

        sandboxes.push(crate::SandboxInfo {
            sandbox_id,
            pid: Some(pid),
            provider: Box::new(FirecrackerProvider {
                socket_path,
                tap_device,
                overlay_upper_dir,
                jailer_pid: Some(pid),
            }),
        });
    }

    Ok(sandboxes)
}

#[cfg(not(target_os = "linux"))]
pub fn discover_firecracker_vms() -> Result<Vec<crate::SandboxInfo>> {
    Ok(vec![])
}

/// Query the Firecracker API via Unix socket to get the tap device name.
/// Returns `None` on any failure (connection refused, timeout, parse error).
#[cfg(target_os = "linux")]
fn query_fc_tap_device(socket_path: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok()?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .ok()?;

    let request = "GET /network-interfaces HTTP/1.0\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }

    let response = String::from_utf8_lossy(&response);

    // Parse HTTP response — find the JSON body after \r\n\r\n
    let body = response.split("\r\n\r\n").nth(1)?;

    let ifaces: serde_json::Value = serde_json::from_str(body).ok()?;
    ifaces
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|iface| iface.get("host_dev_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Event-driven lifecycle watcher (Linux only)
// ---------------------------------------------------------------------------

/// Watch for Firecracker VM lifecycle events using pidfd for process death
/// detection. Does an initial /proc scan, then monitors each discovered
/// process via pidfd. Re-scans periodically (10s) to catch new VMs.
#[cfg(target_os = "linux")]
fn watch_firecracker_lifecycle(
    tx: std::sync::mpsc::Sender<crate::LifecycleEvent>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    /// How often to re-scan /proc for new VMs (seconds).
    const RESCAN_INTERVAL_SECS: u64 = 10;

    struct TrackedVm {
        sandbox_id: String,
        pidfd: Option<std::os::fd::OwnedFd>,
    }

    let mut tracked: HashMap<u32, TrackedVm> = HashMap::new();
    // Force immediate scan on first iteration.
    let mut last_scan = std::time::Instant::now()
        - std::time::Duration::from_secs(RESCAN_INTERVAL_SECS + 1);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Periodic scan for new VMs.
        if last_scan.elapsed() >= std::time::Duration::from_secs(RESCAN_INTERVAL_SECS) {
            if let Ok(discovered) = discover_firecracker_vms() {
                for info in discovered {
                    let pid = match info.pid {
                        Some(p) => p,
                        None => continue,
                    };

                    if tracked.contains_key(&pid) {
                        continue;
                    }

                    let pidfd = open_pidfd(pid);
                    if pidfd.is_none() {
                        tracing::debug!(pid, "pidfd unavailable, using /proc fallback");
                    }

                    let sandbox_id = info.sandbox_id.clone();
                    tracked.insert(
                        pid,
                        TrackedVm {
                            sandbox_id: sandbox_id.clone(),
                            pidfd,
                        },
                    );

                    if tx.send(crate::LifecycleEvent::Attached(info)).is_err() {
                        return Ok(());
                    }
                    tracing::info!(sandbox_id = %sandbox_id, pid, "attached to VM");
                }
            }
            last_scan = std::time::Instant::now();
        }

        // Check for dead VMs via pidfd (instant) or /proc fallback.
        let mut dead_pids = Vec::new();
        for (pid, vm) in &tracked {
            let is_dead = if let Some(ref fd) = vm.pidfd {
                let mut pollfd = libc::pollfd {
                    fd: std::os::fd::AsRawFd::as_raw_fd(fd),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
                ret > 0 && (pollfd.revents & libc::POLLIN) != 0
            } else {
                !std::path::Path::new(&format!("/proc/{pid}")).exists()
            };

            if is_dead {
                dead_pids.push(*pid);
            }
        }

        for pid in dead_pids {
            if let Some(vm) = tracked.remove(&pid) {
                tracing::info!(sandbox_id = %vm.sandbox_id, pid, "VM exited");
                let _ = tx.send(crate::LifecycleEvent::Detached {
                    sandbox_id: vm.sandbox_id,
                });
            }
        }

        // Sleep briefly — pidfd poll is non-blocking, this just paces the loop.
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    Ok(())
}

/// Open a pidfd for the given process (Linux 5.3+).
#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0) };
    if fd >= 0 {
        Some(unsafe { OwnedFd::from_raw_fd(fd as std::os::fd::RawFd) })
    } else {
        None
    }
}
