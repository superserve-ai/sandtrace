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
            .name("sandtrace-net".to_string())
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
            .name("sandtrace-fs".to_string())
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

        // Derive sandbox_id from socket path
        let sandbox_id = std::path::Path::new(&socket_path)
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("fc-{pid}"));

        // Try to query Firecracker API for tap device
        let tap_device = query_fc_tap_device(&socket_path)
            .unwrap_or_else(|_| format!("tap{}", sandboxes.len()));

        // Derive overlay dir from socket dir convention
        let overlay_upper_dir = std::path::Path::new(&socket_path)
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
#[cfg(target_os = "linux")]
fn query_fc_tap_device(socket_path: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let request = "GET /network-interfaces HTTP/1.0\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Parse HTTP response — find the JSON body after \r\n\r\n
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no body in API response"))?;

    let ifaces: serde_json::Value = serde_json::from_str(body)?;
    let tap = ifaces
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|iface| iface.get("host_dev_name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no host_dev_name in network interfaces"))?;

    Ok(tap.to_string())
}
