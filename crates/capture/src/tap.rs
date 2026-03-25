//! AF_PACKET tap device sniffer for capturing raw Ethernet frames.
//!
//! Opens a raw socket bound to a specific network interface (typically a
//! Firecracker tap device like `tapN`) and reads Ethernet frames. This is
//! Linux-only — other platforms get a compile-time stub that returns an error.

use anyhow::Result;

/// Raw packet sniffer bound to a network interface via AF_PACKET.
///
/// Captures all Ethernet frames traversing the interface, including both
/// inbound (host → VM) and outbound (VM → host) traffic.
///
/// On non-Linux platforms, construction always fails — the struct exists
/// only so downstream code compiles unconditionally.
pub struct TapSniffer {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    buf: Vec<u8>,
    #[cfg(target_os = "linux")]
    len: usize,
}

// ── Linux implementation ──────────────────────────────────────────────

/// Maximum Ethernet frame size: standard MTU (1500) + Ethernet header (14) + margin.
#[cfg(target_os = "linux")]
const MAX_FRAME_SIZE: usize = 1600;

#[cfg(target_os = "linux")]
impl TapSniffer {
    /// Open an AF_PACKET socket bound to the named interface.
    ///
    /// Requires `CAP_NET_RAW` or root privileges.
    pub fn open(iface: &str) -> Result<Self> {
        use anyhow::Context;
        use std::os::fd::FromRawFd;

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "failed to create AF_PACKET socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

        let ifindex = interface_index(&fd, iface)
            .with_context(|| format!("looking up interface index for {iface}"))?;

        // Bind to the specific interface so we only see its traffic.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;

        let ret = unsafe {
            libc::bind(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "failed to bind AF_PACKET socket to {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self {
            fd,
            buf: vec![0u8; MAX_FRAME_SIZE],
            len: 0,
        })
    }

    /// Read the next raw Ethernet frame. Blocks until data arrives or
    /// the socket timeout expires.
    ///
    /// Returns `Ok(None)` on timeout (EAGAIN/EWOULDBLOCK).
    pub fn read_frame(&mut self) -> Result<Option<&[u8]>> {
        use std::os::fd::AsRawFd;

        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(anyhow::anyhow!("recv on AF_PACKET socket: {err}"));
        }
        self.len = n as usize;
        Ok(Some(&self.buf[..self.len]))
    }

    /// Set a receive timeout so `read_frame` returns `Ok(None)` instead
    /// of blocking forever.
    pub fn set_timeout(&self, duration: std::time::Duration) -> Result<()> {
        use std::os::fd::AsRawFd;

        let tv = libc::timeval {
            tv_sec: duration.as_secs() as libc::time_t,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
        };
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "setsockopt SO_RCVTIMEO: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn interface_index(fd: &std::os::fd::OwnedFd, iface: &str) -> Result<i32> {
    use std::os::fd::AsRawFd;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(anyhow::anyhow!("interface name too long: {iface}"));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_bytes.len(),
        );
    }

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCGIFINDEX as libc::c_ulong,
            &ifr,
        )
    };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "ioctl SIOCGIFINDEX for {iface}: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

// ── Non-Linux stub ────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
impl TapSniffer {
    /// AF_PACKET is Linux-only. This stub always returns an error.
    pub fn open(iface: &str) -> Result<Self> {
        Err(anyhow::anyhow!(
            "AF_PACKET tap capture requires Linux (requested: {iface})"
        ))
    }

    pub fn read_frame(&mut self) -> Result<Option<&[u8]>> {
        unreachable!()
    }

    pub fn set_timeout(&self, _duration: std::time::Duration) -> Result<()> {
        unreachable!()
    }
}
