#!/usr/bin/env bash
# setup-bare-metal.sh — Idempotent bare metal provisioning for sandtrace integration testing.
#
# Installs KVM/libvirt, Firecracker + jailer, builds sandtrace from source,
# sets up a minimal Alpine guest rootfs with Python + demo-agent, configures
# tap/bridge networking, and installs E2B CLI (local mode) and Daytona server
# (single-node mode).
#
# Target: Ubuntu 22.04 / 24.04
# Usage:  sudo ./setup-bare-metal.sh
#
# Machine-specific config is read from .env in the same directory as this
# script. See .env.example for the available variables.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Load .env (optional — provides overrides)
# ---------------------------------------------------------------------------
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    set -a; source "$SCRIPT_DIR/.env"; set +a
fi

# ---------------------------------------------------------------------------
# Tunables (override via .env or environment)
# ---------------------------------------------------------------------------
FIRECRACKER_VERSION="${FIRECRACKER_VERSION:-1.11.0}"
FIRECRACKER_ARCH="${FIRECRACKER_ARCH:-x86_64}"

# SHA-256 checksums for Firecracker binaries (from official GitHub release tarball)
# These are checksums of the BINARIES inside the tarball, not the tarball itself.
# Update these when changing FIRECRACKER_VERSION.
# Verify: download tarball, extract, sha256sum the binary.
declare -A FC_SHA256=(
    ["firecracker-v1.11.0-x86_64"]="8f0ea0c508d690b288079709830ca6aa037f75cea3dc9ddd48b2aa0ab0b448d5"
    ["jailer-v1.11.0-x86_64"]="6e8d9e719e562376f9f528425724f8e3e0bc64507cb6fe98805d611c0452a528"
)

ALPINE_VERSION="${ALPINE_VERSION:-3.21}"
ALPINE_ARCH="${ALPINE_ARCH:-x86_64}"

# Networking
BRIDGE_NAME="${BRIDGE_NAME:-br0}"
TAP_NAME="${TAP_NAME:-tap0}"
BRIDGE_CIDR="${BRIDGE_CIDR:-172.16.0.1/24}"

# Paths
SANDTRACE_DIR="${SANDTRACE_DIR:-$SCRIPT_DIR}"
ROOTFS_DIR="${ROOTFS_DIR:-/var/lib/sandtrace/rootfs}"
KERNEL_DIR="${KERNEL_DIR:-/var/lib/sandtrace/kernel}"
FC_BIN_DIR="${FC_BIN_DIR:-/usr/local/bin}"

# E2B / Daytona
E2B_DIR="${E2B_DIR:-/e2b}"
DAYTONA_DIR="${DAYTONA_DIR:-/var/lib/daytona}"

# Rust toolchain
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { printf '\033[1;34m[info]\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m[ok]\033[0m    %s\n' "$*"; }
warn()  { printf '\033[1;33m[warn]\033[0m  %s\n' "$*"; }
die()   { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

need_root() {
    [[ $EUID -eq 0 ]] || die "Must run as root (sudo ./setup-bare-metal.sh)"
}

command_exists() { command -v "$1" &>/dev/null; }

# ---------------------------------------------------------------------------
# 0. Pre-flight
# ---------------------------------------------------------------------------
need_root

if ! grep -qiE 'ubuntu' /etc/os-release 2>/dev/null; then
    warn "This script targets Ubuntu 22.04/24.04 — other distros may work but are untested"
fi

# Check KVM support
if [[ ! -e /dev/kvm ]]; then
    die "/dev/kvm not found — ensure hardware virtualisation is enabled (VT-x / AMD-V)"
fi

info "Starting bare metal provisioning for sandtrace integration testing"

# ---------------------------------------------------------------------------
# 1. System packages — KVM, libvirt, build essentials
# ---------------------------------------------------------------------------
info "Installing system packages (KVM, libvirt, build tools)..."

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

# KVM / libvirt
apt-get install -y -qq \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    bridge-utils virtinst cpu-checker \
    >/dev/null

# Build essentials for Rust compilation
apt-get install -y -qq \
    build-essential pkg-config libssl-dev \
    git curl wget jq \
    >/dev/null

# Networking tools
apt-get install -y -qq \
    iproute2 iptables net-tools \
    >/dev/null

# Alpine rootfs build deps
apt-get install -y -qq \
    e2fsprogs python3 python3-pip python3-venv \
    >/dev/null

ok "System packages installed"

# ---------------------------------------------------------------------------
# 2. Rust toolchain
# ---------------------------------------------------------------------------
if command_exists rustup; then
    info "Rust toolchain already installed, updating..."
    sudo -u "${SUDO_USER:-root}" rustup update "$RUST_TOOLCHAIN" 2>/dev/null || true
else
    info "Installing Rust toolchain..."
    sudo -u "${SUDO_USER:-root}" bash -c \
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_TOOLCHAIN"
fi

# Ensure cargo is on PATH for the rest of the script
CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
if [[ -n "${SUDO_USER:-}" ]]; then
    CARGO_HOME="$(eval echo "~$SUDO_USER")/.cargo"
fi
export PATH="$CARGO_HOME/bin:$PATH"

ok "Rust toolchain ready ($(rustc --version 2>/dev/null || echo 'unknown'))"

# ---------------------------------------------------------------------------
# 3. Firecracker + jailer
# ---------------------------------------------------------------------------
FC_RELEASE="firecracker-v${FIRECRACKER_VERSION}-${FIRECRACKER_ARCH}"
FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${FIRECRACKER_VERSION}/${FC_RELEASE}.tgz"

verify_sha256() {
    local file="$1" expected="$2" label="$3"
    if [[ -z "$expected" ]]; then
        warn "No checksum configured for $label — skipping verification"
        return 0
    fi
    local actual
    actual="$(sha256sum "$file" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        die "SHA-256 mismatch for $label: expected $expected, got $actual"
    fi
    ok "SHA-256 verified for $label"
}

FC_BIN_KEY="firecracker-v${FIRECRACKER_VERSION}-${FIRECRACKER_ARCH}"
JAILER_BIN_KEY="jailer-v${FIRECRACKER_VERSION}-${FIRECRACKER_ARCH}"

if command_exists firecracker && firecracker --version 2>/dev/null | grep -q "$FIRECRACKER_VERSION"; then
    # Verify existing install
    info "Firecracker v${FIRECRACKER_VERSION} found, verifying checksum..."
    verify_sha256 "$(command -v firecracker)" "${FC_SHA256[$FC_BIN_KEY]:-}" "firecracker"
else
    info "Installing Firecracker v${FIRECRACKER_VERSION}..."
    TMP_FC="$(mktemp -d)"
    wget -qO "$TMP_FC/fc.tgz" "$FC_URL"
    tar -xzf "$TMP_FC/fc.tgz" -C "$TMP_FC"

    # The tarball extracts to release-v<ver>-<arch>/ with binaries inside
    FC_EXTRACTED="$TMP_FC/release-v${FIRECRACKER_VERSION}-${FIRECRACKER_ARCH}"

    # Verify before installing
    verify_sha256 "$FC_EXTRACTED/$FC_BIN_KEY" "${FC_SHA256[$FC_BIN_KEY]:-}" "firecracker"
    verify_sha256 "$FC_EXTRACTED/$JAILER_BIN_KEY" "${FC_SHA256[$JAILER_BIN_KEY]:-}" "jailer"

    install -m 0755 "$FC_EXTRACTED/$FC_BIN_KEY" "$FC_BIN_DIR/firecracker"
    install -m 0755 "$FC_EXTRACTED/$JAILER_BIN_KEY" "$FC_BIN_DIR/jailer"
    rm -rf "$TMP_FC"
    ok "Firecracker v${FIRECRACKER_VERSION} installed to $FC_BIN_DIR"
fi

# ---------------------------------------------------------------------------
# 4. Build sandtrace from source
# ---------------------------------------------------------------------------
info "Building sandtrace from source..."
cd "$SANDTRACE_DIR"
cargo build --release 2>&1 | tail -5

SANDTRACE_BIN="$SANDTRACE_DIR/target/release/sandtrace"
if [[ -f "$SANDTRACE_BIN" ]]; then
    install -m 0755 "$SANDTRACE_BIN" "$FC_BIN_DIR/sandtrace"
    ok "sandtrace binary installed to $FC_BIN_DIR/sandtrace"
else
    warn "sandtrace binary not found at $SANDTRACE_BIN — check build output"
fi

# ---------------------------------------------------------------------------
# 5. Guest rootfs — minimal Alpine with Python + demo-agent
# ---------------------------------------------------------------------------
ROOTFS_IMG="$ROOTFS_DIR/alpine-rootfs.ext4"

if [[ -f "$ROOTFS_IMG" ]]; then
    ok "Guest rootfs already exists at $ROOTFS_IMG"
else
    info "Building Alpine guest rootfs..."
    mkdir -p "$ROOTFS_DIR"

    ROOTFS_MNT="$(mktemp -d)"
    ALPINE_MINI="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"

    # Create ext4 image (512 MB)
    dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=512 status=none
    mkfs.ext4 -q -F "$ROOTFS_IMG"
    mount -o loop "$ROOTFS_IMG" "$ROOTFS_MNT"

    # Extract Alpine minirootfs
    wget -qO- "$ALPINE_MINI" | tar -xz -C "$ROOTFS_MNT"

    # Configure DNS inside the rootfs
    echo "nameserver 8.8.8.8" > "$ROOTFS_MNT/etc/resolv.conf"

    # Install Python + pip + demo-agent deps via chroot
    # Use alpine's apk to install python3
    chroot "$ROOTFS_MNT" /bin/sh -c '
        apk add --no-cache python3 py3-pip >/dev/null 2>&1 || true
    '

    # Copy demo-agent into the rootfs
    mkdir -p "$ROOTFS_MNT/home/agent"
    if [[ -f "$SANDTRACE_DIR/demo-agent/agent.py" ]]; then
        cp "$SANDTRACE_DIR/demo-agent/agent.py" "$ROOTFS_MNT/home/agent/"
        cp "$SANDTRACE_DIR/demo-agent/requirements.txt" "$ROOTFS_MNT/home/agent/"

        # Install Python deps inside the rootfs
        chroot "$ROOTFS_MNT" /bin/sh -c '
            pip3 install --break-system-packages -r /home/agent/requirements.txt 2>/dev/null || \
            pip3 install -r /home/agent/requirements.txt 2>/dev/null || true
        '
    fi

    # Set up init for Firecracker (OpenRC or simple init)
    chroot "$ROOTFS_MNT" /bin/sh -c '
        # Enable serial console
        [ -f /etc/inittab ] && grep -q ttyS0 /etc/inittab || \
            echo "ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100" >> /etc/inittab

        # Enable networking on boot
        mkdir -p /etc/network
        cat > /etc/network/interfaces <<IFACES
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFACES

        # Enable hostname
        echo "sandtrace-guest" > /etc/hostname
    '

    umount "$ROOTFS_MNT"
    rmdir "$ROOTFS_MNT"
    ok "Guest rootfs created at $ROOTFS_IMG"
fi

# ---------------------------------------------------------------------------
# 6. Guest kernel
# ---------------------------------------------------------------------------
KERNEL_IMG="$KERNEL_DIR/vmlinux.bin"

if [[ -f "$KERNEL_IMG" ]]; then
    ok "Guest kernel already exists at $KERNEL_IMG"
else
    info "Downloading Firecracker-compatible kernel..."
    mkdir -p "$KERNEL_DIR"

    # Use the Firecracker CI kernel (known-good for Firecracker)
    KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/${FIRECRACKER_ARCH}/vmlinux-6.1.102"
    wget -qO "$KERNEL_IMG" "$KERNEL_URL"
    ok "Guest kernel downloaded to $KERNEL_IMG"
fi

# ---------------------------------------------------------------------------
# 7. Tap device + bridge networking
# ---------------------------------------------------------------------------
info "Configuring network (bridge=$BRIDGE_NAME, tap=$TAP_NAME)..."

if ip link show "$BRIDGE_NAME" &>/dev/null; then
    ok "Bridge $BRIDGE_NAME already exists"
else
    ip link add name "$BRIDGE_NAME" type bridge
    ip addr add "$BRIDGE_CIDR" dev "$BRIDGE_NAME"
    ip link set "$BRIDGE_NAME" up
    ok "Bridge $BRIDGE_NAME created with $BRIDGE_CIDR"
fi

if ip link show "$TAP_NAME" &>/dev/null; then
    ok "Tap device $TAP_NAME already exists"
else
    ip tuntap add dev "$TAP_NAME" mode tap
    ip link set "$TAP_NAME" master "$BRIDGE_NAME"
    ip link set "$TAP_NAME" up
    ok "Tap device $TAP_NAME created and attached to $BRIDGE_NAME"
fi

# Enable IP forwarding + NAT for guest internet access
sysctl -q -w net.ipv4.ip_forward=1
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# NAT masquerade — idempotent (check before adding)
BRIDGE_SUBNET="${BRIDGE_CIDR%.*}.0/24"
if ! iptables -t nat -C POSTROUTING -s "$BRIDGE_SUBNET" -o "$(ip route | awk '/default/ {print $5; exit}')" -j MASQUERADE 2>/dev/null; then
    DEFAULT_IF="$(ip route | awk '/default/ {print $5; exit}')"
    if [[ -n "$DEFAULT_IF" ]]; then
        iptables -t nat -A POSTROUTING -s "$BRIDGE_SUBNET" -o "$DEFAULT_IF" -j MASQUERADE
        ok "NAT masquerade configured ($BRIDGE_SUBNET → $DEFAULT_IF)"
    else
        warn "No default route found — skipping NAT masquerade"
    fi
else
    ok "NAT masquerade already configured"
fi

# ---------------------------------------------------------------------------
# 8. E2B CLI (local mode)
# ---------------------------------------------------------------------------
info "Setting up E2B local mode..."

mkdir -p "$E2B_DIR/sandboxes"

if command_exists e2b; then
    ok "E2B CLI already installed"
else
    # E2B CLI is an npm package
    if ! command_exists node; then
        info "Installing Node.js for E2B CLI..."
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1
        apt-get install -y -qq nodejs >/dev/null
    fi
    npm install -g @e2b/cli >/dev/null 2>&1 || warn "E2B CLI install failed — install manually: npm i -g @e2b/cli"
fi

ok "E2B local directory structure ready at $E2B_DIR"

# ---------------------------------------------------------------------------
# 9. Daytona server (single-node mode)
# ---------------------------------------------------------------------------
info "Setting up Daytona server..."

mkdir -p "$DAYTONA_DIR/workspaces"

if command_exists daytona; then
    ok "Daytona server already installed"
else
    info "Installing Daytona..."
    curl -fsSL https://download.daytona.io/daytona/install.sh | bash -s -- -y 2>/dev/null \
        || warn "Daytona install failed — install manually: https://www.daytona.io/docs/installation/installation/"
fi

ok "Daytona directory structure ready at $DAYTONA_DIR"

# ---------------------------------------------------------------------------
# 10. Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Sandtrace bare metal provisioning complete"
echo "============================================================"
echo ""
echo "  Firecracker:  $(firecracker --version 2>/dev/null || echo 'not found')"
echo "  Sandtrace:    $(sandtrace --version 2>/dev/null || echo 'not found')"
echo "  Kernel:       $KERNEL_IMG"
echo "  Rootfs:       $ROOTFS_IMG"
echo "  Bridge:       $BRIDGE_NAME ($BRIDGE_CIDR)"
echo "  Tap device:   $TAP_NAME"
echo "  E2B dir:      $E2B_DIR"
echo "  Daytona dir:  $DAYTONA_DIR"
echo ""
echo "  Next steps:"
echo "    1. Copy .env.example to .env and fill in any overrides"
echo "    2. Run integration tests:"
echo "       sandtrace watch --sandbox-id <vm-id> --policy schema/policy.yaml"
echo ""
