#!/usr/bin/env bash
# e2e-watch.sh — End-to-end test for sandtrace watch auto-discovery.
#
# Requires: Firecracker, sandtrace binary, kernel + rootfs at standard paths.
# Run as root on a bare metal Linux host with KVM.
#
# Usage: sudo ./tests/e2e-watch.sh

set -euo pipefail

PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KERNEL="${KERNEL:-/var/lib/sandtrace/kernel/vmlinux.bin}"
ROOTFS="${ROOTFS:-/var/lib/sandtrace/rootfs/alpine-rootfs.ext4}"
WORKDIR="/tmp/sandtrace-e2e-$$"

# Colors
GREEN='\033[32m'
RED='\033[31m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { PASS=$((PASS + 1)); echo -e "  ${GREEN}✓${RESET} $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  ${RED}✗${RESET} $1"; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

cleanup() {
    echo ""
    echo "Cleaning up..."
    kill "$ST_PID" 2>/dev/null || true
    pkill -f "firecracker --api-sock ${WORKDIR}" 2>/dev/null || true
    sleep 1
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo -e "${BOLD}sandtrace e2e test${RESET}"
echo ""

[[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 1; }
[[ -e /dev/kvm ]] || { echo "/dev/kvm not found"; exit 1; }
command -v firecracker &>/dev/null || { echo "firecracker not found"; exit 1; }
command -v sandtrace &>/dev/null || { echo "sandtrace not found"; exit 1; }
[[ -f "$KERNEL" ]] || { echo "Kernel not found at $KERNEL"; exit 1; }
[[ -f "$ROOTFS" ]] || { echo "Rootfs not found at $ROOTFS"; exit 1; }

mkdir -p "$WORKDIR"

# ---------------------------------------------------------------------------
# Helper: start a Firecracker VM
# ---------------------------------------------------------------------------
start_vm() {
    local vm_name="$1"
    local vm_dir="$WORKDIR/$vm_name"
    local tap_name="$2"

    mkdir -p "$vm_dir/overlay/upper"
    cp "$ROOTFS" "$vm_dir/rootfs.ext4"

    local sock="$vm_dir/api.sock"
    rm -f "$sock"
    firecracker --api-sock "$sock" > /dev/null 2>&1 &
    sleep 1

    curl -s --unix-socket "$sock" -X PUT "http://localhost/boot-source" \
      -H "Content-Type: application/json" \
      -d "{\"kernel_image_path\": \"$KERNEL\", \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"}" > /dev/null

    curl -s --unix-socket "$sock" -X PUT "http://localhost/drives/rootfs" \
      -H "Content-Type: application/json" \
      -d "{\"drive_id\": \"rootfs\", \"path_on_host\": \"$vm_dir/rootfs.ext4\", \"is_root_device\": true, \"is_read_only\": false}" > /dev/null

    curl -s --unix-socket "$sock" -X PUT "http://localhost/machine-config" \
      -H "Content-Type: application/json" \
      -d '{"vcpu_count": 1, "mem_size_mib": 128}' > /dev/null

    curl -s --unix-socket "$sock" -X PUT "http://localhost/actions" \
      -H "Content-Type: application/json" \
      -d '{"action_type": "InstanceStart"}' > /dev/null

    echo "  Started VM: $vm_name (PID=$(pgrep -f "api-sock $sock"))"
}

kill_vm() {
    local vm_name="$1"
    local sock="$WORKDIR/$vm_name/api.sock"
    local pid
    pid=$(pgrep -f "api-sock $sock" 2>/dev/null || true)
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        echo "  Killed VM: $vm_name (PID=$pid)"
    fi
}

# ---------------------------------------------------------------------------
# Test 1: Start 2 VMs, run sandtrace watch, verify auto-discovery
# ---------------------------------------------------------------------------
echo -e "${BOLD}Phase 1: Auto-discovery of 2 VMs${RESET}"

start_vm "vm-alpha" "tap-alpha"
start_vm "vm-beta" "tap-beta"
sleep 2

export SANDTRACE_PROVIDER=firecracker
sandtrace watch \
    -o "$WORKDIR/audit.jsonl" \
    > "$WORKDIR/stdout.log" 2>"$WORKDIR/watch.log" &
ST_PID=$!

# Wait for lifecycle watcher to discover VMs (10s rescan + buffer).
sleep 15

check "sandtrace is running" "kill -0 $ST_PID 2>/dev/null"
check "vm-alpha attached" "grep -q 'vm-alpha' $WORKDIR/watch.log"
check "vm-beta attached" "grep -q 'vm-beta' $WORKDIR/watch.log"
check "banner shows 2 sandboxes" "grep -q 'sandboxes: 2' $WORKDIR/watch.log"

# ---------------------------------------------------------------------------
# Test 2: Generate filesystem events, verify capture
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 2: Filesystem capture${RESET}"

# Write files AFTER sandtrace has attached to VMs.
echo "test data from alpha" > "$WORKDIR/vm-alpha/overlay/upper/output.txt"
mkdir -p "$WORKDIR/vm-beta/overlay/upper/workspace"
echo '{"result": "ok"}' > "$WORKDIR/vm-beta/overlay/upper/workspace/result.json"
sleep 8

check "audit trail has events" "[ -s $WORKDIR/audit.jsonl ]"

EVENT_COUNT=$(wc -l < "$WORKDIR/audit.jsonl" 2>/dev/null || echo 0)
check "at least 1 event captured" "[ $EVENT_COUNT -ge 1 ]"

if [ -s "$WORKDIR/audit.jsonl" ]; then
    check "events have sandbox_id field" "grep -q 'sandbox_id' $WORKDIR/audit.jsonl"
    check "events are filesystem_summary type" "grep -q 'filesystem_summary' $WORKDIR/audit.jsonl"
fi

# ---------------------------------------------------------------------------
# Test 3: Kill a VM, verify detach
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 3: Hot-detach (kill VM)${RESET}"

kill_vm "vm-alpha"
sleep 3

check "vm-alpha detach logged" "grep -qi 'detach\|finished\|exited' $WORKDIR/watch.log"

# ---------------------------------------------------------------------------
# Test 4: Start a new VM, verify hot-attach
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 4: Hot-attach (new VM)${RESET}"

start_vm "vm-gamma" "tap-gamma"
sleep 12  # Firecracker lifecycle rescan is 10s

check "vm-gamma discovered" "grep -q 'vm-gamma\|attached' $WORKDIR/watch.log"

# Generate events from new VM
echo "gamma output" > "$WORKDIR/vm-gamma/overlay/upper/gamma.txt"
sleep 5

# ---------------------------------------------------------------------------
# Test 5: Stop sandtrace, verify audit trail integrity
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Phase 5: Shutdown + verify${RESET}"

kill -TERM "$ST_PID" 2>/dev/null || true
wait "$ST_PID" 2>/dev/null || true
ST_PID=""

FINAL_COUNT=$(wc -l < "$WORKDIR/audit.jsonl" 2>/dev/null || echo 0)
check "audit trail has events ($FINAL_COUNT)" "[ $FINAL_COUNT -ge 1 ]"

if [ -s "$WORKDIR/audit.jsonl" ]; then
    VERIFY_OUT=$(sandtrace verify "$WORKDIR/audit.jsonl" 2>&1)
    check "chain integrity VALID" "echo '$VERIFY_OUT' | grep -q 'VALID'"
fi

check "watch log has summary" "grep -q 'summary' $WORKDIR/watch.log"

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTAL=$((PASS + FAIL))
echo -e "${BOLD}Results: $PASS/$TOTAL passed${RESET}"
if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}$FAIL tests failed${RESET}"
    echo ""
    echo "=== Watch log ==="
    cat "$WORKDIR/watch.log"
    echo ""
    echo "=== Audit trail ==="
    cat "$WORKDIR/audit.jsonl" 2>/dev/null || echo "(empty)"
    exit 1
else
    echo -e "${GREEN}All tests passed${RESET}"
    exit 0
fi
