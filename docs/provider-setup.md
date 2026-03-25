# Provider Setup

Sandtrace supports multiple sandbox providers. The provider adapter layer handles differences in tap interface naming, rootfs locations, jailer paths, and VM metadata so the capture and policy engines work identically across all providers.

## Auto-detection

When you run `sandtrace watch`, the provider is auto-detected in this order:

1. **`SANDTRACE_PROVIDER` env var** — if set, uses that provider directly
2. **Runtime env vars** — checks for `E2B_SANDBOX_ID`, `DAYTONA_WS_ID`
3. **Filesystem probes** — checks for provider-specific directories
4. **Fallback** — uses raw Firecracker

To force a specific provider:

```bash
export SANDTRACE_PROVIDER=firecracker  # or: e2b, daytona, blaxel
sandtrace watch --sandbox-id vm-001 --policy policy.yaml
```

If `SANDTRACE_PROVIDER` is set to an invalid value, Sandtrace logs a warning and falls back to auto-detection.

## Firecracker (raw)

The default fallback provider. Works with any Linux host running Firecracker directly.

**Detection:** Always available (fallback).

**Defaults:**

| Setting | Default |
|---------|---------|
| Socket path | `/run/firecracker.socket` |
| Tap device | `tap0` |
| Overlay upper dir | `/overlay/upper` |
| Jailer PID | (optional, for syscall capture) |

**Setup:**

1. Start a Firecracker microVM with a tap device:
   ```bash
   ip tuntap add tap0 mode tap
   ip link set tap0 up
   ```

2. Configure the VM to use the tap device for networking.

3. If using OverlayFS for the rootfs, note the upper directory path.

4. Run Sandtrace:
   ```bash
   sandtrace watch --sandbox-id <vm-id> --policy policy.yaml
   ```

## E2B

Hooks into the E2B sandbox lifecycle.

**Detection:** `E2B_SANDBOX_ID` env var is set, or `/e2b/sandboxes/` directory exists.

**Conventions:**

| Path | Purpose |
|------|---------|
| `/e2b/sandboxes/{sandbox_id}/rootfs` | Guest filesystem root |
| `/e2b/sandboxes/{sandbox_id}/snapshots/{label}/` | Filesystem snapshots |
| `/e2b/sandboxes/{sandbox_id}/metadata.json` | Sandbox metadata |

**Defaults:**

| Setting | Default |
|---------|---------|
| Sandboxes dir | `/e2b/sandboxes` |
| Tap device | Auto-derived from sandbox index |
| Before snapshot | `"base"` |
| After snapshot | `"current"` |

**Usage:**

```bash
# Auto-detected if E2B_SANDBOX_ID is set
sandtrace watch --sandbox-id $E2B_SANDBOX_ID --policy policy.yaml

# Or force the provider
SANDTRACE_PROVIDER=e2b sandtrace watch --sandbox-id my-sandbox --policy policy.yaml
```

## Daytona

Devcontainer-based workspace support.

**Detection:** `DAYTONA_WS_ID` env var is set, or `/var/lib/daytona/workspaces/` directory exists.

**Conventions:**

| Path | Purpose |
|------|---------|
| `/var/lib/daytona/workspaces/{workspace_id}` | Workspace root |
| `{workspace_root}/projects/{project_name}` | Project directory |
| `{workspace_root}/overlay/upper` | OverlayFS upper dir |

**Defaults:**

| Setting | Default |
|---------|---------|
| Workspaces dir | `/var/lib/daytona/workspaces` |
| Tap device | `dt-{workspace_id_prefix}` (first 8 chars of ID) |
| Tracking mode | Overlay (default) or Snapshot |

**Usage:**

```bash
# Auto-detected if DAYTONA_WS_ID is set
sandtrace watch --sandbox-id $DAYTONA_WS_ID --policy policy.yaml

# Or force it
SANDTRACE_PROVIDER=daytona sandtrace watch --sandbox-id ws-001 --policy policy.yaml
```

## Blaxel

Provider-specific VM management.

**Detection:** `/var/lib/blaxel/vms/` directory exists.

**Conventions:**

| Path | Purpose |
|------|---------|
| `/var/lib/blaxel/vms/{vm_id}` | VM directory |
| `{vm_dir}/rootfs` | Guest filesystem root |
| `{vm_dir}/checkpoints/{label}` | Filesystem checkpoints |
| `{vm_dir}/vm.json` | VM configuration |

**Defaults:**

| Setting | Default |
|---------|---------|
| VMs dir | `/var/lib/blaxel/vms` |
| Tap device | `blx{vm_id_prefix}` (first 6 chars of ID) |
| Before checkpoint | `"init"` |
| After checkpoint | `"latest"` |

**Usage:**

```bash
SANDTRACE_PROVIDER=blaxel sandtrace watch --sandbox-id vm-001 --policy policy.yaml
```

## Provider comparison

| Provider | Tap device | FS tracking | Detection method |
|----------|-----------|-------------|-----------------|
| Firecracker | `tap0` | Overlay upper-dir | Fallback (always) |
| E2B | Auto (by sandbox index) | Snapshot diff or overlay | `E2B_SANDBOX_ID` env or `/e2b/sandboxes/` |
| Daytona | `dt-{id_prefix}` | Overlay (default) or snapshot | `DAYTONA_WS_ID` env or `/var/lib/daytona/workspaces/` |
| Blaxel | `blx{id_prefix}` | Snapshot diff | `/var/lib/blaxel/vms/` |

All providers support optional `jailer_pid` for syscall-level capture via ptrace.
