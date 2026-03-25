<p align="center">
  <h1 align="center">Sandtrace</h1>
  <p align="center">
    Hypervisor-level audit trails for AI agent sandboxes.
  </p>
</p>

<p align="center">
  <a href="#what-it-does">What It Does</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#policy-manifest">Policy Manifest</a> &middot;
  <a href="#supported-providers">Providers</a>
</p>

---

## What It Does

Sandboxes isolate the environment. Sandtrace audits what happens inside it.

Network policies control which destinations an agent can reach. Sandtrace adds the next layer: recording *what* gets sent to those destinations, tracking filesystem changes, and evaluating behavior against a declared policy — all from outside the VM, where the agent can't influence the instrumentation.

It sits on the host side of a Firecracker microVM, capturing network traffic, filesystem diffs, and syscalls independently of the guest.

```
┌─────────────────────────────────┐
│  Agent (guest VM)               │
│  ┌───────────┐  ┌────────────┐  │
│  │ Tool calls│  │ File I/O   │  │
│  └─────┬─────┘  └──────┬─────┘  │
│        │               │        │
│  Guest │ VM ───────────────────  │
└────────┼───────────────┼────────┘
         │ tap device    │ virtio-blk / overlayfs
   ┌─────┴───────────────┴────────┐
   │  Sandtrace (host-level)      │
   │                              │
   │  ● Packet capture on tap0    │
   │  ● Filesystem diff via       │
   │    overlay upper-dir         │
   │  ● Policy evaluation         │
   │  ● Hash-chained audit log    │
   └──────────────────────────────┘
```

Three capture layers, all host-side:

| Layer | Mechanism | What it records |
|-------|-----------|-----------------|
| **Network** | AF_PACKET socket on Firecracker's tap device | Every TCP/UDP connection — destination, port, bytes transferred |
| **Filesystem** | OverlayFS upper-dir monitoring or block-device snapshot diffs | Files created, modified, deleted — with sizes |
| **Syscall** | ptrace on the jailer process | System call activity from the guest |

Each event is evaluated against a [policy manifest](#policy-manifest) and written to a **tamper-evident hash chain** — a JSONL log where every record includes the hash of its predecessor.

## Quick Start

```bash
# Watch a running sandbox in real time
sandtrace watch --sandbox-id <vm-id> --policy policy.yaml

# Verify an existing audit trail
sandtrace verify ./trace.jsonl --against policy.yaml

# Stream and filter events from a trace file
sandtrace stream ./trace.jsonl --filter-verdict deny,anomaly

# Run a demo scenario
sandtrace demo stripe-exfil
```

## Architecture

Sandtrace is a Rust workspace with six crates:

```
crates/
├── cli/           CLI entry point (clap) — watch, verify, stream, demo
├── capture/       Host-side capture engines
│   ├── network    AF_PACKET tap sniffer + TCP/UDP packet parser
│   ├── filesystem OverlayFS upper-dir watcher + snapshot differ
│   ├── tap        Raw tap device binding (Linux AF_PACKET)
│   ├── packet     Ethernet/IP/TCP/UDP frame parser
│   └── syscall    seccomp-bpf / eBPF hooks (optional depth)
├── policy/        Manifest loader + rule evaluator + violation checker
├── audit-chain/   Hash-chained JSONL writer + tamper detection verifier
├── output/        Event pipeline — filtering, validation, sinks (file/stdout/unix socket)
└── provider/      Sandbox provider adapters
    ├── firecracker  Generic Firecracker VM discovery
    └── snapshot     Block-device snapshot management
```

### Audit Event Schema

Every event follows the [AuditEvent schema](schema/event.json):

```json
{
  "schema_version": "1.0",
  "event_id": "evt_a1b2c3",
  "event_type": "network_egress",
  "agent_id": "agent-xyz",
  "trace_id": "trace-001",
  "seq": 1,
  "prev_hash": null,
  "record_hash": "sha256:...",
  "wall_time": "2025-03-25T12:00:00Z",
  "evidence_tier": "hypervisor",
  "payload": { "dst_host": "api.stripe.com", "dst_port": 443, "bytes_sent": 316 },
  "verdict": { "result": "anomaly", "policy_rule": "tool:stripe_charge", "reason": "..." }
}
```

The `record_hash` is `SHA-256(canonical_json(event_without_hash) + prev_hash)`. Chain verification is O(n) — one pass through the JSONL file detects any modification, insertion, deletion, or reordering.

## Policy Manifest

Declare expected agent behavior. Sandtrace evaluates events against these rules.

```yaml
schema_version: "1.0"

rules:
  - id: tool:stripe_charge
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096

  - id: tool:read_file
    type: filesystem
    paths:
      - /home/agent/**
      - /tmp/**
```

The policy engine supports:
- **Wildcard matching** on hosts and file paths (`*.stripe.com`, `/home/agent/**`)
- **Payload size limits** per tool (`max_bytes_per_call`)
- **Destination allowlists** with host:port granularity
- **Three verdicts**: `allow`, `deny`, `anomaly`

## Supported Providers

Sandtrace works with any sandbox that runs on Firecracker microVMs:

| Provider | Status | Notes |
|----------|--------|-------|
| **Firecracker** (raw) | Supported | Direct tap device + jailer integration |
| **E2B** | Adapter | Hooks into E2B sandbox lifecycle |
| **Daytona** | Adapter | Devcontainer-based workspace support |
| **Self-hosted** | Supported | Any Linux host running Firecracker |

The provider adapter layer handles the differences between each setup — tap interface naming, rootfs locations, jailer paths, VM metadata — so the capture and policy engines work identically across all of them.

## License

Apache 2.0
