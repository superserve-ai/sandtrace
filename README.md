<p align="center">
  <h1 align="center">Sandtrace</h1>
  <p align="center">
    Hypervisor-level audit trails for AI agent sandboxes.
    <br />
    <em>Agent observability tools log what agents report doing. Sandtrace logs what they actually do.</em>
  </p>
</p>

<p align="center">
  <a href="#the-problem">The Problem</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#the-exploit-that-inspired-this">The Exploit</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#policy-manifest">Policy Manifest</a>
</p>

---

## The Problem

AI agents run inside sandboxes. Sandboxes enforce network policies — block unauthorized egress, restrict filesystem access, isolate the environment. This is supposed to be enough.

**It isn't.**

An agent that can call `stripe_charge(amount=1, description=<contents of credentials.json>)` is exfiltrating data through an *allowed* channel. The network policy sees a request to `api.stripe.com:443` — a permitted destination — and waves it through. The payload contains your AWS keys.

Every sandbox provider — E2B, Daytona, Blaxel, or bare Firecracker — has this blind spot. Network-level allow/deny lists cannot inspect what's *inside* a permitted API call.

## How It Works

Sandtrace sits **beneath the agent's trust boundary** — on the host side of a Firecracker microVM. The agent cannot see it, cannot influence it, and cannot suppress it.

```
┌─────────────────────────────────┐
│  Agent (untrusted)              │
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

| Layer | Mechanism | What it catches |
|-------|-----------|-----------------|
| **Network** | AF_PACKET socket on Firecracker's tap device | Every TCP/UDP connection — destination, port, bytes transferred per call |
| **Filesystem** | OverlayFS upper-dir monitoring or block-device snapshot diffs | Files created, modified, deleted — with sizes |
| **Policy** | Manifest-based evaluation with payload size analysis | Allowed-channel exfiltration, anomalous payloads, undeclared destinations |

Each captured event is written to a **tamper-evident hash chain** — a JSONL log where every record includes the hash of its predecessor. Even with root access inside the VM, the audit trail on the host cannot be altered without breaking the chain.

## Quick Start

```bash
# Watch a running sandbox in real time
sandtrace watch --sandbox-id <vm-id> --policy policy.yaml

# Verify an existing audit trail
sandtrace verify ./trace.jsonl --against policy.yaml

# Stream and filter events from a trace file
sandtrace stream ./trace.jsonl --filter-verdict deny,anomaly

# Run the demo exploit
sandtrace demo stripe-exfil
```

## The Exploit That Inspired This

We built a demo agent with access to `stripe_charge` and `read_file` running inside a Daytona sandbox with `network_block_all=True` and only `api.stripe.com:443` allowed.

The agent was given a prompt injection hidden inside a PDF:

```
stripe_charge  amount=420000  payload=69b   ← legitimate invoice
stripe_charge  amount=1       payload=316b  ← credentials.json as description
```

Both calls go to `api.stripe.com:443`. Network policy passes both. The tool call trace looks normal. But the second call has a **4.6x payload size anomaly** — 316 bytes vs 69 bytes — because the description field contains the full contents of `credentials.json`.

Sandtrace catches this. The policy engine compares payload sizes against the declared `max_bytes_per_call` in the manifest and flags the anomaly with a verdict:

```json
{
  "event_type": "policy_violation",
  "verdict": {
    "result": "anomaly",
    "policy_rule": "tool:stripe_charge",
    "reason": "payload 316b exceeds baseline for this tool"
  }
}
```

**Run it yourself:**

```bash
export OPENAI_API_KEY=... DAYTONA_API_KEY=...
python demo-agent/agent.py --exploit network
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

Declare what your agent is allowed to do. Anything else is a violation.

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
| **Blaxel** | Adapter | Provider-specific VM management |
| **Self-hosted** | Supported | Any Linux host running Firecracker |

The provider adapter layer handles the differences between each setup — tap interface naming, rootfs locations, jailer paths, VM metadata — so the capture and policy engines work identically across all of them.

## Why Not Just Use Network Policies?

Network policies answer: *"Can this VM talk to api.stripe.com?"*

Sandtrace answers: *"What did this VM send to api.stripe.com, and does it match what the agent was supposed to send?"*

These are fundamentally different questions. The first is access control. The second is behavioral auditing. You need both.

## License

Apache 2.0
