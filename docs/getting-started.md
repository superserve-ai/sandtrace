# Getting Started

## Prerequisites

- **Rust toolchain** (stable) — install via [rustup](https://rustup.rs/)
- **Linux host** — Sandtrace captures from the host side of Firecracker microVMs
- A running sandbox environment (Firecracker, E2B, Daytona, or Blaxel)

## Build from source

```bash
git clone <repo-url>
cd sandtrace
cargo build --release
```

The binary is at `target/release/sandtrace`.

To install system-wide:

```bash
cargo install --path crates/cli
```

## First run: demo mode

The fastest way to see Sandtrace in action — no running VM required:

```bash
sandtrace demo stripe-exfil
```

This generates a synthetic audit trail showing an agent exfiltrating AWS credentials via a Stripe API call. Output goes to `/tmp/sandtrace-demo/stripe-exfil.jsonl`.

Try the multi-session persistence scenario:

```bash
sandtrace demo persist
```

This shows a prompt injection planting a standing instruction in `.agent_memory.json`, then a later session reading and exfiltrating data without any visible injection.

## Verify a trace

Check the integrity of an audit trail and evaluate it against a policy:

```bash
sandtrace verify /tmp/sandtrace-demo/stripe-exfil.jsonl --against schema/policy.yaml
```

Output shows chain integrity status and any policy violations.

## Stream and filter events

Filter events from a trace file:

```bash
sandtrace stream /tmp/sandtrace-demo/stripe-exfil.jsonl --filter-verdict deny,anomaly
```

## Watch a live sandbox

Attach to a running sandbox and capture events in real time:

```bash
sandtrace watch --sandbox-id <vm-id> --policy policy.yaml --output trace.jsonl
```

Sandtrace auto-detects your provider (E2B, Daytona, Blaxel, or raw Firecracker). To force a specific provider:

```bash
SANDTRACE_PROVIDER=firecracker sandtrace watch --sandbox-id vm-001 --policy policy.yaml
```

## Write a policy

Create a `policy.yaml` declaring what your agent is allowed to do:

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

Any network egress or filesystem access not matching a rule is flagged as a violation. See the [Policy Manifest Reference](policy-manifest.md) for full syntax.

## Next steps

- [Policy Manifest Reference](policy-manifest.md) — full YAML syntax and rule types
- [Event Schema Reference](event-schema.md) — event types, evidence tiers, field meanings
- [CLI Reference](cli-reference.md) — all commands and flags
- [Provider Setup](provider-setup.md) — configure Firecracker, E2B, Daytona, Blaxel
- [Verifying Audit Trails](verifying-audit-trails.md) — hash chain mechanics and CI usage
