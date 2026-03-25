# CLI Reference

## Global flags

| Flag | Description |
|------|-------------|
| `--policy <FILE>` | Path to policy YAML manifest |
| `-v, --verbose` | Enable debug logging |
| `--version` | Print version |
| `--help` | Print help |

## `sandtrace watch`

Attach to a running sandbox and capture events in real time.

```
sandtrace watch --sandbox-id <VM_ID> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--sandbox-id <ID>` | (required) | Sandbox or VM identifier to attach to |
| `-o, --output <TARGET>` | `-` (stdout) | Output target: file path, `-` for stdout, or `unix:///path` for Unix socket |
| `--filter-type <TYPES>` | (none) | Comma-separated event types: `network_egress`, `filesystem_summary`, `syscall_activity`, `policy_violation` |
| `--filter-tier <TIERS>` | (none) | Comma-separated evidence tiers: `hypervisor`, `kernel` |
| `--filter-verdict <VERDICTS>` | (none) | Comma-separated verdicts: `allow`, `deny`, `anomaly` |
| `--no-validate` | false | Disable JSON schema validation on output events |

**Examples:**

```bash
# Watch a sandbox, write audit trail to file
sandtrace watch --sandbox-id vm-001 --policy policy.yaml --output trace.jsonl

# Watch and filter for violations only
sandtrace watch --sandbox-id vm-001 --policy policy.yaml --filter-verdict deny,anomaly

# Watch network events only, output to Unix socket
sandtrace watch --sandbox-id vm-001 --filter-type network_egress --output unix:///tmp/sandtrace.sock
```

The provider is auto-detected. Override with `SANDTRACE_PROVIDER` env var (see [Provider Setup](provider-setup.md)).

## `sandtrace verify`

Verify the integrity of an audit trail and optionally check policy compliance.

```
sandtrace verify <PATH> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `<PATH>` | (required) | Path to JSONL audit trail file |
| `--against <FILE>` | (none) | Policy file to verify against (overrides `--policy`) |
| `--json` | false | Output results as JSON instead of human-readable text |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Chain valid and no policy violations (or no policy specified) |
| `1` | Chain broken or policy violations found |

**Examples:**

```bash
# Verify chain integrity only
sandtrace verify trace.jsonl

# Verify chain integrity + policy compliance
sandtrace verify trace.jsonl --against policy.yaml

# JSON output for CI pipelines
sandtrace verify trace.jsonl --against policy.yaml --json
```

**Human-readable output:**

```
Chain integrity: VALID (42 events)
Policy compliance: PASS
```

```
Chain integrity: BROKEN (42 events, 2 errors)
  seq 15: hash_mismatch — recorded hash abc... != computed hash def...
  seq 20: broken_link — prev_hash does not match previous record's hash
Policy compliance: 3 violations
  event evt_a1b2c3: [tool:stripe] payload 5000B exceeds max 4096B
```

**JSON output:**

```json
{
  "path": "./trace.jsonl",
  "chain": {
    "valid": true,
    "event_count": 42,
    "errors": []
  },
  "policy": {
    "checked": true,
    "violations": []
  }
}
```

## `sandtrace stream`

Read and filter events from an existing trace file.

```
sandtrace stream <PATH> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `<PATH>` | (required) | Path to JSONL audit trail file |
| `-o, --output <TARGET>` | `-` (stdout) | Output target: file path, `-` for stdout, or `unix:///path` |
| `--filter-type <TYPES>` | (none) | Comma-separated event types |
| `--filter-tier <TIERS>` | (none) | Comma-separated evidence tiers |
| `--filter-verdict <VERDICTS>` | (none) | Comma-separated verdicts |
| `--no-validate` | false | Disable schema validation |

**Examples:**

```bash
# Show all events
sandtrace stream trace.jsonl

# Filter to denials and anomalies
sandtrace stream trace.jsonl --filter-verdict deny,anomaly

# Extract network events to a new file
sandtrace stream trace.jsonl --filter-type network_egress --output network-only.jsonl

# Show only hypervisor-tier events
sandtrace stream trace.jsonl --filter-tier hypervisor
```

## `sandtrace demo`

Generate a synthetic audit trail demonstrating attack scenarios. No running VM required.

```
sandtrace demo [SCENARIO]
```

| Scenario | Description |
|----------|-------------|
| `stripe-exfil` | (default) Agent exfiltrates AWS credentials by stuffing them into a Stripe API call. Demonstrates payload-size anomaly detection. |
| `persist` | Multi-session persistence attack. First session plants a standing instruction in `.agent_memory.json` via prompt injection. Second session reads and exfiltrates without any visible injection. |

Output is written to `/tmp/sandtrace-demo/<scenario>.jsonl`.

**Examples:**

```bash
# Run the default demo
sandtrace demo

# Run a specific scenario
sandtrace demo persist

# Verify the demo output
sandtrace demo stripe-exfil
sandtrace verify /tmp/sandtrace-demo/stripe-exfil.jsonl --against schema/policy.yaml
```
