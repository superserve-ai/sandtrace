# Verifying Audit Trails

Sandtrace writes tamper-evident hash-chained audit logs. This document explains how the hash chain works and how to use verification in CI pipelines.

## How the hash chain works

Every event in the audit trail includes two fields that form a cryptographic chain:

- **`record_hash`** — SHA-256 hash of this event's content
- **`prev_hash`** — the `record_hash` of the previous event (`null` for the first event)

This creates a linked chain: modifying, inserting, deleting, or reordering any event breaks the chain.

### Hash computation

The `record_hash` is computed as SHA-256 over a deterministic byte sequence. Each field is length-prefixed with an 8-byte little-endian length to prevent field boundary collisions:

```
SHA-256(
  len_le(event_id)      + event_id      +
  len_le(event_type)    + event_type    +
  len_le(agent_id)      + agent_id      +
  len_le(trace_id)      + trace_id      +
  seq_le (8 bytes, little-endian)       +
  len_le(prev_hash)     + prev_hash     +  // or "null" for first event
  len_le(wall_time)     + wall_time     +
  len_le(evidence_tier) + evidence_tier +
  len_le(payload_json)  + payload_json
)
```

The payload is serialized as canonical JSON (sorted keys) so the hash is deterministic regardless of field insertion order.

The **verdict is not included** in the hash. This allows re-evaluating events against a different policy without breaking the chain.

### What the chain detects

| Tampering | Detection |
|-----------|-----------|
| **Modified event** | `record_hash` doesn't match recomputed hash (`hash_mismatch`) |
| **Deleted event** | `prev_hash` of next event doesn't match predecessor (`broken_link`), sequence gap detected (`seq_gap`) |
| **Inserted event** | Chain linkage broken — inserted event can't match existing `prev_hash` values |
| **Reordered events** | Sequence numbers not strictly increasing (`seq_reorder`) |
| **Bad genesis** | First event has non-null `prev_hash` (`invalid_genesis`) or `seq != 1` (`invalid_genesis_seq`) |

Verification is O(n) — a single pass through the JSONL file checks every link.

## Using `sandtrace verify`

### Integrity check only

```bash
sandtrace verify trace.jsonl
```

Checks that the hash chain is intact. Exit code `0` means valid, `1` means broken.

### Integrity + policy compliance

```bash
sandtrace verify trace.jsonl --against policy.yaml
```

Checks chain integrity and evaluates every event against the policy. Reports any violations.

### JSON output

```bash
sandtrace verify trace.jsonl --against policy.yaml --json
```

Returns structured results:

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

When errors or violations are present:

```json
{
  "path": "./trace.jsonl",
  "chain": {
    "valid": false,
    "event_count": 42,
    "errors": [
      {
        "seq": 15,
        "event_id": "evt_abc123",
        "kind": "hash_mismatch",
        "detail": "recorded hash abc... != computed hash def..."
      }
    ]
  },
  "policy": {
    "checked": true,
    "violations": [
      {
        "event_id": "evt_xyz789",
        "rule_id": "tool:stripe_charge",
        "reason": "payload 5000B exceeds max 4096B for api.stripe.com:443"
      }
    ]
  }
}
```

## CI/CD integration

### GitHub Actions

```yaml
jobs:
  verify-audit-trail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Sandtrace
        run: cargo install --path crates/cli

      - name: Verify audit trail
        run: |
          sandtrace verify ./trace.jsonl --against ./policy.yaml --json > verification.json
          cat verification.json

      - name: Upload verification results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-verification
          path: verification.json
```

The `verify` command exits with code `1` on any failure, which fails the CI step automatically.

### Generic CI

```bash
#!/bin/bash
set -e

# Verify the audit trail — exits non-zero on any failure
sandtrace verify "$TRACE_FILE" --against "$POLICY_FILE" --json > verification.json

# Optionally parse the JSON for specific checks
chain_valid=$(jq -r '.chain.valid' verification.json)
violation_count=$(jq '.policy.violations | length' verification.json)

echo "Chain valid: $chain_valid"
echo "Policy violations: $violation_count"

if [ "$chain_valid" != "true" ] || [ "$violation_count" -gt 0 ]; then
  echo "FAIL: Audit trail verification failed"
  jq '.' verification.json
  exit 1
fi
```

### Post-sandbox verification

After a sandbox session completes, verify the trace before acting on the agent's output:

```bash
# 1. Agent finishes work in sandbox
# 2. Verify the audit trail
sandtrace verify /path/to/trace.jsonl --against /path/to/policy.yaml

# 3. Only proceed if verification passes
if [ $? -eq 0 ]; then
  echo "Audit trail verified — safe to use agent output"
else
  echo "Audit trail verification failed — do not trust agent output"
  exit 1
fi
```

## Chain error types

| Error | Description |
|-------|-------------|
| `hash_mismatch` | Event's `record_hash` doesn't match the recomputed hash. Content was modified. |
| `broken_link` | Event's `prev_hash` doesn't match the previous event's `record_hash`. Chain linkage broken. |
| `seq_gap` | Sequence number jumped (e.g., 5 → 7). Events may have been deleted. |
| `seq_reorder` | Sequence number not strictly increasing. Events may have been reordered. |
| `invalid_genesis` | First event has a non-null `prev_hash`. |
| `invalid_genesis_seq` | First event has `seq != 1`. |
