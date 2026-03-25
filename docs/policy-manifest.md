# Policy Manifest Reference

A policy manifest declares expected agent behavior. Sandtrace evaluates every captured event against these rules and assigns a verdict. Rules are evaluated in first-match order: the first matching rule determines the verdict, enabling deny-before-allow patterns.

## Structure

```yaml
schema_version: "2.0"
mode: enforce          # or "audit" (log-only, no blocking)

rules:
  - id: <unique-rule-id>
    type: <rule-type>
    action: allow       # or "deny"
    mode: audit         # per-rule override (optional)
    description: "..."  # optional
    # type-specific fields...
```

- `schema_version` — must be `"2.0"`
- `mode` — global policy mode: `enforce` (block violations) or `audit` (log only). Defaults to `enforce`.
- `rules` — list of rule objects, evaluated in order (first match wins)

### Common rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique rule identifier |
| `type` | yes | Rule type (see below) |
| `action` | no | `allow` or `deny` (default: `allow`) |
| `mode` | no | Per-rule mode override: `audit` or `enforce` |
| `description` | no | Human-readable description |

## Rule types

### `network_egress`

Controls which network destinations the agent may contact.

```yaml
- id: tool:stripe_charge
  type: network_egress
  description: "Stripe charge API calls"
  destinations:
    - host: api.stripe.com
      port: 443
  max_bytes_per_call: 4096
```

| Field | Required | Description |
|-------|----------|-------------|
| `destinations` | yes | List of allowed host:port pairs |
| `destinations[].host` | yes | Hostname or IP (supports wildcards) |
| `destinations[].port` | yes | TCP/UDP port number |
| `max_bytes_per_call` | no | Maximum bytes per connection. Exceeding triggers `anomaly` verdict |

### `filesystem`

Controls which filesystem paths the agent may access, with optional access level presets.

```yaml
- id: fs:workspace
  type: filesystem
  access: read-write
  paths:
    - /home/agent/**
    - /tmp/**
```

| Field | Required | Description |
|-------|----------|-------------|
| `access` | no | Access preset: `read-only`, `read-write`, or `full` |
| `paths` | yes | List of allowed path patterns (supports wildcards) |

### `match`

Field predicate rules that match events based on payload field values. Supports variable binding for downstream use.

```yaml
- id: deny:exfil
  type: match
  action: deny
  match:
    event_type:
      equals: network_egress
    dest_host:
      not_in:
        - api.stripe.com
        - api.openai.com
  bind:
    host: dest_host
```

| Field | Required | Description |
|-------|----------|-------------|
| `match` | yes | Map of field name to predicate. All predicates must match. |
| `bind` | no | Map of variable name to field path, extracted on match |

#### Field predicates

| Predicate | Description | Example |
|-----------|-------------|---------|
| `equals` | Exact value match (string, number, or bool) | `equals: network_egress` |
| `glob` | Glob pattern match (`*`, `**`) | `glob: "*.evil.com"` |
| `not_in` | Value must not be in the given set | `not_in: [api.stripe.com, api.openai.com]` |

### `threshold`

Aggregate rules that fire when a metric exceeds a limit over a time window.

```yaml
- id: rate:api-calls
  type: threshold
  action: deny
  threshold:
    metric: count
    field: event_id
    window: 5m
    limit: 100.0
```

| Field | Required | Description |
|-------|----------|-------------|
| `threshold.metric` | yes | Aggregation type: `count`, `sum`, or `rate` |
| `threshold.field` | no | Field to aggregate (required for `sum`, optional otherwise) |
| `threshold.window` | yes | Time window, e.g. `5m`, `1h`, `30s` |
| `threshold.limit` | yes | Maximum allowed value before the rule fires |

### `sequence`

Ordered event pattern detection within a time window.

```yaml
- id: seq:exfil-pattern
  type: sequence
  action: deny
  sequence:
    window: 10m
    steps:
      - event_type:
          equals: filesystem_summary
      - event_type:
          equals: network_egress
```

| Field | Required | Description |
|-------|----------|-------------|
| `sequence.window` | yes | Time window for the entire sequence |
| `sequence.steps` | yes | Ordered list of predicate sets (each step uses the same predicates as `match` rules) |

## Wildcard patterns

### Host wildcards (network rules)

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `api.stripe.com` | `api.stripe.com` only | `foo.stripe.com` |
| `*.stripe.com` | `api.stripe.com`, `dashboard.stripe.com` | `a.b.stripe.com` |
| `**.stripe.com` | `api.stripe.com`, `a.b.stripe.com` | `stripe.com` |

- `*` matches exactly one subdomain level
- `**` matches one or more subdomain levels

### Path wildcards (filesystem rules)

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `/home/agent/**` | `/home/agent/file.txt`, `/home/agent/sub/dir/file` | `/home/other/file` |
| `/tmp/*.log` | `/tmp/app.log` | `/tmp/sub/app.log` |
| `/home/*/config` | `/home/alice/config`, `/home/bob/config` | `/home/alice/bob/config` |

- `**` matches any number of path segments (recursive)
- `*` matches one path segment only

## Payload size limits

The `max_bytes_per_call` field on `network_egress` rules limits how much data the agent can send in a single connection.

- Evaluated against the `bytes_sent` field in the event payload
- If `bytes_sent > max_bytes_per_call`, the verdict is `anomaly` instead of `allow`
- If omitted, no size limit is enforced for that rule

This catches exfiltration attempts where an agent stuffs extra data into an otherwise-legitimate API call.

## Verdicts

Every event is evaluated against the policy and assigned one of three verdicts:

| Verdict | Meaning | When |
|---------|---------|------|
| `allow` | Event complies with policy | Matches a rule and satisfies all constraints |
| `deny` | Event violates policy | No matching rule found, or destination/path not in any allowlist |
| `anomaly` | Event matches a rule but violates a constraint | Rule matched but `max_bytes_per_call` exceeded |

The verdict is attached to each event in the audit trail:

```json
{
  "verdict": {
    "result": "anomaly",
    "policy_rule": "tool:stripe_charge",
    "reason": "payload 5000B exceeds max 4096B for api.stripe.com:443"
  }
}
```

## Full example

```yaml
schema_version: "2.0"
mode: enforce

rules:
  # Deny-before-allow: block unknown destinations first
  - id: deny:unknown-egress
    type: match
    action: deny
    match:
      event_type:
        equals: network_egress
      dest_host:
        not_in:
          - api.stripe.com
          - api.openai.com

  # Detect exfiltration pattern
  - id: seq:exfil-pattern
    type: sequence
    action: deny
    sequence:
      window: 10m
      steps:
        - event_type:
            equals: filesystem_summary
        - event_type:
            equals: network_egress

  # Rate limiting
  - id: rate:api-calls
    type: threshold
    action: deny
    threshold:
      metric: count
      window: 5m
      limit: 100.0

  # Filesystem access
  - id: fs:workspace
    type: filesystem
    access: read-write
    paths:
      - /home/agent/**
      - /tmp/**

  # Network egress allowlist
  - id: tool:stripe_charge
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096

  - id: tool:openai_inference
    type: network_egress
    destinations:
      - host: api.openai.com
        port: 443
    max_bytes_per_call: 32768
```

Any network destination or filesystem path not covered by a rule triggers a `deny` verdict.
