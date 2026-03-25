# Policy Manifest Reference

A policy manifest declares expected agent behavior. Sandtrace evaluates every captured event against these rules and assigns a verdict.

## Structure

```yaml
schema_version: "1.0"

rules:
  - id: <unique-rule-id>
    type: <rule-type>
    # type-specific fields...
```

- `schema_version` — must be `"1.0"`
- `rules` — list of rule objects

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
| `id` | yes | Unique rule identifier |
| `type` | yes | Must be `network_egress` |
| `description` | no | Human-readable description |
| `destinations` | yes | List of allowed host:port pairs |
| `destinations[].host` | yes | Hostname or IP (supports wildcards) |
| `destinations[].port` | yes | TCP/UDP port number |
| `max_bytes_per_call` | no | Maximum bytes per connection. Exceeding triggers `anomaly` verdict |

### `filesystem`

Controls which filesystem paths the agent may access.

```yaml
- id: tool:read_file
  type: filesystem
  description: "Local file reads within agent workspace"
  paths:
    - /home/agent/**
    - /tmp/**
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique rule identifier |
| `type` | yes | Must be `filesystem` |
| `description` | no | Human-readable description |
| `paths` | yes | List of allowed path patterns (supports wildcards) |

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
schema_version: "1.0"

rules:
  - id: tool:read_file
    type: filesystem
    description: Local file reads within agent workspace
    paths:
      - /home/agent/**
      - /tmp/**

  - id: tool:stripe_charge
    type: network_egress
    description: Stripe payment processing
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096

  - id: tool:openai_inference
    type: network_egress
    description: OpenAI API calls for LLM inference
    destinations:
      - host: api.openai.com
        port: 443
    max_bytes_per_call: 32768
```

Any network destination or filesystem path not covered by a rule triggers a `deny` verdict.
