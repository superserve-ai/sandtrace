pub mod engine;

use anyhow::{Context, Result};
use sandtrace_audit_chain::{AuditEvent, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use engine::PolicyEngine;

// ---------------------------------------------------------------------------
// Core enums
// ---------------------------------------------------------------------------

/// Global policy mode: audit (log-only) or enforce (block violations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Audit,
    Enforce,
}

/// Rule action: allow or deny matching events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

impl Default for RuleAction {
    fn default() -> Self {
        RuleAction::Allow
    }
}

/// Access preset for filesystem rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessPreset {
    ReadOnly,
    ReadWrite,
    Full,
}

// ---------------------------------------------------------------------------
// Field predicates (for match and sequence rules)
// ---------------------------------------------------------------------------

/// A predicate applied to a single event field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPredicate {
    /// Exact equality (string, number, or bool).
    Equals(serde_json::Value),
    /// Glob pattern match (supports `*` and `**`).
    Glob(String),
    /// Value must NOT be in the given set.
    NotIn(Vec<serde_json::Value>),
}

// ---------------------------------------------------------------------------
// Threshold configuration
// ---------------------------------------------------------------------------

/// Aggregation metric for threshold rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThresholdMetric {
    Count,
    Sum,
    Rate,
}

/// Configuration for a threshold rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub metric: ThresholdMetric,
    /// Field to aggregate (required for `sum`, optional for `count`/`rate`).
    #[serde(default)]
    pub field: Option<String>,
    /// Time window, e.g. `"5m"`, `"1h"`, `"30s"`.
    pub window: String,
    /// Maximum allowed value before the rule fires.
    pub limit: f64,
}

// ---------------------------------------------------------------------------
// Sequence configuration
// ---------------------------------------------------------------------------

/// Configuration for a sequence rule: ordered event pattern within a window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequenceConfig {
    /// Time window for the entire sequence, e.g. `"10m"`.
    pub window: String,
    /// Ordered steps; each step is a set of field predicates that must all match.
    pub steps: Vec<BTreeMap<String, FieldPredicate>>,
}

// ---------------------------------------------------------------------------
// Destination (unchanged from v1)
// ---------------------------------------------------------------------------

/// A permitted network destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

// ---------------------------------------------------------------------------
// PolicyManifest
// ---------------------------------------------------------------------------

/// A policy manifest loaded from a YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifest {
    /// Global policy mode. When `None`, defaults to `Enforce`.
    #[serde(default)]
    pub mode: Option<PolicyMode>,
    pub rules: Vec<PolicyRule>,
}

impl PolicyManifest {
    /// Effective global mode (defaults to `Enforce` when not specified).
    pub fn effective_mode(&self) -> PolicyMode {
        self.mode.unwrap_or(PolicyMode::Enforce)
    }
}

// ---------------------------------------------------------------------------
// PolicyRule — internally tagged enum dispatched on "type"
// ---------------------------------------------------------------------------

/// A single policy rule. The `type` field in YAML selects the variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PolicyRule {
    /// Network egress allowlist.
    #[serde(rename = "network_egress")]
    NetworkEgress {
        id: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        action: RuleAction,
        #[serde(default)]
        mode: Option<PolicyMode>,
        #[serde(default)]
        destinations: Vec<Destination>,
        #[serde(default)]
        max_bytes_per_call: Option<u64>,
    },

    /// Filesystem path allowlist with optional access preset.
    #[serde(rename = "filesystem")]
    Filesystem {
        id: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        action: RuleAction,
        #[serde(default)]
        mode: Option<PolicyMode>,
        #[serde(default)]
        access: Option<AccessPreset>,
        #[serde(default)]
        paths: Vec<String>,
    },

    /// Match rule: field predicates with optional variable binding.
    #[serde(rename = "match")]
    Match {
        id: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        action: RuleAction,
        #[serde(default)]
        mode: Option<PolicyMode>,
        /// Field predicates — all must match for the rule to fire.
        #[serde(rename = "match")]
        predicates: BTreeMap<String, FieldPredicate>,
        /// Variable bindings: `name → field_path` extracted on match.
        #[serde(default)]
        bind: BTreeMap<String, String>,
    },

    /// Threshold rule: count/sum/rate over a sliding time window.
    #[serde(rename = "threshold")]
    Threshold {
        id: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        action: RuleAction,
        #[serde(default)]
        mode: Option<PolicyMode>,
        threshold: ThresholdConfig,
    },

    /// Sequence rule: ordered event pattern within a time window.
    #[serde(rename = "sequence")]
    Sequence {
        id: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        action: RuleAction,
        #[serde(default)]
        mode: Option<PolicyMode>,
        sequence: SequenceConfig,
    },
}

impl PolicyRule {
    /// Rule identifier.
    pub fn id(&self) -> &str {
        match self {
            PolicyRule::NetworkEgress { id, .. }
            | PolicyRule::Filesystem { id, .. }
            | PolicyRule::Match { id, .. }
            | PolicyRule::Threshold { id, .. }
            | PolicyRule::Sequence { id, .. } => id,
        }
    }

    /// Rule action (defaults to `Allow`).
    pub fn action(&self) -> RuleAction {
        match self {
            PolicyRule::NetworkEgress { action, .. }
            | PolicyRule::Filesystem { action, .. }
            | PolicyRule::Match { action, .. }
            | PolicyRule::Threshold { action, .. }
            | PolicyRule::Sequence { action, .. } => *action,
        }
    }

    /// Per-rule mode override, if set.
    pub fn mode(&self) -> Option<PolicyMode> {
        match self {
            PolicyRule::NetworkEgress { mode, .. }
            | PolicyRule::Filesystem { mode, .. }
            | PolicyRule::Match { mode, .. }
            | PolicyRule::Threshold { mode, .. }
            | PolicyRule::Sequence { mode, .. } => *mode,
        }
    }

    /// Optional human-readable description.
    pub fn description(&self) -> Option<&str> {
        match self {
            PolicyRule::NetworkEgress { description, .. }
            | PolicyRule::Filesystem { description, .. }
            | PolicyRule::Match { description, .. }
            | PolicyRule::Threshold { description, .. }
            | PolicyRule::Sequence { description, .. } => description.as_deref(),
        }
    }
}

// ---------------------------------------------------------------------------
// Policy violation
// ---------------------------------------------------------------------------

/// A policy violation found when checking events against rules.
#[derive(Debug, Clone)]
pub struct Violation {
    pub event_id: String,
    pub rule_id: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Loading / parsing
// ---------------------------------------------------------------------------

/// Load a policy manifest from a YAML file.
pub fn load_policy_file(path: &str) -> Result<PolicyManifest> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy file: {path}"))?;
    load_policy(&contents)
}

/// Parse a policy manifest from YAML string.
pub fn load_policy(yaml: &str) -> Result<PolicyManifest> {
    let manifest: PolicyManifest =
        serde_yaml::from_str(yaml).context("parsing policy YAML")?;
    tracing::debug!(
        rules = manifest.rules.len(),
        "loaded policy manifest"
    );
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Evaluation — all rules go through the PolicyEngine
// ---------------------------------------------------------------------------

/// Evaluate a single audit event against the policy, producing a verdict.
///
/// Convenience wrapper that creates a temporary `PolicyEngine`. For evaluating
/// multiple events, create a `PolicyEngine` directly to preserve state across
/// threshold and sequence rules.
pub fn evaluate(event: &AuditEvent, policy: &PolicyManifest) -> Verdict {
    let mut engine = PolicyEngine::new(policy.clone());
    engine.evaluate(event)
}

/// Check a set of audit events against a policy, returning violations.
///
/// A violation is any event whose verdict is "deny" or "anomaly".
pub fn check_events(
    events: &[AuditEvent],
    policy: &PolicyManifest,
) -> Vec<Violation> {
    let mut engine = PolicyEngine::new(policy.clone());
    engine.check_events(events)
}

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

/// Match a hostname against a pattern supporting wildcards.
///
/// Patterns:
/// - `api.stripe.com` — exact match
/// - `*.stripe.com` — matches any single subdomain (e.g. `api.stripe.com`)
/// - `**.stripe.com` — matches any depth of subdomains (e.g. `a.b.stripe.com`)
pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("**.") {
        return host.ends_with(suffix) && host.len() > suffix.len();
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Single-level wildcard: host must be exactly <something>.<suffix>
        if let Some(prefix) = host.strip_suffix(suffix) {
            let prefix = prefix.strip_suffix('.').unwrap_or(prefix);
            return !prefix.is_empty() && !prefix.contains('.');
        }
    }
    false
}

/// Match a file path against a pattern supporting prefix and wildcard matching.
///
/// Patterns:
/// - `/etc/passwd` — exact match
/// - `/home/agent/**` — matches anything under `/home/agent/`
/// - `/tmp/*.log` — matches `*.log` files directly in `/tmp/`
/// - `/home/*/config` — matches one directory level wildcard
pub(crate) fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    // Prefix wildcard: /foo/bar/** matches anything under /foo/bar/
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix)
            && path.len() > prefix.len()
            && path.as_bytes().get(prefix.len()) == Some(&b'/');
    }
    // Simple glob: split on * segments and match
    glob_match(pattern, path)
}

/// Simple glob matching supporting `*` as a single-segment wildcard.
/// `*` matches any characters except `/`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('*').collect();
    if pat_parts.len() == 1 {
        return pattern == text;
    }

    let mut pos = 0;
    for (i, part) in pat_parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = text[pos..].find(part) {
            let match_pos = pos + found;
            // First segment must be anchored at start
            if i == 0 && match_pos != 0 {
                return false;
            }
            // Check that the wildcard didn't span a /
            if i > 0 && text[pos..match_pos].contains('/') {
                return false;
            }
            pos = match_pos + part.len();
        } else {
            return false;
        }
    }

    // Last segment must be anchored at end
    if !pat_parts.last().unwrap_or(&"").is_empty() && pos != text.len() {
        return false;
    }
    // Check trailing wildcard doesn't span /
    if pat_parts.last().map_or(false, |p| p.is_empty()) && text[pos..].contains('/') {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: &str, payload: serde_json::Value) -> AuditEvent {
        AuditEvent {
            schema_version: "1.0".into(),
            event_id: "e1".into(),
            event_type: event_type.into(),
            agent_id: "a1".into(),
            trace_id: "t1".into(),
            seq: 1,
            prev_hash: None,
            record_hash: "h1".into(),
            wall_time: "2024-01-01T00:00:00Z".into(),
            evidence_tier: "hypervisor".into(),
            payload,
            verdict: None,
        }
    }

    // -----------------------------------------------------------------------
    // Schema parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_network_egress_rule() {
        let yaml = r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.mode, None);
        assert_eq!(policy.effective_mode(), PolicyMode::Enforce);

        match &policy.rules[0] {
            PolicyRule::NetworkEgress {
                id, destinations, max_bytes_per_call, action, ..
            } => {
                assert_eq!(id, "tool:stripe");
                assert_eq!(destinations[0].host, "api.stripe.com");
                assert_eq!(destinations[0].port, 443);
                assert_eq!(*max_bytes_per_call, Some(4096));
                assert_eq!(*action, RuleAction::Allow); // default
            }
            other => panic!("expected NetworkEgress, got {:?}", other),
        }
    }

    #[test]
    fn test_load_filesystem_rule_with_paths() {
        let yaml = r#"
rules:
  - id: tool:read_file
    type: filesystem
    paths:
      - /home/agent/**
      - /tmp/*.log
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Filesystem { paths, access, .. } => {
                assert_eq!(paths.len(), 2);
                assert_eq!(*access, None);
            }
            other => panic!("expected Filesystem, got {:?}", other),
        }
    }

    #[test]
    fn test_full_manifest_evaluates() {
        let yaml = r#"
mode: enforce
rules:
  - id: tool:read_file
    type: filesystem
    description: Local file reads within agent workspace
    access: read-write
    paths:
      - /home/agent/**
      - /tmp/**
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
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 3);

        // Network allow
        let event = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443,
                "bytes_sent": 100
            }),
        );
        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "allow");

        // Filesystem allow
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/home/agent/output.txt"],
                "files_modified": [],
                "files_deleted": []
            }),
        );
        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "allow");
    }

    #[test]
    fn test_load_policy_with_mode() {
        let yaml = r#"
mode: audit
rules:
  - id: tool:stripe
    type: network_egress
    action: allow
    mode: enforce
    destinations:
      - host: api.stripe.com
        port: 443
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.mode, Some(PolicyMode::Audit));
        assert_eq!(policy.effective_mode(), PolicyMode::Audit);

        let rule = &policy.rules[0];
        assert_eq!(rule.action(), RuleAction::Allow);
        assert_eq!(rule.mode(), Some(PolicyMode::Enforce));
    }

    #[test]
    fn test_parse_match_rule() {
        let yaml = r#"
rules:
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
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 1);

        match &policy.rules[0] {
            PolicyRule::Match {
                id,
                action,
                predicates,
                bind,
                ..
            } => {
                assert_eq!(id, "deny:exfil");
                assert_eq!(*action, RuleAction::Deny);
                assert_eq!(predicates.len(), 2);
                assert_eq!(
                    predicates.get("event_type"),
                    Some(&FieldPredicate::Equals(serde_json::json!("network_egress")))
                );
                assert_eq!(
                    predicates.get("dest_host"),
                    Some(&FieldPredicate::NotIn(vec![
                        serde_json::json!("api.stripe.com"),
                        serde_json::json!("api.openai.com"),
                    ]))
                );
                assert_eq!(bind.get("host"), Some(&"dest_host".to_string()));
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_match_rule_with_glob() {
        let yaml = r#"
rules:
  - id: match:wildcard-host
    type: match
    action: deny
    match:
      dest_host:
        glob: "*.evil.com"
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Match { predicates, .. } => {
                assert_eq!(
                    predicates.get("dest_host"),
                    Some(&FieldPredicate::Glob("*.evil.com".to_string()))
                );
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_threshold_rule() {
        let yaml = r#"
rules:
  - id: rate:api-calls
    type: threshold
    action: deny
    threshold:
      metric: count
      field: event_id
      window: 5m
      limit: 100.0
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 1);

        match &policy.rules[0] {
            PolicyRule::Threshold {
                id,
                action,
                threshold,
                ..
            } => {
                assert_eq!(id, "rate:api-calls");
                assert_eq!(*action, RuleAction::Deny);
                assert_eq!(threshold.metric, ThresholdMetric::Count);
                assert_eq!(threshold.field, Some("event_id".to_string()));
                assert_eq!(threshold.window, "5m");
                assert_eq!(threshold.limit, 100.0);
            }
            other => panic!("expected Threshold, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_threshold_sum_and_rate() {
        let yaml = r#"
rules:
  - id: rate:bytes
    type: threshold
    action: deny
    threshold:
      metric: sum
      field: bytes_sent
      window: 1h
      limit: 1048576.0
  - id: rate:req-rate
    type: threshold
    action: deny
    threshold:
      metric: rate
      window: 1m
      limit: 60.0
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 2);

        match &policy.rules[0] {
            PolicyRule::Threshold { threshold, .. } => {
                assert_eq!(threshold.metric, ThresholdMetric::Sum);
                assert_eq!(threshold.field, Some("bytes_sent".to_string()));
            }
            other => panic!("expected Threshold, got {:?}", other),
        }

        match &policy.rules[1] {
            PolicyRule::Threshold { threshold, .. } => {
                assert_eq!(threshold.metric, ThresholdMetric::Rate);
                assert_eq!(threshold.field, None);
            }
            other => panic!("expected Threshold, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_sequence_rule() {
        let yaml = r#"
rules:
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
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 1);

        match &policy.rules[0] {
            PolicyRule::Sequence {
                id,
                action,
                sequence,
                ..
            } => {
                assert_eq!(id, "seq:exfil-pattern");
                assert_eq!(*action, RuleAction::Deny);
                assert_eq!(sequence.window, "10m");
                assert_eq!(sequence.steps.len(), 2);
                assert_eq!(
                    sequence.steps[0].get("event_type"),
                    Some(&FieldPredicate::Equals(serde_json::json!("filesystem_summary")))
                );
                assert_eq!(
                    sequence.steps[1].get("event_type"),
                    Some(&FieldPredicate::Equals(serde_json::json!("network_egress")))
                );
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_sequence_multi_predicate_steps() {
        let yaml = r#"
rules:
  - id: seq:targeted-exfil
    type: sequence
    action: deny
    sequence:
      window: 5m
      steps:
        - event_type:
            equals: filesystem_summary
          path:
            glob: "/home/agent/credentials*"
        - event_type:
            equals: network_egress
          dest_host:
            not_in:
              - api.stripe.com
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Sequence { sequence, .. } => {
                assert_eq!(sequence.steps[0].len(), 2);
                assert_eq!(sequence.steps[1].len(), 2);
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_filesystem_with_access_preset() {
        let yaml = r#"
rules:
  - id: fs:workspace
    type: filesystem
    access: read-only
    paths:
      - /home/agent/**
  - id: fs:tmp
    type: filesystem
    access: read-write
    paths:
      - /tmp/**
  - id: fs:system
    type: filesystem
    access: full
    paths:
      - /opt/app/**
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 3);

        match &policy.rules[0] {
            PolicyRule::Filesystem { access, .. } => {
                assert_eq!(*access, Some(AccessPreset::ReadOnly));
            }
            other => panic!("expected Filesystem, got {:?}", other),
        }
        match &policy.rules[1] {
            PolicyRule::Filesystem { access, .. } => {
                assert_eq!(*access, Some(AccessPreset::ReadWrite));
            }
            other => panic!("expected Filesystem, got {:?}", other),
        }
        match &policy.rules[2] {
            PolicyRule::Filesystem { access, .. } => {
                assert_eq!(*access, Some(AccessPreset::Full));
            }
            other => panic!("expected Filesystem, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_deny_before_allow() {
        // First-match order: deny rule comes first
        let yaml = r#"
mode: enforce
rules:
  - id: deny:evil
    type: match
    action: deny
    match:
      dest_host:
        equals: evil.com
  - id: allow:all-egress
    type: network_egress
    action: allow
    destinations:
      - host: "**.com"
        port: 443
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].action(), RuleAction::Deny);
        assert_eq!(policy.rules[1].action(), RuleAction::Allow);
    }

    #[test]
    fn test_parse_mixed_rule_types() {
        // Manifest with all five rule types
        let yaml = r#"
mode: audit
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096
  - id: fs:workspace
    type: filesystem
    access: read-write
    paths:
      - /home/agent/**
  - id: deny:exfil
    type: match
    action: deny
    match:
      dest_host:
        not_in:
          - api.stripe.com
  - id: rate:calls
    type: threshold
    action: deny
    threshold:
      metric: count
      window: 5m
      limit: 100.0
  - id: seq:read-then-send
    type: sequence
    action: deny
    sequence:
      window: 10m
      steps:
        - event_type:
            equals: filesystem_summary
        - event_type:
            equals: network_egress
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 5);
        assert!(matches!(policy.rules[0], PolicyRule::NetworkEgress { .. }));
        assert!(matches!(policy.rules[1], PolicyRule::Filesystem { .. }));
        assert!(matches!(policy.rules[2], PolicyRule::Match { .. }));
        assert!(matches!(policy.rules[3], PolicyRule::Threshold { .. }));
        assert!(matches!(policy.rules[4], PolicyRule::Sequence { .. }));
    }

    // -----------------------------------------------------------------------
    // Accessor methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule_accessors() {
        let yaml = r#"
rules:
  - id: test-rule
    type: match
    action: deny
    description: "Test match rule"
    mode: audit
    match:
      event_type:
        equals: network_egress
"#;
        let policy = load_policy(yaml).unwrap();
        let rule = &policy.rules[0];
        assert_eq!(rule.id(), "test-rule");
        assert_eq!(rule.action(), RuleAction::Deny);
        assert_eq!(rule.mode(), Some(PolicyMode::Audit));
        assert_eq!(rule.description(), Some("Test match rule"));
    }

    // -----------------------------------------------------------------------
    // Evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_rules_allows_everything() {
        let policy = PolicyManifest {
            mode: None,
            rules: vec![],
        };
        let event = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "evil.com",
                "dest_port": 443,
                "bytes_sent": 100
            }),
        );
        // No rules = no restrictions — event is allowed.
        let violations = check_events(&[event], &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_evaluate_network_allow() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096
"#,
        )
        .unwrap();

        let event = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443,
                "bytes_sent": 100
            }),
        );

        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "allow");
        assert_eq!(verdict.policy_rule, "tool:stripe");
    }

    #[test]
    fn test_evaluate_network_deny() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
"#,
        )
        .unwrap();

        let event = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "evil.com",
                "dest_port": 443
            }),
        );

        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "deny");
    }

    #[test]
    fn test_evaluate_network_anomaly_bytes() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096
"#,
        )
        .unwrap();

        let event = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443,
                "bytes_sent": 10000
            }),
        );

        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "anomaly");
        assert_eq!(verdict.policy_rule, "tool:stripe");
        assert!(verdict.reason.contains("exceeds max"));
    }

    #[test]
    fn test_evaluate_filesystem_allow() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:read_file
    type: filesystem
    paths:
      - /home/agent/**
"#,
        )
        .unwrap();

        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/home/agent/output.txt"],
                "files_modified": ["/home/agent/data/result.csv"],
                "files_deleted": []
            }),
        );

        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "allow");
    }

    #[test]
    fn test_evaluate_filesystem_deny() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:read_file
    type: filesystem
    paths:
      - /home/agent/**
"#,
        )
        .unwrap();

        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/etc/shadow"],
                "files_modified": [],
                "files_deleted": []
            }),
        );

        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "deny");
    }

    #[test]
    fn test_host_wildcard_single_level() {
        assert!(host_matches("*.stripe.com", "api.stripe.com"));
        assert!(!host_matches("*.stripe.com", "a.b.stripe.com"));
        assert!(!host_matches("*.stripe.com", "stripe.com"));
    }

    #[test]
    fn test_host_wildcard_multi_level() {
        assert!(host_matches("**.stripe.com", "api.stripe.com"));
        assert!(host_matches("**.stripe.com", "a.b.stripe.com"));
        assert!(!host_matches("**.stripe.com", "stripe.com"));
    }

    #[test]
    fn test_host_exact_match() {
        assert!(host_matches("api.stripe.com", "api.stripe.com"));
        assert!(!host_matches("api.stripe.com", "evil.com"));
    }

    #[test]
    fn test_path_prefix_match() {
        assert!(path_matches("/home/agent/**", "/home/agent/file.txt"));
        assert!(path_matches("/home/agent/**", "/home/agent/sub/deep/file.txt"));
        assert!(!path_matches("/home/agent/**", "/home/agent"));
        assert!(!path_matches("/home/agent/**", "/etc/passwd"));
    }

    #[test]
    fn test_path_glob_match() {
        assert!(path_matches("/tmp/*.log", "/tmp/app.log"));
        assert!(!path_matches("/tmp/*.log", "/tmp/sub/app.log"));
        assert!(path_matches("/home/*/config", "/home/user/config"));
        assert!(!path_matches("/home/*/config", "/home/a/b/config"));
    }

    #[test]
    fn test_path_exact_match() {
        assert!(path_matches("/etc/passwd", "/etc/passwd"));
        assert!(!path_matches("/etc/passwd", "/etc/shadow"));
    }

    #[test]
    fn test_evaluate_multiple_events() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
"#,
        )
        .unwrap();

        let allowed = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443
            }),
        );
        let denied = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "evil.com",
                "dest_port": 443
            }),
        );

        assert_eq!(evaluate(&allowed, &policy).result, "allow");
        assert_eq!(evaluate(&denied, &policy).result, "deny");
    }

    #[test]
    fn test_wildcard_host_in_policy() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:stripe_all
    type: network_egress
    destinations:
      - host: "*.stripe.com"
        port: 443
"#,
        )
        .unwrap();

        let event = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443
            }),
        );

        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "allow");
    }

    #[test]
    fn test_unknown_event_type_allows() {
        let policy = PolicyManifest {
            mode: None,
            rules: vec![],
        };
        let event = make_event("custom_metric", serde_json::json!({}));
        let verdict = evaluate(&event, &policy);
        assert_eq!(verdict.result, "allow");
    }

    #[test]
    fn test_check_events_returns_violations_for_deny_and_anomaly() {
        let policy = load_policy(
            r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 100
"#,
        )
        .unwrap();

        let denied = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "evil.com",
                "dest_port": 443
            }),
        );
        let mut anomaly = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "api.stripe.com",
                "dest_port": 443,
                "bytes_sent": 5000
            }),
        );
        anomaly.event_id = "e2".into();

        let violations = check_events(&[denied, anomaly], &policy);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].rule_id, "none"); // deny
        assert_eq!(violations[1].rule_id, "tool:stripe"); // anomaly
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_serialization_produces_valid_yaml() {
        let yaml = r#"
mode: audit
rules:
  - id: tool:stripe
    type: network_egress
    action: allow
    destinations:
      - host: api.stripe.com
        port: 443
"#;
        let policy = load_policy(yaml).unwrap();

        // Serialization should produce valid YAML (no panics)
        let serialized = serde_yaml::to_string(&policy).unwrap();
        assert!(serialized.contains("api.stripe.com"));

        // Re-parse rules without FieldPredicate nesting (serde_yaml limitation
        // with externally-tagged enums inside internally-tagged enums prevents
        // full round-trip for match/threshold/sequence rules)
        let reparsed = load_policy(&serialized).unwrap();
        assert_eq!(reparsed.mode, Some(PolicyMode::Audit));
        assert_eq!(reparsed.rules.len(), 1);
        assert!(matches!(reparsed.rules[0], PolicyRule::NetworkEgress { .. }));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_match_rule_empty_bind() {
        let yaml = r#"
rules:
  - id: m1
    type: match
    action: deny
    match:
      event_type:
        equals: network_egress
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Match { bind, .. } => {
                assert!(bind.is_empty());
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_threshold_no_field() {
        let yaml = r#"
rules:
  - id: t1
    type: threshold
    action: deny
    threshold:
      metric: count
      window: 1m
      limit: 10.0
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Threshold { threshold, .. } => {
                assert_eq!(threshold.field, None);
            }
            other => panic!("expected Threshold, got {:?}", other),
        }
    }

    #[test]
    fn test_filesystem_no_access_preset() {
        // v1-style filesystem rule without access preset
        let yaml = r#"
rules:
  - id: fs:legacy
    type: filesystem
    paths:
      - /tmp/**
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Filesystem { access, .. } => {
                assert_eq!(*access, None);
            }
            other => panic!("expected Filesystem, got {:?}", other),
        }
    }

    #[test]
    fn test_field_predicate_equals_number() {
        let yaml = r#"
rules:
  - id: m1
    type: match
    action: deny
    match:
      dest_port:
        equals: 443
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Match { predicates, .. } => {
                assert_eq!(
                    predicates.get("dest_port"),
                    Some(&FieldPredicate::Equals(serde_json::json!(443)))
                );
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_field_predicate_equals_bool() {
        let yaml = r#"
rules:
  - id: m1
    type: match
    action: allow
    match:
      is_internal:
        equals: true
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Match { predicates, .. } => {
                assert_eq!(
                    predicates.get("is_internal"),
                    Some(&FieldPredicate::Equals(serde_json::json!(true)))
                );
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_not_in_with_numbers() {
        let yaml = r#"
rules:
  - id: m1
    type: match
    action: deny
    match:
      dest_port:
        not_in:
          - 443
          - 8443
"#;
        let policy = load_policy(yaml).unwrap();
        match &policy.rules[0] {
            PolicyRule::Match { predicates, .. } => {
                assert_eq!(
                    predicates.get("dest_port"),
                    Some(&FieldPredicate::NotIn(vec![
                        serde_json::json!(443),
                        serde_json::json!(8443),
                    ]))
                );
            }
            other => panic!("expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_rules_list() {
        let yaml = r#"
rules: []
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules.len(), 0);
    }

    #[test]
    fn test_invalid_rule_type_fails() {
        let yaml = r#"
rules:
  - id: bad
    type: unknown_type
"#;
        let result = load_policy(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_description_on_all_rule_types() {
        let yaml = r#"
rules:
  - id: r1
    type: network_egress
    description: "Network rule"
    destinations: []
  - id: r2
    type: filesystem
    description: "FS rule"
    paths: []
  - id: r3
    type: match
    description: "Match rule"
    match:
      event_type:
        equals: test
  - id: r4
    type: threshold
    description: "Threshold rule"
    threshold:
      metric: count
      window: 1m
      limit: 1.0
  - id: r5
    type: sequence
    description: "Sequence rule"
    sequence:
      window: 1m
      steps: []
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules[0].description(), Some("Network rule"));
        assert_eq!(policy.rules[1].description(), Some("FS rule"));
        assert_eq!(policy.rules[2].description(), Some("Match rule"));
        assert_eq!(policy.rules[3].description(), Some("Threshold rule"));
        assert_eq!(policy.rules[4].description(), Some("Sequence rule"));
    }
}
