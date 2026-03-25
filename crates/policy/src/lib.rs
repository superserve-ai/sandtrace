use anyhow::{Context, Result};
use sandtrace_audit_chain::{AuditEvent, Verdict};
use serde::{Deserialize, Serialize};

/// A policy manifest loaded from a YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub schema_version: String,
    pub rules: Vec<PolicyRule>,
}

/// A single policy rule declaring permitted behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub destinations: Vec<Destination>,
    #[serde(default)]
    pub max_bytes_per_call: Option<u64>,
    #[serde(default)]
    pub paths: Vec<String>,
}

/// A permitted network destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

/// A policy violation found when checking events against rules.
#[derive(Debug, Clone)]
pub struct Violation {
    pub event_id: String,
    pub rule_id: String,
    pub reason: String,
}

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
        version = %manifest.schema_version,
        rules = manifest.rules.len(),
        "loaded policy manifest"
    );
    Ok(manifest)
}

/// Evaluate a single audit event against the policy, producing a verdict.
pub fn evaluate(event: &AuditEvent, policy: &PolicyManifest) -> Verdict {
    match event.event_type.as_str() {
        "network_egress" => evaluate_network(event, policy),
        "filesystem_summary" => evaluate_filesystem(event, policy),
        _ => Verdict {
            result: "allow".to_string(),
            policy_rule: "none".to_string(),
            reason: format!("no policy applies to event type '{}'", event.event_type),
        },
    }
}

/// Evaluate all events against a policy, returning a verdict per event.
pub fn evaluate_all(
    events: &[AuditEvent],
    policy: &PolicyManifest,
) -> Vec<(String, Verdict)> {
    events
        .iter()
        .map(|e| (e.event_id.clone(), evaluate(e, policy)))
        .collect()
}

/// Check a set of audit events against a policy, returning violations.
///
/// A violation is any event whose verdict is "deny" or "anomaly".
pub fn check_events(
    events: &[AuditEvent],
    policy: &PolicyManifest,
) -> Vec<Violation> {
    let mut violations = Vec::new();

    for event in events {
        let verdict = evaluate(event, policy);
        match verdict.result.as_str() {
            "deny" | "anomaly" => {
                violations.push(Violation {
                    event_id: event.event_id.clone(),
                    rule_id: verdict.policy_rule,
                    reason: verdict.reason,
                });
            }
            _ => {}
        }
    }

    violations
}

/// Match a hostname against a pattern supporting wildcards.
///
/// Patterns:
/// - `api.stripe.com` — exact match
/// - `*.stripe.com` — matches any single subdomain (e.g. `api.stripe.com`)
/// - `**.stripe.com` — matches any depth of subdomains (e.g. `a.b.stripe.com`)
fn host_matches(pattern: &str, host: &str) -> bool {
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
fn path_matches(pattern: &str, path: &str) -> bool {
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

fn evaluate_network(event: &AuditEvent, policy: &PolicyManifest) -> Verdict {
    let dest_host = event
        .payload
        .get("dest_host")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let dest_port = event
        .payload
        .get("dest_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let bytes_sent = event
        .payload
        .get("bytes_sent")
        .and_then(serde_json::Value::as_u64);

    // Find a matching rule
    let matching_rule = policy.rules.iter().find(|rule| {
        rule.rule_type == "network_egress"
            && rule
                .destinations
                .iter()
                .any(|d| host_matches(&d.host, dest_host) && d.port == dest_port)
    });

    match matching_rule {
        None => Verdict {
            result: "deny".to_string(),
            policy_rule: "none".to_string(),
            reason: format!("no rule permits egress to {dest_host}:{dest_port}"),
        },
        Some(rule) => {
            if let (Some(max), Some(sent)) = (rule.max_bytes_per_call, bytes_sent) {
                if sent > max {
                    return Verdict {
                        result: "anomaly".to_string(),
                        policy_rule: rule.id.clone(),
                        reason: format!(
                            "payload {sent}B exceeds max {max}B for {dest_host}:{dest_port}"
                        ),
                    };
                }
            }
            Verdict {
                result: "allow".to_string(),
                policy_rule: rule.id.clone(),
                reason: format!("egress to {dest_host}:{dest_port} permitted by rule"),
            }
        }
    }
}

fn evaluate_filesystem(event: &AuditEvent, policy: &PolicyManifest) -> Verdict {
    let fs_rules: Vec<&PolicyRule> = policy
        .rules
        .iter()
        .filter(|r| r.rule_type == "filesystem")
        .collect();

    if fs_rules.is_empty() {
        return Verdict {
            result: "deny".to_string(),
            policy_rule: "none".to_string(),
            reason: "no filesystem rules defined".to_string(),
        };
    }

    // Collect all file paths from the event payload
    let mut all_paths: Vec<&str> = Vec::new();
    for key in &["files_created", "files_modified", "files_deleted"] {
        if let Some(arr) = event.payload.get(*key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    all_paths.push(s);
                }
            }
        }
    }

    // Also check "path" field for single-file events
    if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
        all_paths.push(path);
    }

    if all_paths.is_empty() {
        return Verdict {
            result: "allow".to_string(),
            policy_rule: "none".to_string(),
            reason: "no file paths in event".to_string(),
        };
    }

    // Check each path against filesystem rules
    let mut unauthorized: Vec<String> = Vec::new();
    for path in &all_paths {
        let permitted = fs_rules.iter().any(|rule| {
            rule.paths.iter().any(|pattern| path_matches(pattern, path))
        });
        if !permitted {
            unauthorized.push(path.to_string());
        }
    }

    if unauthorized.is_empty() {
        let rule_ids: Vec<&str> = fs_rules.iter().map(|r| r.id.as_str()).collect();
        Verdict {
            result: "allow".to_string(),
            policy_rule: rule_ids.join(","),
            reason: "all file access permitted by policy".to_string(),
        }
    } else {
        Verdict {
            result: "deny".to_string(),
            policy_rule: "none".to_string(),
            reason: format!(
                "unauthorized file access: {}",
                unauthorized.join(", ")
            ),
        }
    }
}

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

    #[test]
    fn test_load_policy() {
        let yaml = r#"
schema_version: "1.0"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 4096
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.schema_version, "1.0");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].destinations[0].host, "api.stripe.com");
    }

    #[test]
    fn test_load_policy_with_paths() {
        let yaml = r#"
schema_version: "1.0"
rules:
  - id: tool:read_file
    type: filesystem
    paths:
      - /home/agent/**
      - /tmp/*.log
"#;
        let policy = load_policy(yaml).unwrap();
        assert_eq!(policy.rules[0].paths.len(), 2);
    }

    #[test]
    fn test_check_violation_no_rule() {
        let policy = PolicyManifest {
            schema_version: "1.0".into(),
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
        let violations = check_events(&[event], &policy);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].reason.contains("evil.com"));
    }

    #[test]
    fn test_evaluate_network_allow() {
        let policy = load_policy(
            r#"
schema_version: "1.0"
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
schema_version: "1.0"
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
        assert!(verdict.reason.contains("evil.com"));
    }

    #[test]
    fn test_evaluate_network_anomaly_bytes() {
        let policy = load_policy(
            r#"
schema_version: "1.0"
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
schema_version: "1.0"
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
schema_version: "1.0"
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
        assert!(verdict.reason.contains("/etc/shadow"));
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
    fn test_evaluate_all() {
        let policy = load_policy(
            r#"
schema_version: "1.0"
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
        let mut denied = make_event(
            "network_egress",
            serde_json::json!({
                "dest_host": "evil.com",
                "dest_port": 443
            }),
        );
        denied.event_id = "e2".into();

        let results = evaluate_all(&[allowed, denied], &policy);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1.result, "allow");
        assert_eq!(results[1].1.result, "deny");
    }

    #[test]
    fn test_wildcard_host_in_policy() {
        let policy = load_policy(
            r#"
schema_version: "1.0"
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
            schema_version: "1.0".into(),
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
schema_version: "1.0"
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
}
