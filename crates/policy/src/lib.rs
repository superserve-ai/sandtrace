use anyhow::{Context, Result};
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

/// Check a set of audit events against a policy, returning violations.
pub fn check_events(
    events: &[sandtrace_audit_chain::AuditEvent],
    policy: &PolicyManifest,
) -> Vec<Violation> {
    let mut violations = Vec::new();

    for event in events {
        if event.event_type == "network_egress" {
            if let Some(v) = check_network_event(event, policy) {
                violations.push(v);
            }
        }
    }

    violations
}

fn check_network_event(
    event: &sandtrace_audit_chain::AuditEvent,
    policy: &PolicyManifest,
) -> Option<Violation> {
    let dest_host = event.payload.get("dest_host")?.as_str()?;
    let dest_port = event.payload.get("dest_port")?.as_u64()? as u16;
    let bytes_sent = event.payload.get("bytes_sent").and_then(serde_json::Value::as_u64);

    let matching_rule = policy.rules.iter().find(|rule| {
        rule.rule_type == "network_egress"
            && rule.destinations.iter().any(|d| d.host == dest_host && d.port == dest_port)
    });

    match matching_rule {
        None => Some(Violation {
            event_id: event.event_id.clone(),
            rule_id: "none".to_string(),
            reason: format!("no rule permits egress to {dest_host}:{dest_port}"),
        }),
        Some(rule) => {
            if let (Some(max), Some(sent)) = (rule.max_bytes_per_call, bytes_sent) {
                if sent > max {
                    return Some(Violation {
                        event_id: event.event_id.clone(),
                        rule_id: rule.id.clone(),
                        reason: format!(
                            "payload {sent}B exceeds max {max}B for {dest_host}:{dest_port}"
                        ),
                    });
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_check_violation_no_rule() {
        let policy = PolicyManifest {
            schema_version: "1.0".into(),
            rules: vec![],
        };
        let event = sandtrace_audit_chain::AuditEvent {
            schema_version: "1.0".into(),
            event_id: "e1".into(),
            event_type: "network_egress".into(),
            agent_id: "a1".into(),
            trace_id: "t1".into(),
            seq: 1,
            prev_hash: None,
            record_hash: "h1".into(),
            wall_time: "2024-01-01T00:00:00Z".into(),
            evidence_tier: "hypervisor".into(),
            payload: serde_json::json!({
                "dest_host": "evil.com",
                "dest_port": 443,
                "bytes_sent": 100
            }),
            verdict: None,
        };
        let violations = check_events(&[event], &policy);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].reason.contains("evil.com"));
    }
}
