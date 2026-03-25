use anyhow::Result;
use sandtrace_audit_chain::AuditEvent;

/// Validation errors for audit events against the schema.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("schema_version must be \"1.0\", got \"{0}\"")]
    BadSchemaVersion(String),

    #[error("event_id must not be empty")]
    EmptyEventId,

    #[error("event_type \"{0}\" is not in schema enum [network_egress, policy_violation, filesystem_summary]")]
    InvalidEventType(String),

    #[error("agent_id must not be empty")]
    EmptyAgentId,

    #[error("trace_id must not be empty")]
    EmptyTraceId,

    #[error("seq must be >= 1, got {0}")]
    InvalidSeq(u64),

    #[error("record_hash must not be empty")]
    EmptyRecordHash,

    #[error("wall_time must not be empty")]
    EmptyWallTime,

    #[error("evidence_tier must not be empty")]
    EmptyEvidenceTier,

    #[error("payload must be a JSON object")]
    PayloadNotObject,

    #[error("verdict.result \"{0}\" is not in schema enum [allow, deny, anomaly]")]
    InvalidVerdictResult(String),
}

const VALID_EVENT_TYPES: &[&str] = &["network_egress", "policy_violation", "filesystem_summary"];
const VALID_VERDICT_RESULTS: &[&str] = &["allow", "deny", "anomaly"];

/// Validate an AuditEvent against schema/event.json constraints.
pub fn validate_event(event: &AuditEvent) -> Result<()> {
    if event.schema_version != "1.0" {
        return Err(ValidationError::BadSchemaVersion(event.schema_version.clone()).into());
    }

    if event.event_id.is_empty() {
        return Err(ValidationError::EmptyEventId.into());
    }

    if !VALID_EVENT_TYPES.contains(&event.event_type.as_str()) {
        return Err(ValidationError::InvalidEventType(event.event_type.clone()).into());
    }

    if event.agent_id.is_empty() {
        return Err(ValidationError::EmptyAgentId.into());
    }

    if event.trace_id.is_empty() {
        return Err(ValidationError::EmptyTraceId.into());
    }

    if event.seq < 1 {
        return Err(ValidationError::InvalidSeq(event.seq).into());
    }

    if event.record_hash.is_empty() {
        return Err(ValidationError::EmptyRecordHash.into());
    }

    if event.wall_time.is_empty() {
        return Err(ValidationError::EmptyWallTime.into());
    }

    if event.evidence_tier.is_empty() {
        return Err(ValidationError::EmptyEvidenceTier.into());
    }

    if !event.payload.is_object() {
        return Err(ValidationError::PayloadNotObject.into());
    }

    if let Some(ref verdict) = event.verdict {
        if !VALID_VERDICT_RESULTS.contains(&verdict.result.as_str()) {
            return Err(
                ValidationError::InvalidVerdictResult(verdict.result.clone()).into(),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtrace_audit_chain::{build_event, Verdict};

    fn valid_event() -> AuditEvent {
        build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            1,
            None,
            "hypervisor",
            serde_json::json!({"dest_host": "api.stripe.com"}),
            None,
        )
    }

    #[test]
    fn test_valid_event_passes() {
        assert!(validate_event(&valid_event()).is_ok());
    }

    #[test]
    fn test_bad_schema_version() {
        let mut e = valid_event();
        e.schema_version = "2.0".to_string();
        let err = validate_event(&e).unwrap_err();
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn test_invalid_event_type() {
        let mut e = valid_event();
        e.event_type = "unknown_type".to_string();
        // Recompute hash so we don't fail on hash
        e.record_hash = sandtrace_audit_chain::compute_record_hash(&e);
        let err = validate_event(&e).unwrap_err();
        assert!(err.to_string().contains("event_type"));
    }

    #[test]
    fn test_payload_must_be_object() {
        let mut e = valid_event();
        e.payload = serde_json::json!("not an object");
        e.record_hash = sandtrace_audit_chain::compute_record_hash(&e);
        let err = validate_event(&e).unwrap_err();
        assert!(err.to_string().contains("payload"));
    }

    #[test]
    fn test_valid_verdict() {
        let e = build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            1,
            None,
            "hypervisor",
            serde_json::json!({}),
            Some(Verdict {
                result: "deny".to_string(),
                policy_rule: "rule-1".to_string(),
                reason: "blocked".to_string(),
            }),
        );
        assert!(validate_event(&e).is_ok());
    }

    #[test]
    fn test_invalid_verdict_result() {
        let e = build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            1,
            None,
            "hypervisor",
            serde_json::json!({}),
            Some(Verdict {
                result: "maybe".to_string(),
                policy_rule: "rule-1".to_string(),
                reason: "unsure".to_string(),
            }),
        );
        let err = validate_event(&e).unwrap_err();
        assert!(err.to_string().contains("verdict.result"));
    }
}
