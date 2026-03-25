use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::BufRead;

/// A single audit event in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: String,
    pub event_id: String,
    pub event_type: String,
    pub agent_id: String,
    pub trace_id: String,
    pub seq: u64,
    pub prev_hash: Option<String>,
    pub record_hash: String,
    pub wall_time: String,
    pub evidence_tier: String,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
}

/// Policy verdict attached to an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub result: String,
    pub policy_rule: String,
    pub reason: String,
}

/// Result of verifying a chain of audit events.
#[derive(Debug)]
pub struct ChainVerification {
    pub valid: bool,
    pub event_count: usize,
    pub broken_at_seq: Option<u64>,
}

/// Read audit events from a JSONL file.
pub fn read_jsonl(path: &str) -> Result<Vec<AuditEvent>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening audit trail: {path}"))?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for (i, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading line {}", i + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_str(trimmed)
            .with_context(|| format!("parsing event at line {}", i + 1))?;
        events.push(event);
    }

    Ok(events)
}

/// Verify the hash-chain integrity of a sequence of audit events.
pub fn verify_chain(events: &[AuditEvent]) -> Result<ChainVerification> {
    if events.is_empty() {
        return Ok(ChainVerification {
            valid: true,
            event_count: 0,
            broken_at_seq: None,
        });
    }

    let mut prev_hash: Option<String> = None;

    for event in events {
        // Verify prev_hash links to the previous record
        if event.prev_hash != prev_hash {
            return Ok(ChainVerification {
                valid: false,
                event_count: events.len(),
                broken_at_seq: Some(event.seq),
            });
        }

        // Verify the record_hash matches the computed hash
        let computed = compute_record_hash(event);
        if computed != event.record_hash {
            return Ok(ChainVerification {
                valid: false,
                event_count: events.len(),
                broken_at_seq: Some(event.seq),
            });
        }

        prev_hash = Some(event.record_hash.clone());
    }

    Ok(ChainVerification {
        valid: true,
        event_count: events.len(),
        broken_at_seq: None,
    })
}

/// Compute the hash for a single audit event record.
///
/// The hash covers: event_id, event_type, agent_id, trace_id, seq,
/// prev_hash, wall_time, evidence_tier, and the canonical JSON payload.
pub fn compute_record_hash(event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.event_id.as_bytes());
    hasher.update(event.event_type.as_bytes());
    hasher.update(event.agent_id.as_bytes());
    hasher.update(event.trace_id.as_bytes());
    hasher.update(event.seq.to_le_bytes());
    hasher.update(event.prev_hash.as_deref().unwrap_or("null").as_bytes());
    hasher.update(event.wall_time.as_bytes());
    hasher.update(event.evidence_tier.as_bytes());

    // Canonical JSON for payload
    let payload_str = serde_json::to_string(&event.payload).unwrap_or_default();
    hasher.update(payload_str.as_bytes());

    format!("{:x}", hasher.finalize())
}

/// Build a new audit event and chain it to the previous hash.
pub fn build_event(
    event_type: &str,
    agent_id: &str,
    trace_id: &str,
    seq: u64,
    prev_hash: Option<String>,
    evidence_tier: &str,
    payload: serde_json::Value,
    verdict: Option<Verdict>,
) -> AuditEvent {
    let event_id = uuid::Uuid::new_v4().to_string();
    let wall_time = chrono::Utc::now().to_rfc3339();

    let mut event = AuditEvent {
        schema_version: "1.0".to_string(),
        event_id,
        event_type: event_type.to_string(),
        agent_id: agent_id.to_string(),
        trace_id: trace_id.to_string(),
        seq,
        prev_hash,
        record_hash: String::new(),
        wall_time,
        evidence_tier: evidence_tier.to_string(),
        payload,
        verdict,
    };

    event.record_hash = compute_record_hash(&event);
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_verify_chain() {
        let e1 = build_event(
            "network_egress", "agent-1", "trace-1",
            1, None, "hypervisor",
            serde_json::json!({"dest_host": "api.stripe.com", "dest_port": 443}),
            None,
        );
        let e2 = build_event(
            "filesystem_summary", "agent-1", "trace-1",
            2, Some(e1.record_hash.clone()), "hypervisor",
            serde_json::json!({"files_created": ["output.txt"]}),
            None,
        );

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(result.valid);
        assert_eq!(result.event_count, 2);
    }

    #[test]
    fn test_broken_chain() {
        let e1 = build_event(
            "network_egress", "agent-1", "trace-1",
            1, None, "hypervisor",
            serde_json::json!({}),
            None,
        );
        let mut e2 = build_event(
            "network_egress", "agent-1", "trace-1",
            2, Some(e1.record_hash.clone()), "hypervisor",
            serde_json::json!({}),
            None,
        );
        // Tamper with the hash
        e2.record_hash = "tampered".to_string();

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(!result.valid);
        assert_eq!(result.broken_at_seq, Some(2));
    }
}
