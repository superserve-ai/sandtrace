use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::BufRead;
use std::path::Path;

/// A single audit event in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: String,
    pub event_id: String,
    pub event_type: String,
    pub sandbox_id: String,
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

/// What kind of tampering was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TamperKind {
    /// record_hash doesn't match recomputed hash (content was modified)
    HashMismatch,
    /// prev_hash doesn't point to the previous record's hash (link broken)
    BrokenLink,
    /// seq is not monotonically increasing by 1 (insertion or deletion)
    SeqGap,
    /// seq decreased or repeated (reordering)
    SeqReorder,
    /// First event has a non-None prev_hash
    InvalidGenesis,
    /// First event seq is not 1
    InvalidGenesisSeq,
}

impl std::fmt::Display for TamperKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TamperKind::HashMismatch => write!(f, "hash_mismatch"),
            TamperKind::BrokenLink => write!(f, "broken_link"),
            TamperKind::SeqGap => write!(f, "seq_gap"),
            TamperKind::SeqReorder => write!(f, "seq_reorder"),
            TamperKind::InvalidGenesis => write!(f, "invalid_genesis"),
            TamperKind::InvalidGenesisSeq => write!(f, "invalid_genesis_seq"),
        }
    }
}

/// A single verification error found in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainError {
    pub seq: u64,
    pub event_id: String,
    pub kind: TamperKind,
    pub detail: String,
}

/// Result of verifying a chain of audit events.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub event_count: usize,
    pub errors: Vec<ChainError>,
}

impl ChainVerification {
    /// For backwards compat: return the first broken seq, if any.
    pub fn broken_at_seq(&self) -> Option<u64> {
        self.errors.first().map(|e| e.seq)
    }
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
///
/// Detects: tampering (hash mismatch), link breakage (prev_hash wrong),
/// insertion/deletion (seq gaps), and reordering (non-monotonic seq).
pub fn verify_chain(events: &[AuditEvent]) -> Result<ChainVerification> {
    if events.is_empty() {
        return Ok(ChainVerification {
            valid: true,
            event_count: 0,
            errors: vec![],
        });
    }

    let mut errors = Vec::new();
    let mut prev_hash: Option<String> = None;
    let mut prev_seq: Option<u64> = None;

    for event in events {
        // Genesis checks (first event)
        if prev_seq.is_none() {
            if event.prev_hash.is_some() {
                errors.push(ChainError {
                    seq: event.seq,
                    event_id: event.event_id.clone(),
                    kind: TamperKind::InvalidGenesis,
                    detail: "first event must have prev_hash=null".into(),
                });
            }
            if event.seq != 1 {
                errors.push(ChainError {
                    seq: event.seq,
                    event_id: event.event_id.clone(),
                    kind: TamperKind::InvalidGenesisSeq,
                    detail: format!("first event seq should be 1, got {}", event.seq),
                });
            }
        } else {
            let expected_seq = prev_seq.unwrap() + 1;

            // Check seq ordering
            if event.seq <= prev_seq.unwrap() {
                errors.push(ChainError {
                    seq: event.seq,
                    event_id: event.event_id.clone(),
                    kind: TamperKind::SeqReorder,
                    detail: format!(
                        "seq {} is not greater than previous seq {}",
                        event.seq,
                        prev_seq.unwrap()
                    ),
                });
            } else if event.seq != expected_seq {
                errors.push(ChainError {
                    seq: event.seq,
                    event_id: event.event_id.clone(),
                    kind: TamperKind::SeqGap,
                    detail: format!(
                        "expected seq {expected_seq}, got {} (events may have been inserted or deleted)",
                        event.seq
                    ),
                });
            }

            // Check prev_hash linkage
            if event.prev_hash != prev_hash {
                errors.push(ChainError {
                    seq: event.seq,
                    event_id: event.event_id.clone(),
                    kind: TamperKind::BrokenLink,
                    detail: "prev_hash does not match previous record's hash".into(),
                });
            }
        }

        // Verify the record_hash matches recomputed hash
        let computed = compute_record_hash(event);
        if computed != event.record_hash {
            errors.push(ChainError {
                seq: event.seq,
                event_id: event.event_id.clone(),
                kind: TamperKind::HashMismatch,
                detail: format!(
                    "recorded hash {} != computed hash {}",
                    event.record_hash, computed
                ),
            });
        }

        prev_hash = Some(event.record_hash.clone());
        prev_seq = Some(event.seq);
    }

    Ok(ChainVerification {
        valid: errors.is_empty(),
        event_count: events.len(),
        errors,
    })
}

/// Compute the hash for a single audit event record.
///
/// The hash covers: event_id, event_type, sandbox_id, trace_id, seq,
/// prev_hash, wall_time, evidence_tier, and the canonical JSON payload.
///
/// Each variable-length field is length-prefixed (8-byte little-endian length)
/// to prevent field boundary ambiguity (e.g., event_id="ab" + event_type="cd"
/// must not collide with event_id="abc" + event_type="d").
///
/// The payload is serialized as canonical JSON with sorted keys to ensure
/// deterministic hashing regardless of deserialization order.
pub fn compute_record_hash(event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();

    // Helper: hash a string field with length prefix
    let hash_str = |hasher: &mut Sha256, s: &str| {
        hasher.update((s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());
    };

    hash_str(&mut hasher, &event.event_id);
    hash_str(&mut hasher, &event.event_type);
    hash_str(&mut hasher, &event.sandbox_id);
    hash_str(&mut hasher, &event.trace_id);
    hasher.update(event.seq.to_le_bytes());
    hash_str(
        &mut hasher,
        event.prev_hash.as_deref().unwrap_or("null"),
    );
    hash_str(&mut hasher, &event.wall_time);
    hash_str(&mut hasher, &event.evidence_tier);

    // Canonical JSON for payload — sorted keys for determinism
    let canonical_payload = canonical_json(&event.payload);
    hash_str(&mut hasher, &canonical_payload);

    format!("{:x}", hasher.finalize())
}

/// Produce a canonical JSON string with sorted keys at all nesting levels.
///
/// This ensures that `serde_json::Value` objects serialize deterministically
/// regardless of insertion order or deserialization source.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let v = canonical_json(&map[k]);
                    format!("{}:{}", serde_json::to_string(k).unwrap(), v)
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        // Primitives (strings, numbers, bools, null) serialize deterministically
        _ => serde_json::to_string(value).unwrap(),
    }
}

/// Build a new audit event and chain it to the previous hash.
pub fn build_event(
    event_type: &str,
    sandbox_id: &str,
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
        sandbox_id: sandbox_id.to_string(),
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

/// Manages an append-only hash-chained audit log backed by a JSONL file.
pub struct AuditChain {
    path: std::path::PathBuf,
    next_seq: u64,
    prev_hash: Option<String>,
}

impl AuditChain {
    /// Open or create a new audit chain at the given path.
    ///
    /// If the file exists, reads the last event to resume the chain.
    /// If the file doesn't exist, starts a fresh chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if path.exists() {
            let events = read_jsonl(
                path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 path"))?,
            )?;
            if let Some(last) = events.last() {
                Ok(Self {
                    path,
                    next_seq: last.seq + 1,
                    prev_hash: Some(last.record_hash.clone()),
                })
            } else {
                Ok(Self {
                    path,
                    next_seq: 1,
                    prev_hash: None,
                })
            }
        } else {
            Ok(Self {
                path,
                next_seq: 1,
                prev_hash: None,
            })
        }
    }

    /// Append an event to the chain, computing hash linkage automatically.
    pub fn append(
        &mut self,
        event_type: &str,
        sandbox_id: &str,
        trace_id: &str,
        evidence_tier: &str,
        payload: serde_json::Value,
        verdict: Option<Verdict>,
    ) -> Result<AuditEvent> {
        let event = build_event(
            event_type,
            sandbox_id,
            trace_id,
            self.next_seq,
            self.prev_hash.clone(),
            evidence_tier,
            payload,
            verdict,
        );

        self.write_event(&event)?;
        self.prev_hash = Some(event.record_hash.clone());
        self.next_seq += 1;

        Ok(event)
    }

    fn write_event(&self, event: &AuditEvent) -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening audit file: {}", self.path.display()))?;
        let json = serde_json::to_string(event).context("serializing event")?;
        writeln!(file, "{json}").context("writing event")?;
        Ok(())
    }

    /// Current sequence number (next event will get this seq).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Hash of the last written event, if any.
    pub fn prev_hash(&self) -> Option<&str> {
        self.prev_hash.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_event(seq: u64, prev_hash: Option<String>) -> AuditEvent {
        build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            seq,
            prev_hash,
            "hypervisor",
            serde_json::json!({"dest_host": "api.stripe.com", "dest_port": 443}),
            None,
        )
    }

    #[test]
    fn test_build_and_verify_chain() {
        let e1 = make_event(1, None);
        let e2 = make_event(2, Some(e1.record_hash.clone()));

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(result.valid);
        assert_eq!(result.event_count, 2);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_empty_chain_is_valid() {
        let result = verify_chain(&[]).unwrap();
        assert!(result.valid);
        assert_eq!(result.event_count, 0);
    }

    #[test]
    fn test_single_event_chain() {
        let e1 = make_event(1, None);
        let result = verify_chain(&[e1]).unwrap();
        assert!(result.valid);
        assert_eq!(result.event_count, 1);
    }

    #[test]
    fn test_tamper_hash_mismatch() {
        let e1 = make_event(1, None);
        let mut e2 = make_event(2, Some(e1.record_hash.clone()));
        e2.record_hash = "tampered".to_string();

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(!result.valid);
        assert_eq!(result.broken_at_seq(), Some(2));
        assert_eq!(result.errors[0].kind, TamperKind::HashMismatch);
    }

    #[test]
    fn test_tamper_content_modification() {
        let e1 = make_event(1, None);
        let mut e2 = make_event(2, Some(e1.record_hash.clone()));
        // Modify payload without recomputing hash
        e2.payload = serde_json::json!({"dest_host": "evil.com", "dest_port": 443});

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.kind == TamperKind::HashMismatch));
    }

    #[test]
    fn test_tamper_broken_link() {
        let e1 = make_event(1, None);
        // e2 claims a different prev_hash
        let e2 = build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            2,
            Some("wrong_hash".into()),
            "hypervisor",
            serde_json::json!({}),
            None,
        );

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.kind == TamperKind::BrokenLink));
    }

    #[test]
    fn test_tamper_deletion_detected_via_seq_gap() {
        let e1 = make_event(1, None);
        let e2 = make_event(2, Some(e1.record_hash.clone()));
        let e3 = make_event(3, Some(e2.record_hash.clone()));

        // Delete e2 — chain now has seq 1, 3 with broken link
        let result = verify_chain(&[e1.clone(), e3]).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.kind == TamperKind::SeqGap || e.kind == TamperKind::BrokenLink));
    }

    #[test]
    fn test_tamper_insertion_detected() {
        let e1 = make_event(1, None);
        let e3 = make_event(3, Some(e1.record_hash.clone()));

        // Insert e1, then e3 (skipping seq 2) — seq gap detected
        let result = verify_chain(&[e1, e3]).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.kind == TamperKind::SeqGap));
    }

    #[test]
    fn test_tamper_reordering_detected() {
        let e1 = make_event(1, None);
        let e2 = make_event(2, Some(e1.record_hash.clone()));

        // Swap order: e2 first, then e1
        let result = verify_chain(&[e2, e1]).unwrap();
        assert!(!result.valid);
        // e2 at position 0 has a non-None prev_hash → InvalidGenesis
        // e1 at position 1 has seq 1 which is <= prev seq 2 → SeqReorder
        assert!(result.errors.iter().any(|e| e.kind == TamperKind::InvalidGenesis
            || e.kind == TamperKind::SeqReorder));
    }

    #[test]
    fn test_invalid_genesis_nonzero_prev_hash() {
        let e1 = build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            1,
            Some("some_hash".into()),
            "hypervisor",
            serde_json::json!({}),
            None,
        );

        let result = verify_chain(&[e1]).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.kind == TamperKind::InvalidGenesis));
    }

    #[test]
    fn test_invalid_genesis_wrong_seq() {
        let e1 = build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            5,
            None,
            "hypervisor",
            serde_json::json!({}),
            None,
        );

        let result = verify_chain(&[e1]).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.kind == TamperKind::InvalidGenesisSeq));
    }

    #[test]
    fn test_multiple_errors_reported() {
        // Chain with multiple issues
        let e1 = make_event(1, None);
        let mut e2 = build_event(
            "network_egress",
            "agent-1",
            "trace-1",
            4, // wrong seq (gap)
            Some("wrong_hash".into()), // wrong prev_hash (broken link)
            "hypervisor",
            serde_json::json!({}),
            None,
        );
        // Also tamper the hash
        e2.record_hash = "fake".into();

        let result = verify_chain(&[e1, e2]).unwrap();
        assert!(!result.valid);
        // Should report seq gap, broken link, AND hash mismatch
        assert!(result.errors.len() >= 2);
    }

    #[test]
    fn test_audit_chain_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut chain = AuditChain::open(&path).unwrap();
        assert_eq!(chain.next_seq(), 1);
        assert!(chain.prev_hash().is_none());

        let e1 = chain
            .append(
                "network_egress",
                "agent-1",
                "trace-1",
                "hypervisor",
                serde_json::json!({"dest": "api.stripe.com"}),
                None,
            )
            .unwrap();
        assert_eq!(e1.seq, 1);
        assert!(e1.prev_hash.is_none());

        let e2 = chain
            .append(
                "filesystem_summary",
                "agent-1",
                "trace-1",
                "hypervisor",
                serde_json::json!({"files": ["out.txt"]}),
                None,
            )
            .unwrap();
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_hash.as_deref(), Some(e1.record_hash.as_str()));

        // Read back and verify
        let events = read_jsonl(path.to_str().unwrap()).unwrap();
        assert_eq!(events.len(), 2);
        let result = verify_chain(&events).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_audit_chain_resume() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write two events
        let mut chain = AuditChain::open(&path).unwrap();
        chain
            .append(
                "network_egress",
                "agent-1",
                "trace-1",
                "hypervisor",
                serde_json::json!({}),
                None,
            )
            .unwrap();
        let e2 = chain
            .append(
                "network_egress",
                "agent-1",
                "trace-1",
                "hypervisor",
                serde_json::json!({}),
                None,
            )
            .unwrap();
        drop(chain);

        // Reopen and verify state
        let mut chain = AuditChain::open(&path).unwrap();
        assert_eq!(chain.next_seq(), 3);
        assert_eq!(chain.prev_hash(), Some(e2.record_hash.as_str()));

        // Append a third event
        chain
            .append(
                "network_egress",
                "agent-1",
                "trace-1",
                "hypervisor",
                serde_json::json!({}),
                None,
            )
            .unwrap();

        // Verify full chain
        let events = read_jsonl(path.to_str().unwrap()).unwrap();
        assert_eq!(events.len(), 3);
        let result = verify_chain(&events).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_read_jsonl_with_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let e1 = make_event(1, None);
        let json = serde_json::to_string(&e1).unwrap();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{json}").unwrap();
        writeln!(file).unwrap(); // blank line
        writeln!(file, "  ").unwrap(); // whitespace line

        let events = read_jsonl(path.to_str().unwrap()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_hash_determinism() {
        let event = AuditEvent {
            schema_version: "1.0".into(),
            event_id: "fixed-id".into(),
            event_type: "network_egress".into(),
            sandbox_id: "agent-1".into(),
            trace_id: "trace-1".into(),
            seq: 1,
            prev_hash: None,
            record_hash: String::new(),
            wall_time: "2024-01-01T00:00:00Z".into(),
            evidence_tier: "hypervisor".into(),
            payload: serde_json::json!({"key": "value"}),
            verdict: None,
        };

        let h1 = compute_record_hash(&event);
        let h2 = compute_record_hash(&event);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_field_boundary_no_collision() {
        // event_id="ab" + event_type="cd" must NOT collide with
        // event_id="abc" + event_type="d"
        let base = AuditEvent {
            schema_version: "1.0".into(),
            event_id: "ab".into(),
            event_type: "cd".into(),
            sandbox_id: "agent-1".into(),
            trace_id: "trace-1".into(),
            seq: 1,
            prev_hash: None,
            record_hash: String::new(),
            wall_time: "2024-01-01T00:00:00Z".into(),
            evidence_tier: "hypervisor".into(),
            payload: serde_json::json!({}),
            verdict: None,
        };

        let mut shifted = base.clone();
        shifted.event_id = "abc".into();
        shifted.event_type = "d".into();

        let h1 = compute_record_hash(&base);
        let h2 = compute_record_hash(&shifted);
        assert_ne!(h1, h2, "field boundary shift must produce different hashes");
    }

    #[test]
    fn test_canonical_json_key_order() {
        // Payloads with same keys in different insertion order must hash identically
        let event1 = AuditEvent {
            schema_version: "1.0".into(),
            event_id: "id-1".into(),
            event_type: "network_egress".into(),
            sandbox_id: "agent-1".into(),
            trace_id: "trace-1".into(),
            seq: 1,
            prev_hash: None,
            record_hash: String::new(),
            wall_time: "2024-01-01T00:00:00Z".into(),
            evidence_tier: "hypervisor".into(),
            payload: serde_json::json!({"alpha": 1, "beta": 2}),
            verdict: None,
        };

        // Build payload with reversed key order via a BTreeMap trick
        let mut map = serde_json::Map::new();
        map.insert("beta".into(), serde_json::json!(2));
        map.insert("alpha".into(), serde_json::json!(1));
        let mut event2 = event1.clone();
        event2.payload = serde_json::Value::Object(map);

        let h1 = compute_record_hash(&event1);
        let h2 = compute_record_hash(&event2);
        assert_eq!(h1, h2, "same payload with different key order must produce same hash");
    }

    #[test]
    fn test_canonical_json_nested_objects() {
        let val = serde_json::json!({"z": {"b": 1, "a": 2}, "a": [3, {"y": 4, "x": 5}]});
        let canonical = canonical_json(&val);
        // Keys must be sorted at all levels
        assert_eq!(canonical, r#"{"a":[3,{"x":5,"y":4}],"z":{"a":2,"b":1}}"#);
    }
}
