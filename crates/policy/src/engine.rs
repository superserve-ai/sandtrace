//! Stateful evaluation engine for all policy rule types.
//!
//! The engine maintains per-rule state (event buffers for threshold rules,
//! partial-match trackers for sequence rules) and evaluates events in
//! first-match rule order.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use sandtrace_audit_chain::{AuditEvent, Verdict};

use crate::{
    FieldPredicate, PolicyManifest, PolicyRule, RuleAction, ThresholdMetric,
};

// ---------------------------------------------------------------------------
// Time window parsing
// ---------------------------------------------------------------------------

/// Parse a duration string like "5m", "1h", "30s", "2h30m" into seconds.
fn parse_window_secs(window: &str) -> f64 {
    let mut total: f64 = 0.0;
    let mut num_buf = String::new();
    for ch in window.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            num_buf.push(ch);
        } else {
            let n: f64 = num_buf.parse().unwrap_or(0.0);
            num_buf.clear();
            match ch {
                's' => total += n,
                'm' => total += n * 60.0,
                'h' => total += n * 3600.0,
                'd' => total += n * 86400.0,
                _ => {}
            }
        }
    }
    total
}

fn parse_wall_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
}

// ---------------------------------------------------------------------------
// Field extraction helpers
// ---------------------------------------------------------------------------

/// Extract a field value from an AuditEvent. Checks top-level fields first,
/// then falls back to payload fields.
fn extract_field<'a>(event: &'a AuditEvent, field: &str) -> Option<serde_json::Value> {
    match field {
        "event_type" => Some(serde_json::Value::String(event.event_type.clone())),
        "agent_id" => Some(serde_json::Value::String(event.agent_id.clone())),
        "trace_id" => Some(serde_json::Value::String(event.trace_id.clone())),
        "event_id" => Some(serde_json::Value::String(event.event_id.clone())),
        "evidence_tier" => Some(serde_json::Value::String(event.evidence_tier.clone())),
        "seq" => Some(serde_json::json!(event.seq)),
        "wall_time" => Some(serde_json::Value::String(event.wall_time.clone())),
        _ => event.payload.get(field).cloned(),
    }
}

// ---------------------------------------------------------------------------
// Predicate evaluation
// ---------------------------------------------------------------------------

/// Check whether a single field predicate matches a value.
fn predicate_matches(predicate: &FieldPredicate, value: &serde_json::Value) -> bool {
    match predicate {
        FieldPredicate::Equals(expected) => values_equal(value, expected),
        FieldPredicate::Glob(pattern) => {
            if let Some(s) = value.as_str() {
                glob_match(pattern, s)
            } else {
                false
            }
        }
        FieldPredicate::NotIn(excluded) => !excluded.iter().any(|ex| values_equal(value, ex)),
    }
}

/// Compare two JSON values with type coercion for numbers.
fn values_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    if a == b {
        return true;
    }
    // Coerce: compare numbers as f64
    match (a.as_f64(), b.as_f64()) {
        (Some(fa), Some(fb)) => (fa - fb).abs() < f64::EPSILON,
        _ => {
            // Coerce: string-to-number comparison
            match (a.as_str(), b.as_f64()) {
                (Some(s), Some(n)) => s.parse::<f64>().map_or(false, |sn| (sn - n).abs() < f64::EPSILON),
                _ => match (a.as_f64(), b.as_str()) {
                    (Some(n), Some(s)) => s.parse::<f64>().map_or(false, |sn| (sn - n).abs() < f64::EPSILON),
                    _ => false,
                },
            }
        }
    }
}

/// Simple glob matching: `*` matches any characters except `/`.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Handle ** as "match everything"
    if pattern == "**" {
        return true;
    }
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
            if i == 0 && match_pos != 0 {
                return false;
            }
            pos = match_pos + part.len();
        } else {
            return false;
        }
    }

    if !pat_parts.last().unwrap_or(&"").is_empty() && pos != text.len() {
        return false;
    }

    true
}

/// Check whether all predicates in a map match the event.
fn all_predicates_match(
    predicates: &BTreeMap<String, FieldPredicate>,
    event: &AuditEvent,
) -> bool {
    for (field, predicate) in predicates {
        match extract_field(event, field) {
            Some(value) => {
                if !predicate_matches(predicate, &value) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Threshold state
// ---------------------------------------------------------------------------

/// A timestamped value in the threshold ring buffer.
#[derive(Debug, Clone)]
struct ThresholdEntry {
    timestamp: DateTime<Utc>,
    value: f64,
}

/// Per-rule threshold state: a ring buffer of recent events.
#[derive(Debug, Clone)]
struct ThresholdState {
    entries: VecDeque<ThresholdEntry>,
    window_secs: f64,
}

impl ThresholdState {
    fn new(window_secs: f64) -> Self {
        Self {
            entries: VecDeque::new(),
            window_secs,
        }
    }

    /// Expire entries outside the time window relative to `now`.
    fn expire(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::milliseconds((self.window_secs * 1000.0) as i64);
        while let Some(front) = self.entries.front() {
            if front.timestamp < cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    /// Push a new entry and expire old ones.
    fn push(&mut self, now: DateTime<Utc>, value: f64) {
        self.expire(now);
        self.entries.push_back(ThresholdEntry {
            timestamp: now,
            value,
        });
    }

    /// Compute the current aggregate value.
    fn aggregate(&self, metric: ThresholdMetric) -> f64 {
        match metric {
            ThresholdMetric::Count => self.entries.len() as f64,
            ThresholdMetric::Sum => self.entries.iter().map(|e| e.value).sum(),
            ThresholdMetric::Rate => {
                if self.window_secs > 0.0 {
                    self.entries.len() as f64 / self.window_secs
                } else {
                    0.0
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sequence state
// ---------------------------------------------------------------------------

/// Per-rule sequence tracker: which step we've matched up to and when the
/// first step was matched.
#[derive(Debug, Clone)]
struct SequenceTracker {
    /// Index of the next step to match (0 = haven't matched anything yet).
    next_step: usize,
    /// Timestamp when the first step matched (for window enforcement).
    first_match_time: Option<DateTime<Utc>>,
    /// Total number of steps in the sequence.
    total_steps: usize,
    /// Window in seconds.
    window_secs: f64,
}

impl SequenceTracker {
    fn new(total_steps: usize, window_secs: f64) -> Self {
        Self {
            next_step: 0,
            first_match_time: None,
            total_steps,
            window_secs,
        }
    }

    /// Try to advance the sequence with the given event. Returns `true` if the
    /// full sequence has been completed.
    fn advance(
        &mut self,
        event: &AuditEvent,
        steps: &[BTreeMap<String, FieldPredicate>],
        now: DateTime<Utc>,
    ) -> bool {
        // Check if window has expired — reset if so
        if let Some(first) = self.first_match_time {
            let elapsed = (now - first).num_milliseconds() as f64 / 1000.0;
            if elapsed > self.window_secs {
                self.reset();
            }
        }

        if self.next_step >= self.total_steps {
            return false;
        }

        let step = &steps[self.next_step];
        if all_predicates_match(step, event) {
            if self.next_step == 0 {
                self.first_match_time = Some(now);
            }
            self.next_step += 1;
            if self.next_step >= self.total_steps {
                // Full sequence matched — reset for next detection
                self.reset();
                return true;
            }
        }

        false
    }

    fn reset(&mut self) {
        self.next_step = 0;
        self.first_match_time = None;
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

/// Stateful policy evaluation engine.
///
/// Maintains per-rule state for threshold and sequence rules and evaluates
/// events in first-match rule order. This is the primary entry point for
/// v2 policy evaluation in the sandtrace hot path.
pub struct PolicyEngine {
    policy: PolicyManifest,
    threshold_states: Vec<(usize, ThresholdState)>,
    sequence_trackers: Vec<(usize, SequenceTracker)>,
}

impl PolicyEngine {
    /// Create a new engine from a policy manifest.
    pub fn new(policy: PolicyManifest) -> Self {
        let mut threshold_states = Vec::new();
        let mut sequence_trackers = Vec::new();

        for (i, rule) in policy.rules.iter().enumerate() {
            match rule {
                PolicyRule::Threshold { threshold, .. } => {
                    let window_secs = parse_window_secs(&threshold.window);
                    threshold_states.push((i, ThresholdState::new(window_secs)));
                }
                PolicyRule::Sequence { sequence, .. } => {
                    let window_secs = parse_window_secs(&sequence.window);
                    let total = sequence.steps.len();
                    sequence_trackers.push((i, SequenceTracker::new(total, window_secs)));
                }
                _ => {}
            }
        }

        Self {
            policy,
            threshold_states,
            sequence_trackers,
        }
    }

    /// Access the underlying policy manifest.
    pub fn policy(&self) -> &PolicyManifest {
        &self.policy
    }

    /// Evaluate all events in order, returning violations (deny/anomaly verdicts).
    ///
    /// This is the v2 equivalent of `check_events` — it processes events
    /// sequentially so that stateful rules (threshold, sequence) accumulate
    /// state across the batch.
    pub fn check_events(&mut self, events: &[AuditEvent]) -> Vec<crate::Violation> {
        let mut violations = Vec::new();
        for event in events {
            let verdict = self.evaluate(event);
            match verdict.result.as_str() {
                "deny" | "anomaly" => {
                    violations.push(crate::Violation {
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

    /// Evaluate a single event against the policy, returning a verdict.
    ///
    /// Uses first-match rule ordering: rules are checked in manifest order and
    /// the first matching rule determines the verdict. Stateful rules (threshold
    /// and sequence) update their internal state on every call.
    pub fn evaluate(&mut self, event: &AuditEvent) -> Verdict {
        let now = parse_wall_time(&event.wall_time).unwrap_or_else(Utc::now);

        // Collect rule evaluation results. We iterate by index to avoid
        // borrowing self.policy while also needing &mut self for stateful rules.
        let num_rules = self.policy.rules.len();
        for rule_idx in 0..num_rules {
            let raw_verdict = {
                let rule = &self.policy.rules[rule_idx];
                match rule {
                    PolicyRule::NetworkEgress { .. } => {
                        if event.event_type == "network_egress" {
                            evaluate_network_rule(event, rule)
                        } else {
                            None
                        }
                    }
                    PolicyRule::Filesystem { .. } => {
                        if event.event_type == "filesystem_summary" {
                            evaluate_filesystem_rule(event, rule)
                        } else {
                            None
                        }
                    }
                    PolicyRule::Match { .. } => evaluate_match_rule(event, rule),
                    PolicyRule::Threshold { .. } | PolicyRule::Sequence { .. } => {
                        // Handled below with mutable access
                        None
                    }
                }
            };

            if let Some(verdict) = raw_verdict {
                return verdict;
            }

            // Handle stateful rules separately to satisfy borrow checker
            let rule = &self.policy.rules[rule_idx];
            let stateful_verdict = match rule {
                PolicyRule::Threshold {
                    id,
                    action,
                    threshold,
                    ..
                } => {
                    let value = match threshold.metric {
                        ThresholdMetric::Count => 1.0,
                        ThresholdMetric::Sum | ThresholdMetric::Rate => {
                            if let Some(ref field) = threshold.field {
                                extract_field(event, field)
                                    .and_then(|v| v.as_f64())
                                    .unwrap_or(0.0)
                            } else {
                                1.0
                            }
                        }
                    };
                    let metric = threshold.metric;
                    let limit = threshold.limit;
                    let id = id.clone();
                    let action = *action;

                    if let Some((_, state)) = self
                        .threshold_states
                        .iter_mut()
                        .find(|(idx, _)| *idx == rule_idx)
                    {
                        state.push(now, value);
                        let aggregate = state.aggregate(metric);
                        if aggregate > limit {
                            Some(Verdict {
                                result: action_to_result(action),
                                policy_rule: id,
                                reason: format!(
                                    "{metric:?} {aggregate:.1} exceeds limit {limit:.1}"
                                ),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                PolicyRule::Sequence {
                    id,
                    action,
                    sequence,
                    ..
                } => {
                    let steps = sequence.steps.clone();
                    let num_steps = steps.len();
                    let id = id.clone();
                    let action = *action;

                    if let Some((_, tracker)) = self
                        .sequence_trackers
                        .iter_mut()
                        .find(|(idx, _)| *idx == rule_idx)
                    {
                        if tracker.advance(event, &steps, now) {
                            Some(Verdict {
                                result: action_to_result(action),
                                policy_rule: id,
                                reason: format!(
                                    "sequence of {num_steps} steps completed within window"
                                ),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(verdict) = stateful_verdict {
                return verdict;
            }
        }

        // No rule matched — default verdict
        default_verdict(event, &self.policy)
    }

}

// ---------------------------------------------------------------------------
// Stateless rule evaluators (free functions)
// ---------------------------------------------------------------------------

fn evaluate_network_rule(event: &AuditEvent, rule: &PolicyRule) -> Option<Verdict> {
        if let PolicyRule::NetworkEgress {
            id,
            destinations,
            max_bytes_per_call,
            action,
            ..
        } = rule
        {
            let dest_host = event.payload.get("dest_host").and_then(|v| v.as_str()).unwrap_or("");
            let dest_port = event.payload.get("dest_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let bytes_sent = event.payload.get("bytes_sent").and_then(serde_json::Value::as_u64);

            let matches = destinations.iter().any(|d| {
                crate::host_matches(&d.host, dest_host) && d.port == dest_port
            });

            if matches {
                if let (Some(max), Some(sent)) = (max_bytes_per_call, bytes_sent) {
                    if sent > *max {
                        return Some(Verdict {
                            result: "anomaly".to_string(),
                            policy_rule: id.clone(),
                            reason: format!(
                                "payload {sent}B exceeds max {max}B for {dest_host}:{dest_port}"
                            ),
                        });
                    }
                }
                return Some(Verdict {
                    result: action_to_result(*action),
                    policy_rule: id.clone(),
                    reason: format!("egress to {dest_host}:{dest_port} matched rule"),
                });
            }
        }
        None
    }

fn evaluate_filesystem_rule(event: &AuditEvent, rule: &PolicyRule) -> Option<Verdict> {
        if let PolicyRule::Filesystem {
            id, paths, action, access, ..
        } = rule
        {
            // Collect paths from each operation category.
            let mut created: Vec<&str> = Vec::new();
            let mut modified: Vec<&str> = Vec::new();
            let mut deleted: Vec<&str> = Vec::new();

            if let Some(arr) = event.payload.get("files_created").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        created.push(s);
                    }
                }
            }
            if let Some(arr) = event.payload.get("files_modified").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        modified.push(s);
                    }
                }
            }
            if let Some(arr) = event.payload.get("files_deleted").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        deleted.push(s);
                    }
                }
            }

            // Also check "path" field for single-file events (treated as read/modify).
            let single_path = event.payload.get("path").and_then(|v| v.as_str());

            // Enforce access preset: deny operations not permitted by the preset.
            if let Some(preset) = access {
                match preset {
                    crate::AccessPreset::ReadOnly => {
                        // Read-only: deny any write or delete operations.
                        if !created.is_empty() || !modified.is_empty() || !deleted.is_empty() {
                            return Some(Verdict {
                                result: "deny".to_string(),
                                policy_rule: id.clone(),
                                reason: format!(
                                    "access preset read-only denies write/delete operations"
                                ),
                            });
                        }
                    }
                    crate::AccessPreset::ReadWrite => {
                        // Read-write: deny delete operations.
                        if !deleted.is_empty() {
                            return Some(Verdict {
                                result: "deny".to_string(),
                                policy_rule: id.clone(),
                                reason: format!(
                                    "access preset read-write denies delete operations"
                                ),
                            });
                        }
                    }
                    crate::AccessPreset::Full => {
                        // Full: all operations permitted, no restriction.
                    }
                }
            }

            // Gather all paths for allowlist checking.
            let mut all_paths: Vec<&str> = Vec::new();
            all_paths.extend(&created);
            all_paths.extend(&modified);
            all_paths.extend(&deleted);
            if let Some(p) = single_path {
                all_paths.push(p);
            }

            if all_paths.is_empty() {
                // No file paths to check — allow (consistent with v1 behavior).
                return Some(Verdict {
                    result: action_to_result(*action),
                    policy_rule: id.clone(),
                    reason: "no file paths in event".to_string(),
                });
            }

            let all_covered = all_paths.iter().all(|p| {
                paths.iter().any(|pattern| crate::path_matches(pattern, p))
            });

            if all_covered {
                return Some(Verdict {
                    result: action_to_result(*action),
                    policy_rule: id.clone(),
                    reason: "all file access matched rule".to_string(),
                });
            }
        }
        None
    }

fn evaluate_match_rule(event: &AuditEvent, rule: &PolicyRule) -> Option<Verdict> {
        if let PolicyRule::Match {
            id,
            action,
            predicates,
            bind,
            ..
        } = rule
        {
            if all_predicates_match(predicates, event) {
                let bindings: Vec<String> = bind
                    .iter()
                    .filter_map(|(name, field_path)| {
                        extract_field(event, field_path)
                            .map(|v| format!("{name}={}", value_to_string(&v)))
                    })
                    .collect();

                let reason = if bindings.is_empty() {
                    format!("event matched rule '{id}'")
                } else {
                    format!("event matched rule '{id}' [{}]", bindings.join(", "))
                };

                return Some(Verdict {
                    result: action_to_result(*action),
                    policy_rule: id.clone(),
                    reason,
                });
            }
        }
        None
    }

fn default_verdict(
    event: &AuditEvent,
    policy: &PolicyManifest,
) -> Verdict {
    // Only deny by default if there are allowlist-style rules (NetworkEgress /
    // Filesystem) defined for this event type. These rule types act as
    // allowlists: if no rule matched, the event should be denied.
    // Match/threshold/sequence rules are explicit-action rules that don't
    // imply a deny-by-default fallback.
    let has_allowlist_rules = match event.event_type.as_str() {
        "network_egress" => policy
            .rules
            .iter()
            .any(|r| matches!(r, PolicyRule::NetworkEgress { .. })),
        "filesystem_summary" => policy
            .rules
            .iter()
            .any(|r| matches!(r, PolicyRule::Filesystem { .. })),
        _ => false,
    };

    let result = if has_allowlist_rules { "deny" } else { "allow" };

    let reason = if has_allowlist_rules {
        format!("no rule permits event type '{}'", event.event_type)
    } else {
        format!("no rule matched event type '{}'", event.event_type)
    };

    Verdict {
        result: result.to_string(),
        policy_rule: "none".to_string(),
        reason,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn action_to_result(action: RuleAction) -> String {
    match action {
        RuleAction::Allow => "allow".to_string(),
        RuleAction::Deny => "deny".to_string(),
    }
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
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

    fn make_timed_event(event_type: &str, payload: serde_json::Value, time: &str) -> AuditEvent {
        let mut e = make_event(event_type, payload);
        e.wall_time = time.to_string();
        e
    }

    // -------------------------------------------------------------------
    // Window parsing
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_window() {
        assert_eq!(parse_window_secs("30s"), 30.0);
        assert_eq!(parse_window_secs("5m"), 300.0);
        assert_eq!(parse_window_secs("1h"), 3600.0);
        assert_eq!(parse_window_secs("2h30m"), 9000.0);
        assert_eq!(parse_window_secs("1d"), 86400.0);
    }

    // -------------------------------------------------------------------
    // Field extraction
    // -------------------------------------------------------------------

    #[test]
    fn test_extract_top_level_field() {
        let event = make_event("network_egress", serde_json::json!({}));
        assert_eq!(
            extract_field(&event, "event_type"),
            Some(serde_json::json!("network_egress"))
        );
    }

    #[test]
    fn test_extract_payload_field() {
        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com"}),
        );
        assert_eq!(
            extract_field(&event, "dest_host"),
            Some(serde_json::json!("evil.com"))
        );
    }

    // -------------------------------------------------------------------
    // Predicate matching
    // -------------------------------------------------------------------

    #[test]
    fn test_predicate_equals_string() {
        let p = FieldPredicate::Equals(serde_json::json!("hello"));
        assert!(predicate_matches(&p, &serde_json::json!("hello")));
        assert!(!predicate_matches(&p, &serde_json::json!("world")));
    }

    #[test]
    fn test_predicate_equals_number() {
        let p = FieldPredicate::Equals(serde_json::json!(443));
        assert!(predicate_matches(&p, &serde_json::json!(443)));
        assert!(!predicate_matches(&p, &serde_json::json!(80)));
    }

    #[test]
    fn test_predicate_glob() {
        let p = FieldPredicate::Glob("*.evil.com".to_string());
        assert!(predicate_matches(&p, &serde_json::json!("www.evil.com")));
        assert!(!predicate_matches(&p, &serde_json::json!("good.com")));
    }

    #[test]
    fn test_predicate_not_in() {
        let p = FieldPredicate::NotIn(vec![
            serde_json::json!("api.stripe.com"),
            serde_json::json!("api.openai.com"),
        ]);
        assert!(predicate_matches(&p, &serde_json::json!("evil.com")));
        assert!(!predicate_matches(
            &p,
            &serde_json::json!("api.stripe.com")
        ));
    }

    // -------------------------------------------------------------------
    // Match evaluator
    // -------------------------------------------------------------------

    #[test]
    fn test_match_rule_deny() {
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
    bind:
      host: dest_host
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com", "dest_port": 443}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert_eq!(verdict.policy_rule, "deny:exfil");
        assert!(verdict.reason.contains("host=evil.com"));
    }

    #[test]
    fn test_match_rule_no_match() {
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
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "api.stripe.com", "dest_port": 443}),
        );
        let verdict = engine.evaluate(&event);
        // No match rule fired and no NetworkEgress allowlist rules exist -> allow
        assert_eq!(verdict.result, "allow");
        assert_eq!(verdict.policy_rule, "none");
    }

    #[test]
    fn test_match_rule_glob_predicate() {
        let yaml = r#"
rules:
  - id: deny:wildcard
    type: match
    action: deny
    match:
      dest_host:
        glob: "*.evil.com"
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "www.evil.com"}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert_eq!(verdict.policy_rule, "deny:wildcard");
    }

    #[test]
    fn test_match_first_match_order() {
        let yaml = r#"
rules:
  - id: deny:evil
    type: match
    action: deny
    match:
      dest_host:
        equals: evil.com
  - id: allow:all
    type: match
    action: allow
    match:
      event_type:
        equals: network_egress
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // evil.com should hit the deny rule first
        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com"}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert_eq!(verdict.policy_rule, "deny:evil");

        // good.com should hit the allow rule
        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "good.com"}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
        assert_eq!(verdict.policy_rule, "allow:all");
    }

    // -------------------------------------------------------------------
    // Threshold evaluator
    // -------------------------------------------------------------------

    #[test]
    fn test_threshold_count() {
        let yaml = r#"
rules:
  - id: rate:calls
    type: threshold
    action: deny
    threshold:
      metric: count
      window: 5m
      limit: 3.0
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // First 3 events should be fine (count 1, 2, 3 — exceeds at 4)
        for i in 0..3 {
            let event = make_timed_event(
                "network_egress",
                serde_json::json!({"dest_host": "api.com"}),
                &format!("2024-01-01T00:0{}:00Z", i),
            );
            let verdict = engine.evaluate(&event);
            assert_eq!(verdict.result, "allow", "event {i} should be allowed");
        }

        // 4th event exceeds the limit
        let event = make_timed_event(
            "network_egress",
            serde_json::json!({"dest_host": "api.com"}),
            "2024-01-01T00:03:00Z",
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert_eq!(verdict.policy_rule, "rate:calls");
        assert!(verdict.reason.contains("Count"));
    }

    #[test]
    fn test_threshold_sum() {
        let yaml = r#"
rules:
  - id: rate:bytes
    type: threshold
    action: deny
    threshold:
      metric: sum
      field: bytes_sent
      window: 1h
      limit: 1000.0
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_timed_event(
            "network_egress",
            serde_json::json!({"bytes_sent": 500}),
            "2024-01-01T00:00:00Z",
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");

        let event = make_timed_event(
            "network_egress",
            serde_json::json!({"bytes_sent": 600}),
            "2024-01-01T00:01:00Z",
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert!(verdict.reason.contains("Sum"));
    }

    #[test]
    fn test_threshold_window_expiry() {
        let yaml = r#"
rules:
  - id: rate:calls
    type: threshold
    action: deny
    threshold:
      metric: count
      window: 1m
      limit: 2.0
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Two events within the window
        let e1 = make_timed_event("test", serde_json::json!({}), "2024-01-01T00:00:00Z");
        let e2 = make_timed_event("test", serde_json::json!({}), "2024-01-01T00:00:30Z");
        engine.evaluate(&e1);
        let v = engine.evaluate(&e2);
        assert_eq!(v.result, "allow");

        // Third event within window -> exceeds
        let e3 = make_timed_event("test", serde_json::json!({}), "2024-01-01T00:00:45Z");
        let v = engine.evaluate(&e3);
        assert_eq!(v.result, "deny");

        // Event after window expires (>1m from first event) — old entries purged
        let e4 = make_timed_event("test", serde_json::json!({}), "2024-01-01T00:02:00Z");
        let v = engine.evaluate(&e4);
        assert_eq!(v.result, "allow");
    }

    // -------------------------------------------------------------------
    // Sequence evaluator
    // -------------------------------------------------------------------

    #[test]
    fn test_sequence_fires() {
        let yaml = r#"
rules:
  - id: seq:exfil
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
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Step 1: filesystem event
        let e1 = make_timed_event(
            "filesystem_summary",
            serde_json::json!({"files_created": ["/tmp/data"]}),
            "2024-01-01T00:00:00Z",
        );
        let v = engine.evaluate(&e1);
        assert_eq!(v.result, "allow", "step 1 should not fire yet");

        // Step 2: network event within window
        let e2 = make_timed_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com", "dest_port": 443}),
            "2024-01-01T00:05:00Z",
        );
        let v = engine.evaluate(&e2);
        assert_eq!(v.result, "deny");
        assert_eq!(v.policy_rule, "seq:exfil");
        assert!(v.reason.contains("sequence"));
    }

    #[test]
    fn test_sequence_window_expired() {
        let yaml = r#"
rules:
  - id: seq:exfil
    type: sequence
    action: deny
    sequence:
      window: 5m
      steps:
        - event_type:
            equals: filesystem_summary
        - event_type:
            equals: network_egress
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Step 1: filesystem event
        let e1 = make_timed_event(
            "filesystem_summary",
            serde_json::json!({}),
            "2024-01-01T00:00:00Z",
        );
        engine.evaluate(&e1);

        // Step 2: network event AFTER window expired (>5m)
        let e2 = make_timed_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com", "dest_port": 443}),
            "2024-01-01T00:10:00Z",
        );
        let v = engine.evaluate(&e2);
        // Sequence should NOT fire — window expired
        assert_ne!(v.policy_rule, "seq:exfil");
    }

    #[test]
    fn test_sequence_resets_after_fire() {
        let yaml = r#"
rules:
  - id: seq:exfil
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
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Complete the sequence
        let e1 = make_timed_event("filesystem_summary", serde_json::json!({}), "2024-01-01T00:00:00Z");
        let e2 = make_timed_event(
            "network_egress",
            serde_json::json!({"dest_host": "x"}),
            "2024-01-01T00:01:00Z",
        );
        engine.evaluate(&e1);
        let v = engine.evaluate(&e2);
        assert_eq!(v.result, "deny");

        // Another network event should NOT re-fire (sequence reset)
        let e3 = make_timed_event(
            "network_egress",
            serde_json::json!({"dest_host": "y"}),
            "2024-01-01T00:02:00Z",
        );
        let v = engine.evaluate(&e3);
        assert_ne!(v.policy_rule, "seq:exfil");
    }

    #[test]
    fn test_sequence_three_steps() {
        let yaml = r#"
rules:
  - id: seq:three-step
    type: sequence
    action: deny
    sequence:
      window: 10m
      steps:
        - event_type:
            equals: auth
        - event_type:
            equals: filesystem_summary
        - event_type:
            equals: network_egress
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let e1 = make_timed_event("auth", serde_json::json!({}), "2024-01-01T00:00:00Z");
        let e2 = make_timed_event("filesystem_summary", serde_json::json!({}), "2024-01-01T00:01:00Z");
        let e3 = make_timed_event("network_egress", serde_json::json!({}), "2024-01-01T00:02:00Z");

        assert_eq!(engine.evaluate(&e1).result, "allow");
        assert_eq!(engine.evaluate(&e2).result, "allow");
        let v = engine.evaluate(&e3);
        assert_eq!(v.result, "deny");
        assert_eq!(v.policy_rule, "seq:three-step");
    }

    // -------------------------------------------------------------------
    // Network/filesystem through engine
    // -------------------------------------------------------------------

    #[test]
    fn test_engine_network_allow() {
        let yaml = r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "api.stripe.com", "dest_port": 443}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
        assert_eq!(verdict.policy_rule, "tool:stripe");
    }

    #[test]
    fn test_engine_network_deny_no_match() {
        let yaml = r#"
rules:
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com", "dest_port": 443}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
    }

    #[test]
    fn test_engine_filesystem() {
        let yaml = r#"
rules:
  - id: fs:workspace
    type: filesystem
    paths:
      - /home/agent/**
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/home/agent/output.txt"],
                "files_modified": [],
                "files_deleted": []
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
    }

    // -------------------------------------------------------------------
    // Mixed rule types
    // -------------------------------------------------------------------

    #[test]
    fn test_mixed_rules_first_match() {
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
  - id: tool:stripe
    type: network_egress
    destinations:
      - host: api.stripe.com
        port: 443
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Allowed destination: match rule doesn't fire, network rule allows
        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "api.stripe.com", "dest_port": 443}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");

        // Evil destination: match rule fires first (deny)
        let event = make_event(
            "network_egress",
            serde_json::json!({"dest_host": "evil.com", "dest_port": 443}),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert_eq!(verdict.policy_rule, "deny:exfil");
    }

    // -------------------------------------------------------------------
    // Default verdict for unknown event types
    // -------------------------------------------------------------------

    #[test]
    fn test_engine_filesystem_with_full_policy() {
        // Reproduce bug st-0o7: filesystem rule with match/sequence/threshold
        // before it should still evaluate correctly.
        let yaml = r#"
rules:
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
  - id: seq:exfil-pattern
    type: sequence
    action: deny
    sequence:
      window: 10m
      steps:
        - event_type:
            equals: filesystem_summary
          path:
            glob: "/home/agent/credentials*"
        - event_type:
            equals: network_egress
  - id: rate:api-calls
    type: threshold
    action: deny
    threshold:
      metric: count
      window: 5m
      limit: 100.0
  - id: fs:workspace
    type: filesystem
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
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Filesystem event with paths inside allowed workspace
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/home/agent/output.txt"],
                "files_modified": ["/tmp/scratch.log"],
                "files_deleted": []
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(
            verdict.result, "allow",
            "filesystem event within allowed paths should be allowed, got: {:?}",
            verdict
        );
        assert_eq!(verdict.policy_rule, "fs:workspace");

        // Filesystem event with path OUTSIDE allowed workspace should deny
        let bad_event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/etc/shadow"],
                "files_modified": [],
                "files_deleted": []
            }),
        );
        let bad_verdict = engine.evaluate(&bad_event);
        assert_eq!(
            bad_verdict.result, "deny",
            "filesystem event outside allowed paths should be denied, got: {:?}",
            bad_verdict
        );
    }

    #[test]
    fn test_engine_filesystem_readonly_denies_writes() {
        let yaml = r#"
rules:
  - id: fs:readonly
    type: filesystem
    access: read-only
    paths:
      - /home/agent/**
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Read-only: file creation should be denied
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/home/agent/new.txt"],
                "files_modified": [],
                "files_deleted": []
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert!(verdict.reason.contains("read-only"));

        // Read-only: file modification should be denied
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": [],
                "files_modified": ["/home/agent/existing.txt"],
                "files_deleted": []
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");

        // Read-only: read (path only) should be allowed
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": [],
                "files_modified": [],
                "files_deleted": [],
                "path": "/home/agent/data.txt"
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
    }

    #[test]
    fn test_engine_filesystem_readwrite_denies_deletes() {
        let yaml = r#"
rules:
  - id: fs:workspace
    type: filesystem
    access: read-write
    paths:
      - /home/agent/**
      - /tmp/**
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Read-write: creates and modifies should be allowed
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/home/agent/new.txt"],
                "files_modified": ["/tmp/scratch.log"],
                "files_deleted": []
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
        assert_eq!(verdict.policy_rule, "fs:workspace");

        // Read-write: deletes should be denied
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": [],
                "files_modified": [],
                "files_deleted": ["/home/agent/important.txt"]
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "deny");
        assert!(verdict.reason.contains("read-write"));
    }

    #[test]
    fn test_engine_filesystem_full_allows_all() {
        let yaml = r#"
rules:
  - id: fs:full
    type: filesystem
    access: full
    paths:
      - /opt/app/**
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        // Full access: all operations allowed
        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": ["/opt/app/new.bin"],
                "files_modified": ["/opt/app/config.json"],
                "files_deleted": ["/opt/app/old.log"]
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
        assert_eq!(verdict.policy_rule, "fs:full");
    }

    #[test]
    fn test_engine_filesystem_empty_paths_allows() {
        // Regression: v2 should allow filesystem_summary with no file paths
        // (consistent with v1 behavior), not fall through to default deny.
        let yaml = r#"
rules:
  - id: fs:workspace
    type: filesystem
    paths:
      - /home/agent/**
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event(
            "filesystem_summary",
            serde_json::json!({
                "files_created": [],
                "files_modified": [],
                "files_deleted": []
            }),
        );
        let verdict = engine.evaluate(&event);
        assert_eq!(
            verdict.result, "allow",
            "empty filesystem event should be allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_unknown_event_type_in_enforce() {
        let yaml = r#"
rules: []
"#;
        let policy = crate::load_policy(yaml).unwrap();
        let mut engine = PolicyEngine::new(policy);

        let event = make_event("custom_metric", serde_json::json!({}));
        let verdict = engine.evaluate(&event);
        assert_eq!(verdict.result, "allow");
    }
}
