use sandtrace_audit_chain::AuditEvent;

/// Which verdict results to include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictFilter {
    /// Include all events regardless of verdict.
    Any,
    /// Only include events with one of these verdict results.
    Only(Vec<String>),
    /// Only include events that have a verdict attached.
    Present,
    /// Only include events with no verdict.
    Absent,
}

impl Default for VerdictFilter {
    fn default() -> Self {
        Self::Any
    }
}

/// Configurable event filter for the output pipeline.
///
/// All criteria are ANDed together: an event must match every non-empty filter
/// to pass through.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// If non-empty, only pass events whose `event_type` is in this set.
    event_types: Vec<String>,
    /// If non-empty, only pass events whose `evidence_tier` is in this set.
    evidence_tiers: Vec<String>,
    /// Verdict-based filtering.
    verdict: VerdictFilter,
}

impl EventFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by event type (e.g. "network_egress", "filesystem_summary").
    pub fn with_event_types(mut self, types: Vec<String>) -> Self {
        self.event_types = types;
        self
    }

    /// Filter by evidence tier (e.g. "hypervisor", "kernel").
    pub fn with_evidence_tiers(mut self, tiers: Vec<String>) -> Self {
        self.evidence_tiers = tiers;
        self
    }

    /// Filter by policy verdict.
    pub fn with_verdict(mut self, verdict: VerdictFilter) -> Self {
        self.verdict = verdict;
        self
    }

    /// Returns true if the event passes all filter criteria.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if !self.event_types.is_empty() && !self.event_types.contains(&event.event_type) {
            return false;
        }

        if !self.evidence_tiers.is_empty() && !self.evidence_tiers.contains(&event.evidence_tier) {
            return false;
        }

        match &self.verdict {
            VerdictFilter::Any => {}
            VerdictFilter::Present => {
                if event.verdict.is_none() {
                    return false;
                }
            }
            VerdictFilter::Absent => {
                if event.verdict.is_some() {
                    return false;
                }
            }
            VerdictFilter::Only(results) => match &event.verdict {
                Some(v) => {
                    if !results.contains(&v.result) {
                        return false;
                    }
                }
                None => return false,
            },
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtrace_audit_chain::{build_event, Verdict};

    fn make_event(
        event_type: &str,
        tier: &str,
        verdict: Option<(&str, &str)>,
    ) -> AuditEvent {
        let v = verdict.map(|(result, rule)| Verdict {
            result: result.to_string(),
            policy_rule: rule.to_string(),
            reason: "test".to_string(),
        });
        build_event(
            event_type,
            "agent-1",
            "trace-1",
            1,
            None,
            tier,
            serde_json::json!({}),
            v,
        )
    }

    #[test]
    fn test_default_filter_matches_all() {
        let filter = EventFilter::default();
        let event = make_event("network_egress", "hypervisor", None);
        assert!(filter.matches(&event));
    }

    #[test]
    fn test_event_type_filter() {
        let filter = EventFilter::new()
            .with_event_types(vec!["filesystem_summary".to_string()]);

        assert!(!filter.matches(&make_event("network_egress", "hypervisor", None)));
        assert!(filter.matches(&make_event("filesystem_summary", "hypervisor", None)));
    }

    #[test]
    fn test_evidence_tier_filter() {
        let filter = EventFilter::new()
            .with_evidence_tiers(vec!["kernel".to_string()]);

        assert!(!filter.matches(&make_event("network_egress", "hypervisor", None)));
        assert!(filter.matches(&make_event("network_egress", "kernel", None)));
    }

    #[test]
    fn test_verdict_present_filter() {
        let filter = EventFilter::new().with_verdict(VerdictFilter::Present);

        assert!(!filter.matches(&make_event("network_egress", "hypervisor", None)));
        assert!(filter.matches(&make_event(
            "network_egress",
            "hypervisor",
            Some(("allow", "rule-1")),
        )));
    }

    #[test]
    fn test_verdict_only_deny() {
        let filter = EventFilter::new()
            .with_verdict(VerdictFilter::Only(vec!["deny".to_string()]));

        assert!(!filter.matches(&make_event(
            "network_egress",
            "hypervisor",
            Some(("allow", "rule-1")),
        )));
        assert!(filter.matches(&make_event(
            "network_egress",
            "hypervisor",
            Some(("deny", "rule-1")),
        )));
        // No verdict at all → excluded
        assert!(!filter.matches(&make_event("network_egress", "hypervisor", None)));
    }

    #[test]
    fn test_combined_filters() {
        let filter = EventFilter::new()
            .with_event_types(vec!["network_egress".to_string()])
            .with_evidence_tiers(vec!["hypervisor".to_string()])
            .with_verdict(VerdictFilter::Only(vec!["deny".to_string()]));

        // Matches all criteria
        assert!(filter.matches(&make_event(
            "network_egress",
            "hypervisor",
            Some(("deny", "rule-1")),
        )));

        // Wrong event type
        assert!(!filter.matches(&make_event(
            "filesystem_summary",
            "hypervisor",
            Some(("deny", "rule-1")),
        )));

        // Wrong tier
        assert!(!filter.matches(&make_event(
            "network_egress",
            "kernel",
            Some(("deny", "rule-1")),
        )));

        // Wrong verdict
        assert!(!filter.matches(&make_event(
            "network_egress",
            "hypervisor",
            Some(("allow", "rule-1")),
        )));
    }
}
