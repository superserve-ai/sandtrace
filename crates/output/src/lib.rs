//! JSONL event output pipeline for Sandtrace.
//!
//! Writes `AuditEvent`s as JSONL to configurable outputs (file, stdout, Unix socket)
//! with real-time streaming, event filtering, and schema validation.

mod filter;
mod sink;
mod validate;

pub use filter::{EventFilter, VerdictFilter};
pub use sink::OutputSink;
pub use validate::{validate_event, ValidationError};

use anyhow::Result;
use sandtrace_audit_chain::AuditEvent;
use tokio::sync::broadcast;

/// Channel capacity for the event broadcast.
const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// Event output stream that filters, validates, and writes events to one or more sinks.
pub struct EventOutputStream {
    sinks: Vec<OutputSink>,
    filter: EventFilter,
    validate: bool,
    tx: broadcast::Sender<AuditEvent>,
}

impl EventOutputStream {
    /// Create a new output stream writing to the given sinks.
    pub fn new(sinks: Vec<OutputSink>) -> Self {
        let (tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        Self {
            sinks,
            filter: EventFilter::default(),
            validate: true,
            tx,
        }
    }

    /// Set the event filter.
    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Enable or disable schema validation (enabled by default).
    pub fn with_validation(mut self, validate: bool) -> Self {
        self.validate = validate;
        self
    }

    /// Subscribe to the event broadcast for live monitoring.
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.tx.subscribe()
    }

    /// Emit a single event through the pipeline: filter → validate → write to all sinks.
    pub async fn emit(&mut self, event: &AuditEvent) -> Result<()> {
        if !self.filter.matches(event) {
            return Ok(());
        }

        if self.validate {
            validate_event(event)?;
        }

        let line = serde_json::to_string(event)?;

        for sink in &mut self.sinks {
            sink.write_line(&line).await?;
        }

        // Best-effort broadcast for subscribers (ignore if no receivers).
        let _ = self.tx.send(event.clone());

        Ok(())
    }

    /// Emit multiple events.
    pub async fn emit_all(&mut self, events: &[AuditEvent]) -> Result<()> {
        for event in events {
            self.emit(event).await?;
        }
        Ok(())
    }

    /// Flush all sinks.
    pub async fn flush(&mut self) -> Result<()> {
        for sink in &mut self.sinks {
            sink.flush().await?;
        }
        Ok(())
    }

    /// Close all sinks.
    pub async fn close(mut self) -> Result<()> {
        for sink in &mut self.sinks {
            sink.flush().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtrace_audit_chain::build_event;

    fn sample_event(event_type: &str, verdict_result: Option<&str>) -> AuditEvent {
        let verdict = verdict_result.map(|r| sandtrace_audit_chain::Verdict {
            result: r.to_string(),
            policy_rule: "rule-1".to_string(),
            reason: "test".to_string(),
        });
        build_event(
            event_type,
            "agent-1",
            "trace-1",
            1,
            None,
            "hypervisor",
            serde_json::json!({"dest_host": "api.stripe.com", "dest_port": 443}),
            verdict,
        )
    }

    #[tokio::test]
    async fn test_emit_to_file_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");

        let sink = OutputSink::file(&path).await.unwrap();
        let mut stream = EventOutputStream::new(vec![sink]);

        let event = sample_event("network_egress", None);
        stream.emit(&event).await.unwrap();
        stream.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.event_id, event.event_id);
    }

    #[tokio::test]
    async fn test_filter_excludes_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");

        let sink = OutputSink::file(&path).await.unwrap();
        let filter = EventFilter::new().with_event_types(vec!["filesystem_summary".to_string()]);
        let mut stream = EventOutputStream::new(vec![sink]).with_filter(filter);

        let event = sample_event("network_egress", None);
        stream.emit(&event).await.unwrap();
        stream.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[tokio::test]
    async fn test_broadcast_subscriber() {
        let sink = OutputSink::stdout();
        let stream = EventOutputStream::new(vec![sink]).with_validation(false);
        let mut rx = stream.subscribe();

        // We need a mutable stream after subscribing
        let mut stream = stream;
        let event = sample_event("network_egress", None);
        stream.emit(&event).await.unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.event_id, event.event_id);
    }

    #[tokio::test]
    async fn test_validation_rejects_bad_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let sink = OutputSink::file(&path).await.unwrap();
        let mut stream = EventOutputStream::new(vec![sink]);

        let mut event = sample_event("network_egress", None);
        event.schema_version = "99.0".to_string(); // invalid

        let result = stream.emit(&event).await;
        assert!(result.is_err());
    }
}
