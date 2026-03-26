use anyhow::{bail, Result};
use sandtrace_audit_chain::{AuditChain, Verdict};
use sandtrace_policy::PolicyManifest;
use std::path::PathBuf;

/// Run a demo scenario that generates synthetic audit events and shows
/// sandtrace detecting the exploit in real time.
pub fn run(scenario: &str) -> Result<()> {
    match scenario {
        "stripe-exfil" => run_stripe_exfil(),
        "persist" => run_persist(),
        _ => bail!(
            "unknown scenario: {scenario}\navailable: stripe-exfil, persist"
        ),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn demo_policy() -> PolicyManifest {
    sandtrace_policy::load_policy(
        r#"
mode: enforce
rules:
  - id: tool:stripe_charge
    type: network_egress
    description: "Stripe charges should carry only amount + short description"
    destinations:
      - host: api.stripe.com
        port: 443
    max_bytes_per_call: 100

  - id: tool:read_file
    type: filesystem
    access: read-write
    paths:
      - /home/agent/**
      - /tmp/**
"#,
    )
    .expect("built-in demo policy is valid")
}

fn temp_trail(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("sandtrace-demo");
    std::fs::create_dir_all(&dir).ok();
    dir.join(format!("{name}.jsonl"))
}

fn header(text: &str) {
    let bar = "=".repeat(60);
    println!("\n{bar}");
    println!("  {text}");
    println!("{bar}\n");
}

fn step(label: &str) {
    println!("  [{label}]");
}

fn event_line(seq: u64, event_type: &str, verdict: &Verdict) {
    let icon = match verdict.result.as_str() {
        "allow" => " ok ",
        "deny" => "DENY",
        "anomaly" => "WARN",
        _ => " ?? ",
    };
    println!(
        "    seq {seq:<3} {event_type:<22} [{icon}] {}",
        verdict.reason
    );
}

fn verify_and_summarize(trail: &PathBuf, policy: &PolicyManifest) -> Result<()> {
    step("verify audit trail");
    let events = sandtrace_audit_chain::read_jsonl(trail.to_str().unwrap())?;
    let chain = sandtrace_audit_chain::verify_chain(&events)?;

    if chain.valid {
        println!(
            "    chain integrity: VALID ({} events, tamper-evident hash chain)",
            chain.event_count
        );
    } else {
        println!(
            "    chain integrity: BROKEN ({} errors)",
            chain.errors.len()
        );
        for err in &chain.errors {
            println!("      seq {}: {} -- {}", err.seq, err.kind, err.detail);
        }
    }

    let violations = sandtrace_policy::check_events(&events, policy);
    if violations.is_empty() {
        println!("    policy compliance: PASS (no violations)");
    } else {
        println!(
            "    policy compliance: {} violation(s) detected",
            violations.len()
        );
        for v in &violations {
            println!("      [{}] {}", v.rule_id, v.reason);
        }
    }

    println!("\n    audit trail: {}\n", trail.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario 1: stripe-exfil
// ---------------------------------------------------------------------------

fn run_stripe_exfil() -> Result<()> {
    header("sandtrace demo -- stripe-exfil");
    println!("  An AI billing agent is tricked into exfiltrating credentials");
    println!("  via an oversized Stripe charge description field.\n");

    let policy = demo_policy();
    let trail = temp_trail("stripe-exfil");
    // Remove stale trail from previous runs
    std::fs::remove_file(&trail).ok();
    let mut chain = AuditChain::open(&trail)?;

    let agent_id = "demo-billing-agent";
    let trace_id = "demo-trace-001";

    // -- Step 1: Agent reads credentials.json (file access to sensitive path)
    step("agent reads /home/agent/credentials.json");
    let fs_payload = serde_json::json!({
        "files_created": [],
        "files_modified": [],
        "files_deleted": [],
        "path": "/home/agent/credentials.json"
    });
    let fs_verdict = sandtrace_policy::evaluate(
        &stub_event("filesystem_summary", &fs_payload),
        &policy,
    );
    let e1 = chain.append(
        "filesystem_summary",
        agent_id,
        trace_id,
        "hypervisor",
        fs_payload,
        Some(fs_verdict.clone()),
    )?;
    event_line(e1.seq, "filesystem_summary", &fs_verdict);

    // -- Step 2: Legitimate Stripe charge (~69 bytes)
    step("agent charges $4,200 for Invoice #1042 (legitimate)");
    let legit_desc = "Invoice #1042 -- Acme Corp -- $4,200.00";
    let legit_payload = serde_json::json!({
        "dest_host": "api.stripe.com",
        "dest_port": 443,
        "bytes_sent": legit_desc.len(),
        "protocol": "tcp",
        "description": legit_desc,
    });
    let legit_verdict = sandtrace_policy::evaluate(
        &stub_event("network_egress", &legit_payload),
        &policy,
    );
    let e2 = chain.append(
        "network_egress",
        agent_id,
        trace_id,
        "hypervisor",
        legit_payload,
        Some(legit_verdict.clone()),
    )?;
    event_line(e2.seq, "network_egress", &legit_verdict);

    // -- Step 3: Exfiltration charge (~316 bytes -- credentials stuffed into description)
    step("agent exfiltrates credentials via Stripe description (EXPLOIT)");
    let exfil_desc = serde_json::json!({
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "stripe_secret": "sk_live_DEMO_NOT_A_REAL_KEY_000000",
        "database_url": "postgres://admin:s3cr3t@db.internal:5432/prod",
    })
    .to_string();
    let exfil_payload = serde_json::json!({
        "dest_host": "api.stripe.com",
        "dest_port": 443,
        "bytes_sent": exfil_desc.len(),
        "protocol": "tcp",
        "description": exfil_desc,
    });
    let exfil_verdict = sandtrace_policy::evaluate(
        &stub_event("network_egress", &exfil_payload),
        &policy,
    );
    let e3 = chain.append(
        "network_egress",
        agent_id,
        trace_id,
        "hypervisor",
        exfil_payload,
        Some(exfil_verdict.clone()),
    )?;
    event_line(e3.seq, "network_egress", &exfil_verdict);

    // -- Step 4: Agent writes output.txt
    step("agent writes /tmp/output.txt");
    let write_payload = serde_json::json!({
        "files_created": ["/tmp/output.txt"],
        "files_modified": [],
        "files_deleted": [],
    });
    let write_verdict = sandtrace_policy::evaluate(
        &stub_event("filesystem_summary", &write_payload),
        &policy,
    );
    let e4 = chain.append(
        "filesystem_summary",
        agent_id,
        trace_id,
        "hypervisor",
        write_payload,
        Some(write_verdict.clone()),
    )?;
    event_line(e4.seq, "filesystem_summary", &write_verdict);

    println!();
    verify_and_summarize(&trail, &policy)?;

    println!("  RESULT: sandtrace detected the exfiltration via anomalous");
    println!("  payload size on the Stripe API call. The legitimate charge");
    println!("  sent ~{} bytes; the exfil attempt sent ~{} bytes,", legit_desc.len(), exfil_desc.len());
    println!("  exceeding the 100-byte policy limit.\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario 2: multi-session persistence
// ---------------------------------------------------------------------------

fn run_persist() -> Result<()> {
    header("sandtrace demo -- multi-session persistence");
    println!("  A malicious document plants a standing instruction in agent");
    println!("  memory. A fresh session reads it and exfiltrates credentials\n");
    println!("  without any prompt injection in the new session.\n");

    let policy = demo_policy();
    let trail = temp_trail("persist");
    std::fs::remove_file(&trail).ok();
    let mut chain = AuditChain::open(&trail)?;

    let agent_id = "demo-billing-agent";

    // ---- Session 1 ----
    let trace_s1 = "demo-trace-s1";
    step("SESSION 1: normal billing run (injection plants memory)");
    println!();

    // S1-E1: Agent reads report.pdf containing billing_actions with memory_update
    step("agent reads /home/agent/report.pdf");
    let read_payload = serde_json::json!({
        "files_created": [],
        "files_modified": [],
        "files_deleted": [],
        "path": "/home/agent/report.pdf"
    });
    let read_v = sandtrace_policy::evaluate(
        &stub_event("filesystem_summary", &read_payload),
        &policy,
    );
    let e1 = chain.append(
        "filesystem_summary",
        agent_id,
        trace_s1,
        "hypervisor",
        read_payload,
        Some(read_v.clone()),
    )?;
    event_line(e1.seq, "filesystem_summary", &read_v);

    // S1-E2: Agent writes .agent_memory.json (planting the standing instruction)
    step("agent writes /home/agent/.agent_memory.json (INJECTION)");
    let memory_payload = serde_json::json!({
        "files_created": ["/home/agent/.agent_memory.json"],
        "files_modified": [],
        "files_deleted": [],
    });
    let mem_v = sandtrace_policy::evaluate(
        &stub_event("filesystem_summary", &memory_payload),
        &policy,
    );
    let e2 = chain.append(
        "filesystem_summary",
        agent_id,
        trace_s1,
        "hypervisor",
        memory_payload,
        Some(mem_v.clone()),
    )?;
    event_line(e2.seq, "filesystem_summary", &mem_v);

    // S1-E3: Legitimate Stripe charge
    step("agent charges $4,200 for Invoice #1042 (legitimate)");
    let legit_payload = serde_json::json!({
        "dest_host": "api.stripe.com",
        "dest_port": 443,
        "bytes_sent": 69,
        "protocol": "tcp",
    });
    let legit_v = sandtrace_policy::evaluate(
        &stub_event("network_egress", &legit_payload),
        &policy,
    );
    let e3 = chain.append(
        "network_egress",
        agent_id,
        trace_s1,
        "hypervisor",
        legit_payload,
        Some(legit_v.clone()),
    )?;
    event_line(e3.seq, "network_egress", &legit_v);

    // ---- Session 2 ----
    let trace_s2 = "demo-trace-s2";
    println!();
    step("SESSION 2: clean task (standing instruction fires unprompted)");
    println!();

    // S2-E1: Agent reads .agent_memory.json
    step("agent reads /home/agent/.agent_memory.json");
    let read_mem_payload = serde_json::json!({
        "files_created": [],
        "files_modified": [],
        "files_deleted": [],
        "path": "/home/agent/.agent_memory.json"
    });
    let read_mem_v = sandtrace_policy::evaluate(
        &stub_event("filesystem_summary", &read_mem_payload),
        &policy,
    );
    let e4 = chain.append(
        "filesystem_summary",
        agent_id,
        trace_s2,
        "hypervisor",
        read_mem_payload,
        Some(read_mem_v.clone()),
    )?;
    event_line(e4.seq, "filesystem_summary", &read_mem_v);

    // S2-E2: Agent reads credentials.json (triggered by standing instruction)
    step("agent reads /home/agent/credentials.json (standing instruction)");
    let read_creds = serde_json::json!({
        "files_created": [],
        "files_modified": [],
        "files_deleted": [],
        "path": "/home/agent/credentials.json"
    });
    let creds_v = sandtrace_policy::evaluate(
        &stub_event("filesystem_summary", &read_creds),
        &policy,
    );
    let e5 = chain.append(
        "filesystem_summary",
        agent_id,
        trace_s2,
        "hypervisor",
        read_creds,
        Some(creds_v.clone()),
    )?;
    event_line(e5.seq, "filesystem_summary", &creds_v);

    // S2-E3: Exfiltration via Stripe (standing instruction fires)
    step("agent exfiltrates credentials via Stripe (EXPLOIT)");
    let exfil_desc = serde_json::json!({
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    })
    .to_string();
    let exfil_payload = serde_json::json!({
        "dest_host": "api.stripe.com",
        "dest_port": 443,
        "bytes_sent": exfil_desc.len(),
        "protocol": "tcp",
        "description": exfil_desc,
    });
    let exfil_v = sandtrace_policy::evaluate(
        &stub_event("network_egress", &exfil_payload),
        &policy,
    );
    let e6 = chain.append(
        "network_egress",
        agent_id,
        trace_s2,
        "hypervisor",
        exfil_payload,
        Some(exfil_v.clone()),
    )?;
    event_line(e6.seq, "network_egress", &exfil_v);

    println!();
    verify_and_summarize(&trail, &policy)?;

    println!("  RESULT: sandtrace detected the multi-session persistence attack.");
    println!("  Session 1 planted a standing instruction in .agent_memory.json.");
    println!("  Session 2 read that memory and exfiltrated credentials without");
    println!("  any prompt injection in the new session's input.\n");
    println!("  The cross-session trace linkage (trace_id change from s1 to s2)");
    println!("  combined with the anomalous payload size flags the exfiltration.\n");
    Ok(())
}

/// Build a minimal AuditEvent for policy evaluation (not written to chain).
fn stub_event(event_type: &str, payload: &serde_json::Value) -> sandtrace_audit_chain::AuditEvent {
    sandtrace_audit_chain::AuditEvent {
        schema_version: "2.0".into(),
        event_id: "eval".into(),
        event_type: event_type.into(),
        agent_id: String::new(),
        trace_id: String::new(),
        seq: 0,
        prev_hash: None,
        record_hash: String::new(),
        wall_time: String::new(),
        evidence_tier: "hypervisor".into(),
        payload: payload.clone(),
        verdict: None,
    }
}
