mod demo;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sandtrace")]
#[command(about = "Hypervisor-level audit trails for AI agent sandboxes")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to policy YAML file
    #[arg(long, global = true)]
    policy: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Watch a running sandbox and emit audit events in real time
    Watch {
        /// Sandbox or VM identifier to attach to
        #[arg(long)]
        sandbox_id: String,

        /// Output target: file path, `-` for stdout, or `unix:///path` for Unix socket
        #[arg(short, long, default_value = "-")]
        output: String,

        /// Filter by event type (comma-separated, e.g. "network_egress,filesystem_summary")
        #[arg(long)]
        filter_type: Option<String>,

        /// Filter by evidence tier (comma-separated, e.g. "hypervisor,kernel")
        #[arg(long)]
        filter_tier: Option<String>,

        /// Filter by verdict result (comma-separated, e.g. "deny,anomaly")
        #[arg(long)]
        filter_verdict: Option<String>,

        /// Disable schema validation on output events
        #[arg(long)]
        no_validate: bool,

        /// Tap device to capture network traffic from (overrides provider default)
        #[arg(long)]
        tap_device: Option<String>,

        /// Overlay upper directory for filesystem monitoring (overrides provider default)
        #[arg(long)]
        overlay_dir: Option<String>,

        /// Firecracker API socket path (overrides provider default)
        #[arg(long)]
        fc_socket: Option<String>,
    },

    /// Verify a JSONL audit trail for integrity and policy compliance
    Verify {
        /// Path to the JSONL audit trail file
        path: String,

        /// Policy file to check against (overrides --policy)
        #[arg(long)]
        against: Option<String>,

        /// Output results as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Stream events from a JSONL file through the output pipeline
    Stream {
        /// Path to the JSONL audit trail file to stream
        path: String,

        /// Output target: file path, `-` for stdout, or `unix:///path` for Unix socket
        #[arg(short, long, default_value = "-")]
        output: String,

        /// Filter by event type (comma-separated)
        #[arg(long)]
        filter_type: Option<String>,

        /// Filter by evidence tier (comma-separated)
        #[arg(long)]
        filter_tier: Option<String>,

        /// Filter by verdict result (comma-separated)
        #[arg(long)]
        filter_verdict: Option<String>,

        /// Disable schema validation on output events
        #[arg(long)]
        no_validate: bool,
    },

    /// Run the demo scenario showing exfiltration detection
    Demo {
        /// Scenario to run
        #[arg(default_value = "stripe-exfil")]
        scenario: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if cli.verbose {
                    EnvFilter::new("debug")
                } else {
                    EnvFilter::new("info")
                }
            }),
        )
        .init();

    let policy = cli
        .policy
        .as_deref()
        .map(sandtrace_policy::load_policy_file)
        .transpose()?;

    match cli.command {
        Command::Watch {
            sandbox_id,
            output,
            filter_type,
            filter_tier,
            filter_verdict,
            no_validate,
            tap_device,
            overlay_dir,
            fc_socket,
        } => {
            // Set env vars so provider detection picks them up
            if let Some(tap) = &tap_device {
                std::env::set_var("SANDTRACE_TAP_DEVICE", tap);
            }
            if let Some(dir) = &overlay_dir {
                std::env::set_var("SANDTRACE_OVERLAY_DIR", dir);
            }
            if let Some(sock) = &fc_socket {
                std::env::set_var("SANDTRACE_FC_SOCKET", sock);
            }
            cmd_watch(
                sandbox_id,
                output,
                policy,
                filter_type,
                filter_tier,
                filter_verdict,
                no_validate,
            )
            .await
        }
        Command::Verify { path, against, json } => {
            let verify_policy = match against {
                Some(ref p) => Some(sandtrace_policy::load_policy_file(p)?),
                None => policy,
            };
            cmd_verify(path, verify_policy, json)
        }
        Command::Stream {
            path,
            output,
            filter_type,
            filter_tier,
            filter_verdict,
            no_validate,
        } => {
            cmd_stream(
                path,
                output,
                policy,
                filter_type,
                filter_tier,
                filter_verdict,
                no_validate,
            )
            .await
        }
        Command::Demo { scenario } => cmd_demo(scenario),
    }
}

fn build_filter(
    filter_type: Option<String>,
    filter_tier: Option<String>,
    filter_verdict: Option<String>,
) -> sandtrace_output::EventFilter {
    let mut filter = sandtrace_output::EventFilter::new();

    if let Some(types) = filter_type {
        let types: Vec<String> = types.split(',').map(|s| s.trim().to_string()).collect();
        filter = filter.with_event_types(types);
    }

    if let Some(tiers) = filter_tier {
        let tiers: Vec<String> = tiers.split(',').map(|s| s.trim().to_string()).collect();
        filter = filter.with_evidence_tiers(tiers);
    }

    if let Some(verdicts) = filter_verdict {
        let results: Vec<String> = verdicts.split(',').map(|s| s.trim().to_string()).collect();
        filter = filter.with_verdict(sandtrace_output::VerdictFilter::Only(results));
    }

    filter
}

async fn cmd_watch(
    sandbox_id: String,
    output: String,
    policy: Option<sandtrace_policy::PolicyManifest>,
    filter_type: Option<String>,
    filter_tier: Option<String>,
    filter_verdict: Option<String>,
    no_validate: bool,
) -> Result<()> {
    tracing::info!(sandbox_id, "attaching to sandbox");

    // Auto-detect schema version and create the appropriate evaluator.
    // V2 policies use the stateful PolicyEngine (supports match/threshold/sequence).
    // V1 policies use the legacy stateless evaluate() function.
    let mut engine = policy.as_ref().and_then(|p| {
        if p.is_v2() {
            tracing::info!(rules = p.rules.len(), "loaded v2 policy engine");
            Some(sandtrace_policy::PolicyEngine::new(p.clone()))
        } else {
            tracing::info!(rules = p.rules.len(), "loaded v1 policy");
            None
        }
    });

    if engine.is_none() {
        if let Some(p) = &policy {
            tracing::info!(rules = p.rules.len(), "loaded policy");
        }
    }

    let sink = sandtrace_output::OutputSink::from_target(&output).await?;
    let filter = build_filter(filter_type, filter_tier, filter_verdict);

    let mut stream = sandtrace_output::EventOutputStream::new(vec![sink])
        .with_filter(filter)
        .with_validation(!no_validate);

    tracing::info!(output, "output pipeline ready");

    // Auto-detect the sandbox provider and attach.
    let provider = sandtrace_provider::detect::create_default_provider();
    tracing::info!(provider = provider.name(), "detected provider");

    let capture_stream = provider.attach(&sandbox_id)?;

    // Convert captured events into hash-chained audit events, evaluate
    // policy on each, and emit through the output pipeline.
    let mut seq: u64 = 1;
    let mut prev_hash: Option<String> = None;
    let mut event_count: u64 = 0;

    // Set up a shutdown flag triggered by SIGINT/SIGTERM.
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let ctrl_c = tokio::signal::ctrl_c();
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to register SIGTERM handler");
                tokio::select! {
                    _ = ctrl_c => {},
                    _ = sigterm.recv() => {},
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
            }
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }

    tracing::info!("watching sandbox — press Ctrl+C to stop");

    // Continuously receive events from the capture stream until shutdown.
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!("shutdown signal received, flushing");
            break;
        }

        // Block for up to 1 second waiting for an event, then re-check shutdown.
        let captured = match capture_stream.recv_timeout(std::time::Duration::from_secs(1)) {
            Some(ev) => ev,
            None => {
                // Timeout or all capture threads finished.
                // Check if all senders have been dropped (stream exhausted).
                // recv_timeout returns None for both timeout and disconnect;
                // we distinguish by checking if shutdown was requested.
                continue;
            }
        };

        let event_type_str = event_type_to_str(&captured.event_type);
        let evidence_tier = evidence_tier_for(&captured.event_type);

        // Evaluate policy if available. We build a preliminary event without
        // a verdict so policy can inspect it, then build the final event with
        // the verdict included in the hash.
        let verdict = if let Some(ref mut eng) = engine {
            // V2: stateful engine evaluation (handles all rule types)
            let tmp = sandtrace_audit_chain::build_event(
                event_type_str,
                &captured.agent_id,
                &captured.trace_id,
                seq,
                prev_hash.clone(),
                evidence_tier,
                captured.payload.clone(),
                None,
            );
            Some(eng.evaluate(&tmp))
        } else {
            policy.as_ref().map(|p| {
                let tmp = sandtrace_audit_chain::build_event(
                    event_type_str,
                    &captured.agent_id,
                    &captured.trace_id,
                    seq,
                    prev_hash.clone(),
                    evidence_tier,
                    captured.payload.clone(),
                    None,
                );
                sandtrace_policy::evaluate(&tmp, p)
            })
        };

        let audit_event = sandtrace_audit_chain::build_event(
            event_type_str,
            &captured.agent_id,
            &captured.trace_id,
            seq,
            prev_hash.clone(),
            evidence_tier,
            captured.payload,
            verdict,
        );

        prev_hash = Some(audit_event.record_hash.clone());
        seq += 1;

        // Print event to terminal in real time
        let verdict_str = audit_event.verdict.as_ref()
            .map(|v| format!("{}", v.result))
            .unwrap_or_else(|| "allow".to_string());
        let verdict_color = match verdict_str.as_str() {
            "deny" | "block" => "\x1b[1;31m",   // red
            "anomaly" | "flag" => "\x1b[1;33m",  // yellow
            _ => "\x1b[1;32m",                   // green
        };
        let reason = audit_event.verdict.as_ref()
            .map(|v| v.reason.as_str())
            .unwrap_or("");
        eprintln!(
            "  {}{:>6}\x1b[0m  seq={:<3}  {}  {}",
            verdict_color, verdict_str, audit_event.seq,
            audit_event.event_type, reason
        );

        stream.emit(&audit_event).await?;
        event_count += 1;
    }

    stream.flush().await?;
    stream.close().await?;

    tracing::info!(event_count, "watch complete");
    Ok(())
}

/// Map `EventType` enum to its snake_case string representation.
fn event_type_to_str(et: &sandtrace_capture::EventType) -> &'static str {
    match et {
        sandtrace_capture::EventType::NetworkEgress => "network_egress",
        sandtrace_capture::EventType::FilesystemSummary => "filesystem_summary",
        sandtrace_capture::EventType::SyscallActivity => "syscall_activity",
        sandtrace_capture::EventType::PolicyViolation => "policy_violation",
    }
}

/// Determine the evidence tier for a given event type.
fn evidence_tier_for(et: &sandtrace_capture::EventType) -> &'static str {
    match et {
        sandtrace_capture::EventType::NetworkEgress => "hypervisor",
        sandtrace_capture::EventType::FilesystemSummary => "hypervisor",
        sandtrace_capture::EventType::SyscallActivity => "kernel",
        sandtrace_capture::EventType::PolicyViolation => "hypervisor",
    }
}

async fn cmd_stream(
    path: String,
    output: String,
    policy: Option<sandtrace_policy::PolicyManifest>,
    filter_type: Option<String>,
    filter_tier: Option<String>,
    filter_verdict: Option<String>,
    no_validate: bool,
) -> Result<()> {
    tracing::info!(path, "streaming events");

    let mut events = sandtrace_audit_chain::read_jsonl(&path)?;

    // When a policy is provided, re-evaluate verdicts through the appropriate
    // engine so that stream output reflects the current policy (not stale
    // verdicts baked into the JSONL file).
    if let Some(ref p) = policy {
        if p.is_v2() {
            tracing::info!("applying v2 policy evaluation to stream");
            let mut engine = sandtrace_policy::PolicyEngine::new(p.clone());
            for event in &mut events {
                let verdict = engine.evaluate(event);
                event.verdict = Some(verdict);
            }
        } else {
            tracing::info!("applying v1 policy evaluation to stream");
            for event in &mut events {
                let verdict = sandtrace_policy::evaluate(event, p);
                event.verdict = Some(verdict);
            }
        }
    }

    let sink = sandtrace_output::OutputSink::from_target(&output).await?;
    let filter = build_filter(filter_type, filter_tier, filter_verdict);

    let mut stream = sandtrace_output::EventOutputStream::new(vec![sink])
        .with_filter(filter)
        .with_validation(!no_validate);

    stream.emit_all(&events).await?;
    stream.flush().await?;

    tracing::info!(count = events.len(), "streaming complete");
    Ok(())
}

fn cmd_verify(
    path: String,
    policy: Option<sandtrace_policy::PolicyManifest>,
    json_output: bool,
) -> Result<()> {
    tracing::info!(path, "verifying audit trail");

    let events = sandtrace_audit_chain::read_jsonl(&path)?;
    let chain_result = sandtrace_audit_chain::verify_chain(&events)?;

    // Auto-detect schema version: v2 uses stateful engine (threshold/sequence
    // state accumulates across events), v1 uses legacy stateless evaluator.
    let violations = match &policy {
        Some(p) if p.is_v2() => {
            tracing::info!("using v2 policy engine for verification");
            let mut engine = sandtrace_policy::PolicyEngine::new(p.clone());
            engine.check_events(&events)
        }
        Some(p) => sandtrace_policy::check_events(&events, p),
        None => Vec::new(),
    };

    if json_output {
        let output = serde_json::json!({
            "path": path,
            "chain": {
                "valid": chain_result.valid,
                "event_count": chain_result.event_count,
                "errors": chain_result.errors,
            },
            "policy": {
                "checked": policy.is_some(),
                "violations": violations.iter().map(|v| serde_json::json!({
                    "event_id": v.event_id,
                    "rule_id": v.rule_id,
                    "reason": v.reason,
                })).collect::<Vec<_>>(),
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable output
        if chain_result.valid {
            println!(
                "Chain integrity: VALID ({} events)",
                chain_result.event_count
            );
        } else {
            println!(
                "Chain integrity: BROKEN ({} events, {} errors)",
                chain_result.event_count,
                chain_result.errors.len()
            );
            for err in &chain_result.errors {
                println!(
                    "  seq {}: {} — {}",
                    err.seq, err.kind, err.detail
                );
            }
        }

        if policy.is_some() {
            if violations.is_empty() {
                println!("Policy compliance: PASS");
            } else {
                println!("Policy compliance: {} violations", violations.len());
                for v in &violations {
                    println!(
                        "  event {}: [{}] {}",
                        v.event_id, v.rule_id, v.reason
                    );
                }
            }
        }
    }

    // Exit with non-zero status if chain is broken or policy violated
    if !chain_result.valid || !violations.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn cmd_demo(scenario: String) -> Result<()> {
    demo::run(&scenario)
}
