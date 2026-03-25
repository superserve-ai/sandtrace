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
        } => {
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

    if let Some(policy) = &policy {
        tracing::info!(rules = policy.rules.len(), "loaded policy");
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

    let captured_events = provider.attach(&sandbox_id)?;

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

    for captured in captured_events {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!("shutdown signal received, flushing");
            break;
        }

        let event_type_str = event_type_to_str(&captured.event_type);
        let evidence_tier = evidence_tier_for(&captured.event_type);

        // Evaluate policy if available. We build a preliminary event without
        // a verdict so policy can inspect it, then build the final event with
        // the verdict included in the hash.
        let verdict = policy.as_ref().map(|p| {
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
        });

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
    filter_type: Option<String>,
    filter_tier: Option<String>,
    filter_verdict: Option<String>,
    no_validate: bool,
) -> Result<()> {
    tracing::info!(path, "streaming events");

    let events = sandtrace_audit_chain::read_jsonl(&path)?;
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

    let violations = policy
        .as_ref()
        .map(|p| sandtrace_policy::check_events(&events, p))
        .unwrap_or_default();

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
    tracing::info!(scenario, "running demo scenario");

    // Placeholder: will invoke the Python demo-agent or a Rust-native
    // version of the scenario, then run verify on the output.
    tracing::warn!("demo command is not yet implemented");
    Ok(())
}
