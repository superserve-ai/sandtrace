mod demo;
mod pretty;

use std::collections::HashMap;

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
        /// Sandbox or VM identifier (omit to auto-discover all running VMs)
        #[arg(long)]
        sandbox_id: Option<String>,

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
    sandbox_id: Option<String>,
    output: String,
    policy: Option<sandtrace_policy::PolicyManifest>,
    filter_type: Option<String>,
    filter_tier: Option<String>,
    filter_verdict: Option<String>,
    no_validate: bool,
) -> Result<()> {
    // Auto-detect schema version and create the appropriate evaluator.
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

    // Determine provider.
    let provider = sandtrace_provider::detect::create_default_provider();
    let provider_name = provider.name().to_string();
    tracing::info!(provider = %provider_name, "detected provider");

    let single_mode = sandbox_id.is_some();

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

    // Two channels: lifecycle events (attach/detach) and capture events.
    let (capture_tx, capture_rx) = std::sync::mpsc::channel();
    let (lifecycle_tx, lifecycle_rx) = std::sync::mpsc::channel();
    let mut tracker = SandboxTracker::new();

    let multi = !single_mode;

    if single_mode {
        // Single-VM mode: attach directly, no lifecycle watcher.
        let info = sandtrace_provider::SandboxInfo {
            sandbox_id: sandbox_id.unwrap(),
            pid: None,
            provider,
        };
        tracker.attach(info, capture_tx.clone(), shutdown.clone())?;
    } else {
        // Auto-discovery mode: start lifecycle watcher in a background thread.
        let lc_shutdown = shutdown.clone();
        std::thread::Builder::new()
            .name("sandtrace-lifecycle".to_string())
            .spawn(move || {
                if let Err(e) = provider.watch_lifecycle(lifecycle_tx, lc_shutdown) {
                    tracing::error!(error = %e, "lifecycle watcher failed");
                }
            })?;
    }

    let policy_rules = policy.as_ref().map(|p| p.rules.len()).unwrap_or(0);

    // Wait briefly for initial discovery before printing banner.
    if !single_mode {
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Process initial lifecycle events.
        while let Ok(event) = lifecycle_rx.try_recv() {
            match event {
                sandtrace_provider::LifecycleEvent::Attached(info) => {
                    pretty::print_attach(&info.sandbox_id);
                    if let Err(e) = tracker.attach(info, capture_tx.clone(), shutdown.clone()) {
                        tracing::warn!(error = %e, "failed to attach");
                    }
                }
                sandtrace_provider::LifecycleEvent::Detached { sandbox_id } => {
                    pretty::print_detach(&sandbox_id);
                    tracker.remove(&sandbox_id);
                }
            }
        }
    }

    pretty::print_banner(&tracker.active_ids(), &provider_name, policy_rules, &output);

    let mut stats = pretty::WatchStats::default();
    let mut seq: u64 = 1;
    let mut prev_hash: Option<String> = None;

    // Main event loop: process lifecycle and capture events.
    loop {
        // Process lifecycle events (non-blocking).
        while let Ok(event) = lifecycle_rx.try_recv() {
            match event {
                sandtrace_provider::LifecycleEvent::Attached(info) => {
                    pretty::print_attach(&info.sandbox_id);
                    if let Err(e) = tracker.attach(info, capture_tx.clone(), shutdown.clone()) {
                        tracing::warn!(error = %e, "failed to attach to new sandbox");
                    }
                }
                sandtrace_provider::LifecycleEvent::Detached { sandbox_id } => {
                    pretty::print_detach(&sandbox_id);
                    tracker.remove(&sandbox_id);
                }
            }
        }

        // Process capture events (with timeout for shutdown checks).
        match capture_rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(captured) => {
                let event_type_str = event_type_to_str(&captured.event_type);
                let evidence_tier = evidence_tier_for(&captured.event_type);

                let verdict = if let Some(ref mut eng) = engine {
                    let tmp = sandtrace_audit_chain::build_event(
                        event_type_str,
                        &captured.sandbox_id,
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
                            &captured.sandbox_id,
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
                    &captured.sandbox_id,
                    &captured.trace_id,
                    seq,
                    prev_hash.clone(),
                    evidence_tier,
                    captured.payload,
                    verdict,
                );

                prev_hash = Some(audit_event.record_hash.clone());
                seq += 1;

                pretty::print_event(&audit_event, multi);
                stats.record(&audit_event);
                stream.emit(&audit_event).await?;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        }

        // Reap finished capture threads (safety net).
        for id in tracker.reap() {
            pretty::print_detach(&id);
        }

        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!("shutdown signal received, flushing");
            break;
        }
    }

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    tracker.join_all();

    stream.flush().await?;
    stream.close().await?;

    pretty::print_summary(&stats, &output);
    Ok(())
}

/// Manages active capture threads for discovered sandboxes.
struct SandboxTracker {
    active: HashMap<String, std::thread::JoinHandle<()>>,
}

impl SandboxTracker {
    fn new() -> Self {
        Self {
            active: HashMap::new(),
        }
    }

    /// Spawn a capture thread for a sandbox and track it.
    fn attach(
        &mut self,
        info: sandtrace_provider::SandboxInfo,
        tx: std::sync::mpsc::Sender<sandtrace_capture::CapturedEvent>,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        let sandbox_id = info.sandbox_id.clone();
        let handle = std::thread::Builder::new()
            .name(format!("sandtrace-{}", sandbox_id))
            .spawn(move || {
                if let Err(e) =
                    info.provider
                        .attach_streaming(&info.sandbox_id, tx, shutdown)
                {
                    tracing::error!(
                        sandbox_id = %info.sandbox_id,
                        error = %e,
                        "capture failed"
                    );
                }
            })?;
        self.active.insert(sandbox_id, handle);
        Ok(())
    }

    /// Check for finished threads and remove them. Returns detached sandbox IDs.
    fn reap(&mut self) -> Vec<String> {
        let finished: Vec<String> = self
            .active
            .iter()
            .filter(|(_, h)| h.is_finished())
            .map(|(id, _)| id.clone())
            .collect();

        for id in &finished {
            if let Some(handle) = self.active.remove(id) {
                let _ = handle.join();
                tracing::info!(sandbox_id = %id, "sandbox capture thread finished");
            }
        }

        finished
    }

    /// Remove a sandbox and join its thread.
    fn remove(&mut self, sandbox_id: &str) {
        if let Some(handle) = self.active.remove(sandbox_id) {
            let _ = handle.join();
        }
    }

    /// Get sorted list of active sandbox IDs.
    fn active_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.active.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Wait for all threads to finish.
    fn join_all(&mut self) {
        for (_, handle) in self.active.drain() {
            let _ = handle.join();
        }
    }
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
