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

        /// Output file for JSONL audit events (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,
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

    /// Run the demo scenario showing exfiltration detection
    Demo {
        /// Scenario to run
        #[arg(default_value = "stripe-exfil")]
        scenario: String,
    },
}

fn main() -> Result<()> {
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
        } => cmd_watch(sandbox_id, output, policy),
        Command::Verify { path, against, json } => {
            let verify_policy = match against {
                Some(ref p) => Some(sandtrace_policy::load_policy_file(p)?),
                None => policy,
            };
            cmd_verify(path, verify_policy, json)
        }
        Command::Demo { scenario } => cmd_demo(scenario),
    }
}

fn cmd_watch(
    sandbox_id: String,
    output: Option<String>,
    policy: Option<sandtrace_policy::PolicyManifest>,
) -> Result<()> {
    tracing::info!(sandbox_id, "attaching to sandbox");

    if let Some(policy) = &policy {
        tracing::info!(rules = policy.rules.len(), "loaded policy");
    }

    let _output = output.as_deref().unwrap_or("-");

    // Placeholder: real implementation will attach to Firecracker tap
    // interface, mount overlay fs, and install seccomp-bpf filters.
    tracing::warn!("watch command is not yet implemented — capture crates pending");
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
