// Copyright 2026 Superserve AI. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Human-readable terminal output for sandtrace watch.

use std::collections::HashMap;

use sandtrace_audit_chain::AuditEvent;

/// Per-sandbox counters.
#[derive(Default)]
pub struct SandboxStats {
    pub total: u64,
    pub deny: u64,
    pub anomaly: u64,
}

/// Counters for the summary at the end.
#[derive(Default)]
pub struct WatchStats {
    pub total: u64,
    pub allow: u64,
    pub deny: u64,
    pub anomaly: u64,
    pub deny_details: Vec<String>,
    pub anomaly_details: Vec<String>,
    pub per_sandbox: HashMap<String, SandboxStats>,
}

impl WatchStats {
    pub fn record(&mut self, event: &AuditEvent) {
        self.total += 1;
        let sb = self
            .per_sandbox
            .entry(event.sandbox_id.clone())
            .or_default();
        sb.total += 1;

        if let Some(v) = &event.verdict {
            match v.result.as_str() {
                "allow" => self.allow += 1,
                "deny" => {
                    self.deny += 1;
                    sb.deny += 1;
                    self.deny_details
                        .push(format!("[{}] {} — {}", event.sandbox_id, v.policy_rule, v.reason));
                }
                "anomaly" => {
                    self.anomaly += 1;
                    sb.anomaly += 1;
                    self.anomaly_details
                        .push(format!("[{}] {} — {}", event.sandbox_id, v.policy_rule, v.reason));
                }
                _ => self.allow += 1,
            }
        } else {
            self.allow += 1;
        }
    }
}

/// Truncate a sandbox ID for display (max 12 chars).
fn short_id(id: &str) -> &str {
    if id.len() <= 12 {
        id
    } else {
        &id[..12]
    }
}

/// Print the banner when watching starts.
pub fn print_banner(sandbox_ids: &[String], provider: &str, policy_rules: usize, output: &str) {
    eprintln!();
    eprintln!("  \x1b[1msandtrace\x1b[0m v0.1.0 — hypervisor-level audit trail");
    if sandbox_ids.len() == 1 {
        eprintln!("  sandbox:  {}", sandbox_ids[0]);
    } else {
        eprintln!("  sandboxes: {} discovered", sandbox_ids.len());
        for id in sandbox_ids {
            eprintln!("    - {id}");
        }
    }
    eprintln!("  provider: {provider}");
    if policy_rules > 0 {
        eprintln!("  policy:   {policy_rules} rules loaded");
    } else {
        eprintln!("  policy:   none (all events logged without evaluation)");
    }
    eprintln!("  output:   {output}");
    eprintln!();
    eprintln!("  watching... (Ctrl+C to stop)");
    eprintln!();
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!();
}

/// Print a single event in human-readable format.
pub fn print_event(event: &AuditEvent, multi: bool) {
    let time = &event.wall_time[11..19]; // HH:MM:SS from ISO timestamp
    let label = if multi {
        format!("\x1b[36m{}\x1b[0m  ", short_id(&event.sandbox_id))
    } else {
        String::new()
    };

    let (icon, color) = match event.verdict.as_ref().map(|v| v.result.as_str()) {
        Some("deny") => ("✗", "\x1b[31m"),   // red
        Some("anomaly") => ("⚠", "\x1b[33m"), // yellow
        _ => ("✓", "\x1b[32m"),               // green
    };

    match event.event_type.as_str() {
        "network_egress" => print_network_event(event, time, &label, icon, color),
        "filesystem_summary" => print_filesystem_event(event, time, &label, icon, color),
        "syscall_activity" => print_syscall_event(event, time, &label, icon, color),
        _ => {
            eprintln!("  {time}  {color}{icon}\x1b[0m  {label}{}", event.event_type);
        }
    }

    // Print verdict reason for deny/anomaly
    if let Some(v) = &event.verdict {
        if v.result == "deny" || v.result == "anomaly" {
            let result_label = v.result.to_uppercase();
            eprintln!("  {color}         {result_label}\x1b[0m  {}", v.reason);
        }
    }
}

fn print_network_event(event: &AuditEvent, time: &str, label: &str, icon: &str, color: &str) {
    let p = &event.payload;
    let host = p.get("dest_host").and_then(|v| v.as_str()).unwrap_or("?");
    let port = p.get("dest_port").and_then(|v| v.as_u64()).unwrap_or(0);
    let sent = p.get("bytes_sent").and_then(|v| v.as_u64()).unwrap_or(0);
    let recv = p.get("bytes_received").and_then(|v| v.as_u64()).unwrap_or(0);

    eprintln!(
        "  {time}  {color}{icon}\x1b[0m  {label}network     {host}:{port}{}{}",
        format_bytes_arrow(sent, "↑"),
        format_bytes_arrow(recv, "↓"),
    );
}

fn print_filesystem_event(event: &AuditEvent, time: &str, label: &str, icon: &str, color: &str) {
    let p = &event.payload;
    let created = p
        .get("files_created")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let modified = p
        .get("files_modified")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let deleted = p
        .get("files_deleted")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let bytes = p
        .get("total_bytes_written")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut parts = Vec::new();
    if created > 0 {
        parts.push(format!("+{created}"));
    }
    if modified > 0 {
        parts.push(format!("~{modified}"));
    }
    if deleted > 0 {
        parts.push(format!("-{deleted}"));
    }

    eprintln!(
        "  {time}  {color}{icon}\x1b[0m  {label}filesystem  {} files  {}",
        parts.join(" "),
        format_bytes(bytes),
    );

    // Show individual file details
    if let Some(files) = p.get("files_created").and_then(|v| v.as_array()) {
        for f in files.iter().take(5) {
            if let Some(path) = f.get("path").and_then(|v| v.as_str()) {
                let size = f.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                eprintln!("                          + {path} ({})", format_bytes(size));
            }
        }
    }
    if let Some(files) = p.get("files_modified").and_then(|v| v.as_array()) {
        for f in files.iter().take(5) {
            if let Some(path) = f.get("path").and_then(|v| v.as_str()) {
                eprintln!("                          ~ {path}");
            }
        }
    }
}

fn print_syscall_event(event: &AuditEvent, time: &str, label: &str, icon: &str, color: &str) {
    let p = &event.payload;
    let total = p
        .get("total_syscalls")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let suspicious = p
        .get("suspicious")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    eprintln!(
        "  {time}  {color}{icon}\x1b[0m  {label}syscall     {total} calls, {suspicious} suspicious",
    );

    if let Some(sus) = p.get("suspicious").and_then(|v| v.as_array()) {
        for s in sus.iter().take(3) {
            if let Some(name) = s.as_str() {
                eprintln!("                          ! {name}");
            }
        }
    }
}

/// Print the summary at the end of a watch session.
pub fn print_summary(stats: &WatchStats, output: &str) {
    let multi = stats.per_sandbox.len() > 1;

    eprintln!();
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!();
    if multi {
        eprintln!(
            "  \x1b[1msummary\x1b[0m ({} sandboxes)",
            stats.per_sandbox.len()
        );
    } else {
        eprintln!("  \x1b[1msummary\x1b[0m");
    }
    eprintln!("  ───────");
    eprintln!("  events:     {}", stats.total);
    eprintln!("  \x1b[32mallow\x1b[0m:      {}", stats.allow);

    if stats.anomaly > 0 {
        eprintln!("  \x1b[33manomaly\x1b[0m:    {}", stats.anomaly);
        for d in &stats.anomaly_details {
            eprintln!("              {d}");
        }
    }

    if stats.deny > 0 {
        eprintln!("  \x1b[31mdeny\x1b[0m:       {}", stats.deny);
        for d in &stats.deny_details {
            eprintln!("              {d}");
        }
    }

    // Per-sandbox breakdown for multi-VM mode
    if multi {
        eprintln!();
        eprintln!("  \x1b[1mper-sandbox\x1b[0m");
        let mut ids: Vec<&String> = stats.per_sandbox.keys().collect();
        ids.sort();
        for id in ids {
            let sb = &stats.per_sandbox[id];
            let status = if sb.deny > 0 {
                format!("\x1b[31m{} deny\x1b[0m", sb.deny)
            } else if sb.anomaly > 0 {
                format!("\x1b[33m{} anomaly\x1b[0m", sb.anomaly)
            } else {
                "\x1b[32mclean\x1b[0m".to_string()
            };
            eprintln!("    {id}: {} events, {status}", sb.total);
        }
    }

    eprintln!("  chain:      {}/{} hashes", stats.total, stats.total);
    eprintln!("  output:     {output}");
    eprintln!();
    eprintln!("  run `sandtrace verify {output}` to re-check integrity");
    eprintln!();
}

fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b}B")
    } else if b < 1024 * 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{:.1}MB", b as f64 / (1024.0 * 1024.0))
    }
}

fn format_bytes_arrow(b: u64, arrow: &str) -> String {
    if b == 0 {
        String::new()
    } else {
        format!("  {}{arrow}", format_bytes(b))
    }
}
