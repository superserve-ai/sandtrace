//! Auto-detection of the sandbox provider in the current environment.
//!
//! Probes well-known paths and environment variables to determine which
//! provider adapter to use. Detection order: E2B, Daytona, then falls
//! back to generic Firecracker.

use crate::SandboxProvider;

/// Detected provider kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    E2b,
    Daytona,
    Firecracker,
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderKind::E2b => write!(f, "e2b"),
            ProviderKind::Daytona => write!(f, "daytona"),
            ProviderKind::Firecracker => write!(f, "firecracker"),
        }
    }
}

/// Detect which provider is active by probing the environment.
///
/// Checks in order: E2B, Daytona. Falls back to generic Firecracker
/// if none of the provider-specific markers are found.
///
/// Also checks environment variables:
/// - `SANDTRACE_PROVIDER` — explicit override (e2b, daytona, firecracker)
/// - `E2B_SANDBOX_ID` — E2B runtime indicator
/// - `DAYTONA_WS_ID` — Daytona runtime indicator
pub fn detect_provider() -> ProviderKind {
    // Explicit override via environment variable.
    if let Ok(val) = std::env::var("SANDTRACE_PROVIDER") {
        match val.to_lowercase().as_str() {
            "e2b" => return ProviderKind::E2b,
            "daytona" => return ProviderKind::Daytona,
            "firecracker" => return ProviderKind::Firecracker,
            _ => {
                tracing::warn!(provider = %val, "unknown SANDTRACE_PROVIDER value, auto-detecting");
            }
        }
    }

    // Environment variable hints from provider runtimes.
    if std::env::var("E2B_SANDBOX_ID").is_ok() {
        return ProviderKind::E2b;
    }
    if std::env::var("DAYTONA_WS_ID").is_ok() {
        return ProviderKind::Daytona;
    }

    // Filesystem probes.
    if crate::e2b::detect() {
        return ProviderKind::E2b;
    }
    if crate::daytona::detect() {
        return ProviderKind::Daytona;
    }
    ProviderKind::Firecracker
}

/// Create a default-configured provider based on auto-detection.
///
/// Returns a boxed `SandboxProvider` using the detected provider's
/// default configuration. For custom configuration, instantiate the
/// provider structs directly.
pub fn create_default_provider() -> Box<dyn SandboxProvider> {
    let kind = detect_provider();
    create_provider(kind)
}

/// Create a default-configured provider for the given kind.
pub fn create_provider(kind: ProviderKind) -> Box<dyn SandboxProvider> {
    tracing::info!(provider = %kind, "creating provider adapter");

    match kind {
        ProviderKind::E2b => Box::new(crate::e2b::E2bProvider::default()),
        ProviderKind::Daytona => Box::new(crate::daytona::DaytonaProvider::default()),
        ProviderKind::Firecracker => Box::new(crate::firecracker::FirecrackerProvider {
            socket_path: std::env::var("SANDTRACE_FC_SOCKET")
                .unwrap_or_else(|_| "/run/firecracker.socket".to_string()),
            tap_device: std::env::var("SANDTRACE_TAP_DEVICE")
                .unwrap_or_else(|_| "tap0".to_string()),
            overlay_upper_dir: std::env::var("SANDTRACE_OVERLAY_DIR")
                .unwrap_or_else(|_| "/overlay/upper".to_string()),
            jailer_pid: std::env::var("SANDTRACE_JAILER_PID")
                .ok()
                .and_then(|s| s.parse().ok()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clear all detection-relevant env vars to avoid cross-test pollution.
    fn clean_env() {
        std::env::remove_var("SANDTRACE_PROVIDER");
        std::env::remove_var("E2B_SANDBOX_ID");
        std::env::remove_var("DAYTONA_WS_ID");
    }

    #[test]
    fn display_provider_kinds() {
        assert_eq!(ProviderKind::E2b.to_string(), "e2b");
        assert_eq!(ProviderKind::Daytona.to_string(), "daytona");
        assert_eq!(ProviderKind::Firecracker.to_string(), "firecracker");
    }

    // Note: env-var-based detection tests are combined into a single test
    // to avoid races from parallel test execution (env vars are process-global).
    #[test]
    fn detect_env_var_precedence() {
        // Explicit override takes highest priority.
        clean_env();
        std::env::set_var("SANDTRACE_PROVIDER", "daytona");
        std::env::set_var("E2B_SANDBOX_ID", "sb-test"); // should be ignored
        assert_eq!(detect_provider(), ProviderKind::Daytona);

        // E2B env var detection.
        clean_env();
        std::env::set_var("E2B_SANDBOX_ID", "sb-test");
        assert_eq!(detect_provider(), ProviderKind::E2b);

        // Daytona env var detection.
        clean_env();
        std::env::set_var("DAYTONA_WS_ID", "ws-test");
        assert_eq!(detect_provider(), ProviderKind::Daytona);

        // Fallback to Firecracker when nothing is set.
        clean_env();
        assert_eq!(detect_provider(), ProviderKind::Firecracker);

        clean_env();
    }

    #[test]
    fn create_provider_returns_correct_name() {
        let p = create_provider(ProviderKind::E2b);
        assert_eq!(p.name(), "e2b");

        let p = create_provider(ProviderKind::Daytona);
        assert_eq!(p.name(), "daytona");

        let p = create_provider(ProviderKind::Firecracker);
        assert_eq!(p.name(), "firecracker");
    }
}
