//! Defense audit orchestrator
//!
//! Runs all defense checks against a host (locally or via SSH)
//! and returns aggregated findings.

use crate::checks;
use protectinator_core::{Finding, Severity};
use protectinator_remote::types::RemoteHost;
use protectinator_remote::ssh;
use tracing::{info, debug};

/// Context about the host being audited (for severity decisions)
pub struct HostContext {
    /// Host name
    pub name: String,
    /// Tags from fleet config (e.g., "external", "internal")
    pub tags: Vec<String>,
    /// Allowed services from fleet config (e.g., "ssh:22", "http:8090")
    pub allowed_services: Vec<String>,
}

impl HostContext {
    /// Whether this host is tagged as external-facing
    pub fn is_external(&self) -> bool {
        self.tags.iter().any(|t| t == "external")
    }

    /// Severity escalation: external hosts get higher severity
    pub fn escalate_severity(&self, base: Severity) -> Severity {
        if self.is_external() {
            match base {
                Severity::Medium => Severity::High,
                Severity::High => Severity::Critical,
                other => other,
            }
        } else {
            base
        }
    }
}

/// Result of a defense audit
pub struct DefenseAuditResult {
    pub host: String,
    pub findings: Vec<Finding>,
}

/// Run defense audit checks
pub struct DefenseAudit;

impl DefenseAudit {
    /// Audit a remote host via SSH
    pub fn audit_remote(host: &RemoteHost, ctx: &HostContext) -> DefenseAuditResult {
        info!("Running defense audit on {}", ctx.name);
        let mut findings = Vec::new();

        // Helper closure to run commands via SSH
        let run = |cmd: &str| -> Option<String> {
            match ssh::ssh_exec(host, cmd) {
                Ok(output) => Some(output),
                Err(e) => {
                    debug!("SSH command failed on {}: {}: {}", ctx.name, cmd, e);
                    None
                }
            }
        };

        // 1. Firewall status
        findings.extend(checks::firewall::check_firewall(&run, ctx));

        // 2. Brute-force protection
        findings.extend(checks::bruteforce::check_bruteforce(&run, ctx));

        // 3. Open ports vs allowed services
        if !ctx.allowed_services.is_empty() {
            findings.extend(checks::open_ports::check_open_ports(&run, ctx));
        }

        // 4. Unattended upgrades
        findings.extend(checks::auto_updates::check_auto_updates(&run, ctx));

        DefenseAuditResult {
            host: ctx.name.clone(),
            findings,
        }
    }

    /// Audit the local host
    pub fn audit_local(ctx: &HostContext) -> DefenseAuditResult {
        info!("Running local defense audit");
        let mut findings = Vec::new();

        // Helper closure to run commands locally
        let run = |cmd: &str| -> Option<String> {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                }
                Ok(o) => {
                    // Some commands return non-zero for "inactive" states
                    let combined = format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                    Some(combined)
                }
                Err(e) => {
                    debug!("Local command failed: {}: {}", cmd, e);
                    None
                }
            }
        };

        findings.extend(checks::firewall::check_firewall(&run, ctx));
        findings.extend(checks::bruteforce::check_bruteforce(&run, ctx));
        if !ctx.allowed_services.is_empty() {
            findings.extend(checks::open_ports::check_open_ports(&run, ctx));
        }
        findings.extend(checks::auto_updates::check_auto_updates(&run, ctx));

        DefenseAuditResult {
            host: ctx.name.clone(),
            findings,
        }
    }
}
