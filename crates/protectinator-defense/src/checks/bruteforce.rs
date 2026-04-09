//! Brute-force protection check
//!
//! Detects if sshguard, fail2ban, or crowdsec is installed and running.

use crate::audit::HostContext;
use protectinator_core::{Finding, FindingSource, Severity};

pub fn check_bruteforce(run: &dyn Fn(&str) -> Option<String>, ctx: &HostContext) -> Vec<Finding> {
    let services = ["sshguard", "fail2ban", "crowdsec"];

    for service in &services {
        if let Some(output) = run(&format!("systemctl is-active {} 2>/dev/null", service)) {
            if output.trim() == "active" {
                return Vec::new(); // At least one is running
            }
        }
    }

    // Check if any are installed but not running
    for service in &services {
        if let Some(output) = run(&format!("systemctl is-enabled {} 2>/dev/null", service)) {
            if output.trim() == "disabled" || output.trim() == "enabled" {
                return vec![Finding::new(
                    "defense-bruteforce-inactive",
                    format!("{} installed but not running on {}", service, ctx.name),
                    format!("{} is installed but not active. Run 'sudo systemctl enable --now {}' to start it.", service, service),
                    ctx.escalate_severity(Severity::Medium),
                    FindingSource::Defense {
                        check_category: "bruteforce_protection".to_string(),
                        host: Some(ctx.name.clone()),
                    },
                )
                .with_resource(format!("host:{}", ctx.name))
                .with_remediation(format!("sudo systemctl enable --now {}", service))];
            }
        }
    }

    // None installed
    // Only flag if SSH is likely exposed (check if sshd is running)
    let ssh_running = run("systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null")
        .map(|o| o.trim().contains("active"))
        .unwrap_or(false);

    if ssh_running {
        vec![Finding::new(
            "defense-no-bruteforce",
            format!("No brute-force protection on {}", ctx.name),
            "SSH is running but no brute-force protection detected (checked sshguard, fail2ban, crowdsec). \
             Install sshguard: 'sudo apt install sshguard' (lightweight, no Python dependency)."
                .to_string(),
            ctx.escalate_severity(Severity::High),
            FindingSource::Defense {
                check_category: "bruteforce_protection".to_string(),
                host: Some(ctx.name.clone()),
            },
        )
        .with_resource(format!("host:{}", ctx.name))
        .with_remediation("sudo apt install -y sshguard && sudo systemctl enable --now sshguard")]
    } else {
        Vec::new() // No SSH, no need for brute-force protection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sshguard_active_no_finding() {
        let run = |cmd: &str| -> Option<String> {
            if cmd.contains("sshguard") && cmd.contains("is-active") {
                Some("active\n".to_string())
            } else {
                None
            }
        };
        let ctx = HostContext { name: "test".into(), tags: vec![], allowed_services: vec![] };
        assert!(check_bruteforce(&run, &ctx).is_empty());
    }

    #[test]
    fn test_no_protection_ssh_running() {
        let run = |cmd: &str| -> Option<String> {
            // Only respond to the SSH running check, not individual service checks
            if cmd.contains("is-active sshd") && cmd.contains("is-active ssh 2") {
                Some("active\n".to_string())
            } else {
                None
            }
        };
        let ctx = HostContext { name: "test".into(), tags: vec![], allowed_services: vec![] };
        let findings = check_bruteforce(&run, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "defense-no-bruteforce");
    }

    #[test]
    fn test_no_protection_no_ssh_no_finding() {
        let run = |_cmd: &str| -> Option<String> { None };
        let ctx = HostContext { name: "test".into(), tags: vec![], allowed_services: vec![] };
        assert!(check_bruteforce(&run, &ctx).is_empty());
    }
}
