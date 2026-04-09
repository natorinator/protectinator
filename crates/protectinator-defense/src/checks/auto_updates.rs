//! Automatic security update check
//!
//! Detects if automatic security updates are configured.

use crate::audit::HostContext;
use protectinator_core::{Finding, FindingSource, Severity};

pub fn check_auto_updates(run: &dyn Fn(&str) -> Option<String>, ctx: &HostContext) -> Vec<Finding> {
    // Check for unattended-upgrades (Debian/Ubuntu)
    if let Some(output) = run("systemctl is-enabled unattended-upgrades 2>/dev/null || dpkg -l unattended-upgrades 2>/dev/null") {
        if output.contains("enabled") || output.contains("ii  unattended-upgrades") {
            return Vec::new(); // Configured
        }
    }

    // Check for dnf-automatic (Fedora/RHEL)
    if let Some(output) = run("systemctl is-enabled dnf-automatic.timer 2>/dev/null") {
        if output.trim() == "enabled" {
            return Vec::new();
        }
    }

    // Check for apt-daily-upgrade timer (alternative Debian method)
    if let Some(output) = run("systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null") {
        if output.trim() == "enabled" {
            return Vec::new();
        }
    }

    vec![Finding::new(
        "defense-no-auto-updates",
        format!("No automatic security updates on {}", ctx.name),
        "No automatic security update mechanism detected. Security patches won't be applied \
         until manually updated. Install unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora)."
            .to_string(),
        ctx.escalate_severity(Severity::Medium),
        FindingSource::Defense {
            check_category: "auto_updates".to_string(),
            host: Some(ctx.name.clone()),
        },
    )
    .with_resource(format!("host:{}", ctx.name))
    .with_remediation("sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unattended_upgrades_enabled() {
        let run = |cmd: &str| -> Option<String> {
            if cmd.contains("unattended-upgrades") {
                Some("enabled\n".to_string())
            } else {
                None
            }
        };
        let ctx = HostContext { name: "test".into(), tags: vec![], allowed_services: vec![] };
        assert!(check_auto_updates(&run, &ctx).is_empty());
    }

    #[test]
    fn test_no_auto_updates() {
        let run = |_cmd: &str| -> Option<String> { None };
        let ctx = HostContext { name: "test".into(), tags: vec![], allowed_services: vec![] };
        let findings = check_auto_updates(&run, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "defense-no-auto-updates");
    }
}
