//! Firewall status check
//!
//! Detects active firewall (ufw, firewalld, nftables, iptables)
//! and reports missing or inactive firewall configuration.

use crate::audit::HostContext;
use protectinator_core::{Finding, FindingSource, Severity};

/// Check firewall status
/// `run` executes a shell command and returns stdout, or None on failure
pub fn check_firewall(run: &dyn Fn(&str) -> Option<String>, ctx: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try ufw first
    if let Some(output) = run("ufw status 2>/dev/null") {
        let status = parse_ufw_status(&output);
        match status {
            FirewallStatus::Active { rules } => {
                // Check for overly permissive rules
                for rule in &rules {
                    if rule.contains("ALLOW") && rule.contains("Anywhere") && !rule.contains("22") {
                        findings.push(make_finding(
                            "defense-firewall-permissive-rule",
                            format!("Overly permissive firewall rule on {}", ctx.name),
                            format!("ufw rule allows traffic from anywhere: {}", rule.trim()),
                            ctx.escalate_severity(Severity::Medium),
                            &ctx.name,
                        ));
                    }
                }
                return findings; // Firewall is active, done
            }
            FirewallStatus::Inactive => {
                findings.push(make_finding(
                    "defense-firewall-inactive",
                    format!("Firewall installed but inactive on {}", ctx.name),
                    "ufw is installed but not enabled. Run 'sudo ufw enable' to activate.".to_string(),
                    ctx.escalate_severity(Severity::High),
                    &ctx.name,
                ));
                return findings;
            }
            FirewallStatus::NotInstalled => {} // Try next
        }
    }

    // Try firewalld
    if let Some(output) = run("firewall-cmd --state 2>/dev/null") {
        if output.trim() == "running" {
            return findings; // Active, done
        }
        if output.contains("not running") {
            findings.push(make_finding(
                "defense-firewall-inactive",
                format!("Firewall installed but inactive on {}", ctx.name),
                "firewalld is installed but not running. Run 'sudo systemctl enable --now firewalld' to activate.".to_string(),
                ctx.escalate_severity(Severity::High),
                &ctx.name,
            ));
            return findings;
        }
    }

    // Try nftables
    if let Some(output) = run("nft list ruleset 2>/dev/null") {
        if !output.trim().is_empty() && output.contains("chain") {
            return findings; // Has rules, consider active
        }
    }

    // Try iptables
    if let Some(output) = run("iptables -L -n 2>/dev/null") {
        // Check if there are any non-default rules
        let has_rules = output.lines()
            .filter(|l| !l.starts_with("Chain") && !l.starts_with("target") && !l.is_empty())
            .count() > 0;
        if has_rules {
            return findings; // Has rules
        }
    }

    // No firewall found
    findings.push(make_finding(
        "defense-no-firewall",
        format!("No active firewall on {}", ctx.name),
        "No firewall detected (checked ufw, firewalld, nftables, iptables). \
         Install and enable a firewall to restrict inbound traffic."
            .to_string(),
        ctx.escalate_severity(Severity::Critical),
        &ctx.name,
    ));

    findings
}

#[derive(Debug)]
enum FirewallStatus {
    Active { rules: Vec<String> },
    Inactive,
    NotInstalled,
}

fn parse_ufw_status(output: &str) -> FirewallStatus {
    if output.contains("Status: active") {
        let rules: Vec<String> = output
            .lines()
            .skip_while(|l| !l.contains("---"))
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();
        FirewallStatus::Active { rules }
    } else if output.contains("Status: inactive") {
        FirewallStatus::Inactive
    } else {
        FirewallStatus::NotInstalled
    }
}

fn make_finding(id: &str, title: String, description: String, severity: Severity, host: &str) -> Finding {
    Finding::new(id, title, description, severity, FindingSource::Defense {
        check_category: "firewall".to_string(),
        host: Some(host.to_string()),
    })
    .with_resource(format!("host:{}", host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ufw_active() {
        let output = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere\n22/tcp (v6)                ALLOW       Anywhere (v6)";
        match parse_ufw_status(output) {
            FirewallStatus::Active { rules } => {
                assert_eq!(rules.len(), 3);
                assert!(rules[0].contains("22/tcp"));
            }
            other => panic!("Expected Active, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_ufw_inactive() {
        let output = "Status: inactive";
        match parse_ufw_status(output) {
            FirewallStatus::Inactive => {}
            other => panic!("Expected Inactive, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_ufw_not_installed() {
        let output = ""; // command returned empty or failed
        match parse_ufw_status(output) {
            FirewallStatus::NotInstalled => {}
            other => panic!("Expected NotInstalled, got {:?}", other),
        }
    }

    #[test]
    fn test_no_firewall_finding() {
        let run = |_cmd: &str| -> Option<String> { None }; // all commands fail
        let ctx = HostContext {
            name: "testhost".to_string(),
            tags: vec![],
            allowed_services: vec![],
        };
        let findings = check_firewall(&run, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "defense-no-firewall");
    }

    #[test]
    fn test_no_firewall_external_escalation() {
        let run = |_cmd: &str| -> Option<String> { None };
        let ctx = HostContext {
            name: "external-host".to_string(),
            tags: vec!["external".to_string()],
            allowed_services: vec![],
        };
        let findings = check_firewall(&run, &ctx);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_firewall_active_no_finding() {
        let run = |cmd: &str| -> Option<String> {
            if cmd.contains("ufw status") {
                Some("Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere".to_string())
            } else {
                None
            }
        };
        let ctx = HostContext {
            name: "testhost".to_string(),
            tags: vec![],
            allowed_services: vec![],
        };
        let findings = check_firewall(&run, &ctx);
        assert!(findings.is_empty());
    }
}
