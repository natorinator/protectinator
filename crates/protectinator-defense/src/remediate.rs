//! Remediation plan generation and storage
//!
//! Maps defense audit findings to concrete fix actions.
//! Plans are stored in the DB for review before execution.

use crate::checks::open_ports::parse_allowed_service;
use protectinator_core::Finding;
use serde::{Deserialize, Serialize};

/// A remediation plan for a host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub id: Option<i64>,
    pub host: String,
    pub created_at: String,
    pub status: PlanStatus,
    pub actions: Vec<RemediationAction>,
    pub source_findings: Vec<String>, // finding IDs that generated this plan
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Pending,
    Approved,
    Executing,
    Done,
    Failed,
}

impl std::fmt::Display for PlanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanStatus::Pending => write!(f, "pending"),
            PlanStatus::Approved => write!(f, "approved"),
            PlanStatus::Executing => write!(f, "executing"),
            PlanStatus::Done => write!(f, "done"),
            PlanStatus::Failed => write!(f, "failed"),
        }
    }
}

/// A single remediation action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemediationAction {
    InstallPackage {
        package: String,
        description: String,
    },
    EnableService {
        service: String,
        description: String,
    },
    FirewallAllow {
        port: u16,
        protocol: String,
        comment: String,
    },
    FirewallEnable {
        description: String,
    },
    ConfigChange {
        file: String,
        setting: String,
        value: String,
        description: String,
    },
    RunCommand {
        command: String,
        description: String,
    },
}

impl RemediationAction {
    /// Generate the shell command for this action
    pub fn to_command(&self) -> String {
        match self {
            RemediationAction::InstallPackage { package, .. } => {
                format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y {}",
                    package
                )
            }
            RemediationAction::EnableService { service, .. } => {
                format!("systemctl enable --now {}", service)
            }
            RemediationAction::FirewallAllow {
                port,
                protocol,
                comment,
            } => {
                format!("ufw allow {}/{} comment '{}'", port, protocol, comment)
            }
            RemediationAction::FirewallEnable { .. } => "ufw --force enable".to_string(),
            RemediationAction::ConfigChange {
                file,
                setting,
                value,
                ..
            } => {
                // Use sed to set/replace a config value
                format!(
                    "sed -i 's/^#*{}\\s.*/{} {}/' {} || echo '{} {}' >> {}",
                    setting, setting, value, file, setting, value, file
                )
            }
            RemediationAction::RunCommand { command, .. } => command.clone(),
        }
    }

    /// Human-readable description
    pub fn describe(&self) -> &str {
        match self {
            RemediationAction::InstallPackage { description, .. } => description,
            RemediationAction::EnableService { description, .. } => description,
            RemediationAction::FirewallAllow { comment, .. } => comment,
            RemediationAction::FirewallEnable { description } => description,
            RemediationAction::ConfigChange { description, .. } => description,
            RemediationAction::RunCommand { description, .. } => description,
        }
    }
}

/// Generate a remediation plan from defense audit findings
pub fn generate_plan(
    host: &str,
    findings: &[Finding],
    allowed_services: &[String],
) -> Option<RemediationPlan> {
    let mut actions = Vec::new();
    let mut source_ids = Vec::new();

    for finding in findings {
        // Only process defense findings
        if !finding.id.starts_with("defense-") {
            continue;
        }

        source_ids.push(finding.id.clone());

        match finding.id.as_str() {
            "defense-no-firewall" => {
                // Install ufw
                actions.push(RemediationAction::InstallPackage {
                    package: "ufw".to_string(),
                    description: "Install ufw firewall".to_string(),
                });
                // SSH first -- ALWAYS
                actions.push(RemediationAction::FirewallAllow {
                    port: 22,
                    protocol: "tcp".to_string(),
                    comment: "Allow SSH (safety: added first)".to_string(),
                });
                // Then allowed services
                for svc_str in allowed_services {
                    if let Some(svc) = parse_allowed_service(svc_str) {
                        if svc.port != 22 {
                            // SSH already added
                            actions.push(RemediationAction::FirewallAllow {
                                port: svc.port,
                                protocol: svc.protocol.clone(),
                                comment: format!("Allow {} (from fleet config)", svc.name),
                            });
                        }
                    }
                }
                // Enable
                actions.push(RemediationAction::FirewallEnable {
                    description: "Enable ufw with default deny incoming".to_string(),
                });
            }
            "defense-firewall-inactive" => {
                // SSH first
                actions.push(RemediationAction::FirewallAllow {
                    port: 22,
                    protocol: "tcp".to_string(),
                    comment: "Allow SSH (safety: added first)".to_string(),
                });
                // Allowed services
                for svc_str in allowed_services {
                    if let Some(svc) = parse_allowed_service(svc_str) {
                        if svc.port != 22 {
                            actions.push(RemediationAction::FirewallAllow {
                                port: svc.port,
                                protocol: svc.protocol.clone(),
                                comment: format!("Allow {} (from fleet config)", svc.name),
                            });
                        }
                    }
                }
                // Enable
                actions.push(RemediationAction::FirewallEnable {
                    description: "Enable ufw firewall".to_string(),
                });
            }
            "defense-no-bruteforce" => {
                actions.push(RemediationAction::InstallPackage {
                    package: "sshguard".to_string(),
                    description: "Install sshguard brute-force protection".to_string(),
                });
                actions.push(RemediationAction::EnableService {
                    service: "sshguard".to_string(),
                    description: "Enable and start sshguard".to_string(),
                });
            }
            "defense-bruteforce-inactive" => {
                // Extract service name from the finding title
                let service = if finding.title.contains("sshguard") {
                    "sshguard"
                } else if finding.title.contains("fail2ban") {
                    "fail2ban"
                } else if finding.title.contains("crowdsec") {
                    "crowdsec"
                } else {
                    "sshguard"
                };
                actions.push(RemediationAction::EnableService {
                    service: service.to_string(),
                    description: format!("Enable and start {}", service),
                });
            }
            "defense-no-auto-updates" => {
                actions.push(RemediationAction::InstallPackage {
                    package: "unattended-upgrades".to_string(),
                    description: "Install automatic security updates".to_string(),
                });
                actions.push(RemediationAction::RunCommand {
                    command: "dpkg-reconfigure -plow unattended-upgrades".to_string(),
                    description: "Configure unattended-upgrades".to_string(),
                });
            }
            _ => {} // Unknown defense finding, skip
        }
    }

    if actions.is_empty() {
        return None;
    }

    // Safety check: verify SSH allow is in the plan if any firewall actions exist
    let has_firewall_actions = actions
        .iter()
        .any(|a| matches!(a, RemediationAction::FirewallEnable { .. }));
    let has_ssh_allow = actions
        .iter()
        .any(|a| matches!(a, RemediationAction::FirewallAllow { port: 22, .. }));
    if has_firewall_actions && !has_ssh_allow {
        // Inject SSH allow at the beginning of firewall actions
        let pos = actions
            .iter()
            .position(|a| {
                matches!(
                    a,
                    RemediationAction::FirewallAllow { .. } | RemediationAction::FirewallEnable { .. }
                )
            })
            .unwrap_or(0);
        actions.insert(
            pos,
            RemediationAction::FirewallAllow {
                port: 22,
                protocol: "tcp".to_string(),
                comment: "Allow SSH (safety: auto-injected)".to_string(),
            },
        );
    }

    Some(RemediationPlan {
        id: None,
        host: host.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        status: PlanStatus::Pending,
        actions,
        source_findings: source_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use protectinator_core::{FindingSource, Severity};

    fn defense_finding(id: &str, title: &str) -> Finding {
        Finding::new(
            id,
            title,
            "test description",
            Severity::High,
            FindingSource::Defense {
                check_category: "test".to_string(),
                host: Some("testhost".to_string()),
            },
        )
    }

    #[test]
    fn test_no_firewall_plan() {
        let findings = vec![defense_finding("defense-no-firewall", "No active firewall")];
        let plan = generate_plan(
            "testhost",
            &findings,
            &["ssh:22".to_string(), "http:8090".to_string()],
        )
        .unwrap();

        assert_eq!(plan.status, PlanStatus::Pending);
        assert_eq!(plan.host, "testhost");

        // Should have: install ufw, allow 22, allow 8090, enable
        assert!(plan.actions.len() >= 4);

        // First firewall action should be SSH allow
        let first_fw = plan
            .actions
            .iter()
            .find(|a| matches!(a, RemediationAction::FirewallAllow { .. }))
            .unwrap();
        match first_fw {
            RemediationAction::FirewallAllow { port, .. } => assert_eq!(*port, 22),
            _ => panic!("Expected FirewallAllow"),
        }

        // Last should be enable
        assert!(matches!(
            plan.actions.last().unwrap(),
            RemediationAction::FirewallEnable { .. }
        ));
    }

    #[test]
    fn test_no_bruteforce_plan() {
        let findings = vec![defense_finding(
            "defense-no-bruteforce",
            "No brute-force protection",
        )];
        let plan = generate_plan("testhost", &findings, &[]).unwrap();

        assert_eq!(plan.actions.len(), 2); // install + enable
        assert!(matches!(
            &plan.actions[0],
            RemediationAction::InstallPackage { package, .. } if package == "sshguard"
        ));
        assert!(matches!(
            &plan.actions[1],
            RemediationAction::EnableService { service, .. } if service == "sshguard"
        ));
    }

    #[test]
    fn test_combined_plan() {
        let findings = vec![
            defense_finding("defense-no-firewall", "No firewall"),
            defense_finding("defense-no-bruteforce", "No brute-force"),
            defense_finding("defense-no-auto-updates", "No auto-updates"),
        ];
        let plan = generate_plan("testhost", &findings, &["ssh:22".to_string()]).unwrap();

        // Should have actions for all three findings
        assert!(plan.actions.len() >= 6);
        assert_eq!(plan.source_findings.len(), 3);
    }

    #[test]
    fn test_ssh_safety_guarantee() {
        let findings = vec![defense_finding(
            "defense-firewall-inactive",
            "Firewall inactive",
        )];
        let plan = generate_plan("testhost", &findings, &[]).unwrap();

        // Even with no allowed_services, SSH must be allowed before enable
        let enable_pos = plan
            .actions
            .iter()
            .position(|a| matches!(a, RemediationAction::FirewallEnable { .. }))
            .unwrap();
        let ssh_pos = plan
            .actions
            .iter()
            .position(|a| matches!(a, RemediationAction::FirewallAllow { port: 22, .. }))
            .unwrap();
        assert!(
            ssh_pos < enable_pos,
            "SSH allow must come before firewall enable"
        );
    }

    #[test]
    fn test_no_defense_findings_no_plan() {
        let findings = vec![Finding::new(
            "some-other-finding",
            "Not defense",
            "desc",
            Severity::Low,
            FindingSource::Hardening {
                check_id: "x".into(),
                category: "x".into(),
            },
        )];
        assert!(generate_plan("testhost", &findings, &[]).is_none());
    }

    #[test]
    fn test_action_to_command() {
        let action = RemediationAction::FirewallAllow {
            port: 443,
            protocol: "tcp".to_string(),
            comment: "Allow HTTPS".to_string(),
        };
        assert_eq!(
            action.to_command(),
            "ufw allow 443/tcp comment 'Allow HTTPS'"
        );

        let action = RemediationAction::InstallPackage {
            package: "sshguard".to_string(),
            description: "Install sshguard".to_string(),
        };
        assert_eq!(
            action.to_command(),
            "DEBIAN_FRONTEND=noninteractive apt-get install -y sshguard"
        );
    }
}
