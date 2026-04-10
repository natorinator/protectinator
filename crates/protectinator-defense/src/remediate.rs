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
    /// User explicitly declined this remediation
    Denied,
    /// User acknowledged but chose not to act now
    Ignored,
    /// User wants to be reminded later
    Remind,
    /// Replaced by a newer plan for the same host
    Superseded,
}

impl std::fmt::Display for PlanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanStatus::Pending => write!(f, "pending"),
            PlanStatus::Approved => write!(f, "approved"),
            PlanStatus::Executing => write!(f, "executing"),
            PlanStatus::Done => write!(f, "done"),
            PlanStatus::Failed => write!(f, "failed"),
            PlanStatus::Denied => write!(f, "denied"),
            PlanStatus::Ignored => write!(f, "ignored"),
            PlanStatus::Remind => write!(f, "remind"),
            PlanStatus::Superseded => write!(f, "superseded"),
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
    UpgradePackage {
        package: String,
        cve_ids: Vec<String>,
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
            RemediationAction::UpgradePackage { package, .. } => {
                format!(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade {}",
                    package
                )
            }
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
            RemediationAction::UpgradePackage { description, .. } => description,
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

/// Parse package name and CVE ID from a vulnerability finding title.
///
/// Expected formats:
/// - "UBUNTU-CVE-2022-28653: apport@2.28.1-0ubuntu3.8" → Some(("apport", "UBUNTU-CVE-2022-28653"))
/// - "CVE-2023-1234: openssl@1.1.1" → Some(("openssl", "CVE-2023-1234"))
fn parse_vuln_title(title: &str) -> Option<(String, String)> {
    let (cve_part, pkg_part) = title.split_once(": ")?;
    let package = pkg_part.split('@').next()?.trim().to_string();
    if package.is_empty() {
        return None;
    }
    Some((package, cve_part.trim().to_string()))
}

/// Generate a remediation plan for patching CVE vulnerabilities on a host
///
/// Groups findings by package name, deduplicates, and generates
/// one UpgradePackage action per unique package.
pub fn generate_patch_plan(host: &str, findings: &[Finding]) -> Option<RemediationPlan> {
    use std::collections::BTreeMap;

    // Track package → (cve_ids, max_severity)
    struct PkgInfo {
        cve_ids: Vec<String>,
        max_severity: u8,
    }

    let mut packages: BTreeMap<String, PkgInfo> = BTreeMap::new();
    let mut source_ids = Vec::new();

    for finding in findings {
        // Only process vulnerability findings
        if !finding.id.starts_with("container-vuln-")
            && !finding.id.starts_with("supply-chain-vuln-")
        {
            continue;
        }

        source_ids.push(finding.id.clone());

        if let Some((package, cve_id)) = parse_vuln_title(&finding.title) {
            let severity_rank = match finding.severity {
                protectinator_core::Severity::Critical => 4,
                protectinator_core::Severity::High => 3,
                protectinator_core::Severity::Medium => 2,
                protectinator_core::Severity::Low => 1,
                protectinator_core::Severity::Info => 0,
            };

            let entry = packages.entry(package).or_insert_with(|| PkgInfo {
                cve_ids: Vec::new(),
                max_severity: 0,
            });

            if !entry.cve_ids.contains(&cve_id) {
                entry.cve_ids.push(cve_id);
            }
            if severity_rank > entry.max_severity {
                entry.max_severity = severity_rank;
            }
        }
    }

    if packages.is_empty() {
        return None;
    }

    // Sort by severity (critical first), then alphabetically
    let mut sorted_pkgs: Vec<(String, PkgInfo)> = packages.into_iter().collect();
    sorted_pkgs.sort_by(|a, b| b.1.max_severity.cmp(&a.1.max_severity).then(a.0.cmp(&b.0)));

    let mut actions: Vec<RemediationAction> = sorted_pkgs
        .into_iter()
        .map(|(package, info)| {
            let description = if info.cve_ids.len() == 1 {
                format!("Upgrade {} (fixes {})", package, info.cve_ids[0])
            } else if info.cve_ids.len() <= 2 {
                format!(
                    "Upgrade {} (fixes {})",
                    package,
                    info.cve_ids.join(", ")
                )
            } else {
                format!(
                    "Upgrade {} (fixes {}, {}, +{} more)",
                    package,
                    info.cve_ids[0],
                    info.cve_ids[1],
                    info.cve_ids.len() - 2
                )
            };

            RemediationAction::UpgradePackage {
                package,
                cve_ids: info.cve_ids,
                description,
            }
        })
        .collect();

    // Prepend apt-get update to refresh package lists
    actions.insert(0, RemediationAction::RunCommand {
        command: "apt-get update -q".to_string(),
        description: "Refresh package lists".to_string(),
    });

    // Final cleanup action
    actions.push(RemediationAction::RunCommand {
        command: "apt-get autoremove -y".to_string(),
        description: "Clean up unused packages".to_string(),
    });

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

    // --- Patch plan tests ---

    fn vuln_finding(id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(
            id,
            title,
            "test vuln description",
            severity,
            FindingSource::SupplyChain {
                check_category: "vulnerability".to_string(),
                ecosystem: Some("deb".to_string()),
            },
        )
    }

    #[test]
    fn test_parse_vuln_title_standard() {
        let (pkg, cve) =
            parse_vuln_title("UBUNTU-CVE-2022-28653: apport@2.28.1-0ubuntu3.8").unwrap();
        assert_eq!(pkg, "apport");
        assert_eq!(cve, "UBUNTU-CVE-2022-28653");
    }

    #[test]
    fn test_parse_vuln_title_simple_cve() {
        let (pkg, cve) = parse_vuln_title("CVE-2023-1234: openssl@1.1.1").unwrap();
        assert_eq!(pkg, "openssl");
        assert_eq!(cve, "CVE-2023-1234");
    }

    #[test]
    fn test_parse_vuln_title_no_separator() {
        assert!(parse_vuln_title("no separator here").is_none());
    }

    #[test]
    fn test_parse_vuln_title_no_package() {
        assert!(parse_vuln_title("CVE-2023-1234: @1.0").is_none());
    }

    #[test]
    fn test_group_cves_per_package() {
        let findings = vec![
            vuln_finding(
                "container-vuln-CVE-2023-0001",
                "CVE-2023-0001: binutils@2.38",
                Severity::Medium,
            ),
            vuln_finding(
                "container-vuln-CVE-2023-0002",
                "CVE-2023-0002: binutils@2.38",
                Severity::High,
            ),
            vuln_finding(
                "container-vuln-CVE-2023-0003",
                "CVE-2023-0003: binutils@2.38",
                Severity::Low,
            ),
            vuln_finding(
                "container-vuln-CVE-2023-0004",
                "CVE-2023-0004: binutils@2.38",
                Severity::Medium,
            ),
            vuln_finding(
                "container-vuln-CVE-2023-0005",
                "CVE-2023-0005: binutils@2.38",
                Severity::Medium,
            ),
        ];
        let plan = generate_patch_plan("testhost", &findings).unwrap();

        // 5 CVEs for same package → 1 upgrade action + 1 autoremove
        assert_eq!(plan.actions.len(), 2);

        match &plan.actions[0] {
            RemediationAction::UpgradePackage {
                package, cve_ids, description, ..
            } => {
                assert_eq!(package, "binutils");
                assert_eq!(cve_ids.len(), 5);
                assert!(description.contains("+3 more"));
            }
            _ => panic!("Expected UpgradePackage"),
        }

        // Last action should be autoremove
        match &plan.actions[1] {
            RemediationAction::RunCommand { command, .. } => {
                assert_eq!(command, "apt-get autoremove -y");
            }
            _ => panic!("Expected RunCommand autoremove"),
        }

        assert_eq!(plan.source_findings.len(), 5);
    }

    #[test]
    fn test_sort_by_severity_critical_first() {
        let findings = vec![
            vuln_finding(
                "container-vuln-CVE-LOW",
                "CVE-LOW: zlib@1.2",
                Severity::Low,
            ),
            vuln_finding(
                "container-vuln-CVE-CRIT",
                "CVE-CRIT: openssl@3.0",
                Severity::Critical,
            ),
            vuln_finding(
                "container-vuln-CVE-MED",
                "CVE-MED: curl@7.88",
                Severity::Medium,
            ),
        ];
        let plan = generate_patch_plan("testhost", &findings).unwrap();

        // 3 packages + autoremove = 4 actions
        assert_eq!(plan.actions.len(), 4);

        // Critical package first
        match &plan.actions[0] {
            RemediationAction::UpgradePackage { package, .. } => {
                assert_eq!(package, "openssl");
            }
            _ => panic!("Expected UpgradePackage"),
        }
        // Medium next
        match &plan.actions[1] {
            RemediationAction::UpgradePackage { package, .. } => {
                assert_eq!(package, "curl");
            }
            _ => panic!("Expected UpgradePackage"),
        }
        // Low last
        match &plan.actions[2] {
            RemediationAction::UpgradePackage { package, .. } => {
                assert_eq!(package, "zlib");
            }
            _ => panic!("Expected UpgradePackage"),
        }
    }

    #[test]
    fn test_upgrade_package_command() {
        let action = RemediationAction::UpgradePackage {
            package: "apport".to_string(),
            cve_ids: vec!["CVE-2022-28653".to_string()],
            description: "Upgrade apport".to_string(),
        };
        assert_eq!(
            action.to_command(),
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade apport"
        );
    }

    #[test]
    fn test_empty_findings_returns_none() {
        assert!(generate_patch_plan("testhost", &[]).is_none());
    }

    #[test]
    fn test_non_vuln_findings_returns_none() {
        let findings = vec![defense_finding("defense-no-firewall", "No firewall")];
        assert!(generate_patch_plan("testhost", &findings).is_none());
    }

    #[test]
    fn test_supply_chain_vuln_prefix() {
        let findings = vec![vuln_finding(
            "supply-chain-vuln-CVE-2023-9999",
            "CVE-2023-9999: requests@2.28.0",
            Severity::High,
        )];
        let plan = generate_patch_plan("testhost", &findings).unwrap();
        assert_eq!(plan.actions.len(), 2); // 1 upgrade + autoremove
        match &plan.actions[0] {
            RemediationAction::UpgradePackage { package, .. } => {
                assert_eq!(package, "requests");
            }
            _ => panic!("Expected UpgradePackage"),
        }
    }

    #[test]
    fn test_description_single_cve() {
        let findings = vec![vuln_finding(
            "container-vuln-CVE-2022-28653",
            "CVE-2022-28653: apport@2.28.1",
            Severity::Medium,
        )];
        let plan = generate_patch_plan("testhost", &findings).unwrap();
        match &plan.actions[0] {
            RemediationAction::UpgradePackage { description, .. } => {
                assert_eq!(description, "Upgrade apport (fixes CVE-2022-28653)");
            }
            _ => panic!("Expected UpgradePackage"),
        }
    }

    #[test]
    fn test_description_two_cves() {
        let findings = vec![
            vuln_finding(
                "container-vuln-CVE-2023-0001",
                "CVE-2023-0001: pkg@1.0",
                Severity::Medium,
            ),
            vuln_finding(
                "container-vuln-CVE-2023-0002",
                "CVE-2023-0002: pkg@1.0",
                Severity::Medium,
            ),
        ];
        let plan = generate_patch_plan("testhost", &findings).unwrap();
        match &plan.actions[0] {
            RemediationAction::UpgradePackage { description, .. } => {
                assert!(description.contains("CVE-2023-0001, CVE-2023-0002"));
            }
            _ => panic!("Expected UpgradePackage"),
        }
    }
}
