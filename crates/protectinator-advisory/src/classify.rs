//! Actionability classification and CVE intelligence enrichment
//!
//! Classifies CVEs into actionable categories based on Debian tracker data
//! and enriches protectinator findings with remediation guidance.

use crate::debian::{DebianCveEntry, SubState, TrackerStatus};
use protectinator_core::Finding;
use serde::{Deserialize, Serialize};

/// How actionable a CVE finding is
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum ActionabilityClass {
    /// A fix is available -- run this command
    PatchableNow {
        fixed_version: String,
        install_cmd: String,
    },
    /// No fix available yet, upstream is working on it
    WaitingOnUpstream { reason: String },
    /// Debian security team assessed as low risk
    AcceptedRisk { reason: String },
    /// CVE is disputed or rejected
    Disputed { reason: String },
    /// No Debian tracker data available for this CVE
    Unknown,
}

/// Enriched CVE intelligence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveIntelligence {
    pub cve_id: String,
    pub actionability: ActionabilityClass,
    pub debian_status: Option<String>,
    pub debian_urgency: Option<String>,
    pub debian_sub_state: Option<String>,
}

/// Classify a CVE based on Debian tracker data
///
/// `entry` is the parsed Debian tracker entry for a specific package/release.
/// `installed_version` is the currently installed version, if known.
/// `package` is the package name (used for generating install commands).
pub fn classify_cve(
    entry: &DebianCveEntry,
    installed_version: Option<&str>,
    package: &str,
) -> ActionabilityClass {
    match entry.status {
        TrackerStatus::Resolved => {
            if let Some(ref fixed_ver) = entry.fixed_version {
                // For MVP, if there's a fixed version and status is resolved,
                // we consider it patchable. Full dpkg version comparison
                // can come later.
                let needs_update = match installed_version {
                    Some(installed) => installed != fixed_ver,
                    None => true, // Assume needs update if we don't know
                };

                if needs_update {
                    ActionabilityClass::PatchableNow {
                        fixed_version: fixed_ver.clone(),
                        install_cmd: format!("apt install {}={}", package, fixed_ver),
                    }
                } else {
                    // Already at fixed version
                    ActionabilityClass::AcceptedRisk {
                        reason: format!(
                            "Already running fixed version {}",
                            fixed_ver
                        ),
                    }
                }
            } else {
                // Resolved but no fixed_version recorded -- unusual
                ActionabilityClass::Unknown
            }
        }
        TrackerStatus::Unfixed => {
            // Check urgency and sub_state for risk assessment
            let urgency_lower = entry.urgency.to_lowercase();

            if urgency_lower == "unimportant" {
                return ActionabilityClass::AcceptedRisk {
                    reason: "Debian classifies as unimportant".to_string(),
                };
            }

            if entry.sub_state == SubState::Ignored {
                return ActionabilityClass::AcceptedRisk {
                    reason: format!(
                        "Debian security team: ignored -- {}",
                        entry.description.as_deref().unwrap_or("no reason given")
                    ),
                };
            }

            if entry.sub_state == SubState::Postponed {
                return ActionabilityClass::AcceptedRisk {
                    reason: "Debian security team: postponed for future point release"
                        .to_string(),
                };
            }

            ActionabilityClass::WaitingOnUpstream {
                reason: format!(
                    "No fix in Debian yet. Urgency: {}",
                    entry.urgency
                ),
            }
        }
        TrackerStatus::NotAffected => ActionabilityClass::Disputed {
            reason: "Debian tracker reports this release as not affected".to_string(),
        },
        TrackerStatus::Undetermined => ActionabilityClass::Unknown,
    }
}

/// Build a CveIntelligence struct from a Debian tracker entry
pub fn build_intelligence(
    entry: &DebianCveEntry,
    installed_version: Option<&str>,
    package: &str,
) -> CveIntelligence {
    let actionability = classify_cve(entry, installed_version, package);

    CveIntelligence {
        cve_id: entry.cve_id.clone(),
        actionability,
        debian_status: Some(entry.status.to_string()),
        debian_urgency: Some(entry.urgency.clone()),
        debian_sub_state: Some(entry.sub_state.to_string()),
    }
}

/// Enrich a finding with CVE intelligence metadata
pub fn enrich_finding(finding: &mut Finding, intelligence: &CveIntelligence) {
    // Add actionability metadata
    if let Ok(value) = serde_json::to_value(&intelligence.actionability) {
        finding
            .metadata
            .insert("actionability".to_string(), value);
    }

    if let Some(ref status) = intelligence.debian_status {
        finding.metadata.insert(
            "debian_status".to_string(),
            serde_json::Value::String(status.clone()),
        );
    }

    if let Some(ref urgency) = intelligence.debian_urgency {
        finding.metadata.insert(
            "debian_urgency".to_string(),
            serde_json::Value::String(urgency.clone()),
        );
    }

    // Update remediation with specific guidance
    let package = finding
        .resource
        .as_deref()
        .unwrap_or("affected-package");
    let remediation =
        generate_remediation_text(&intelligence.actionability, package, &intelligence.cve_id);
    finding.remediation = Some(remediation);
}

/// Generate human-readable remediation text from an actionability classification
pub fn generate_remediation_text(
    class: &ActionabilityClass,
    package: &str,
    cve_id: &str,
) -> String {
    match class {
        ActionabilityClass::PatchableNow {
            fixed_version,
            install_cmd,
        } => {
            format!(
                "Fix available for {}: upgrade {} to version {} by running: {}",
                cve_id, package, fixed_version, install_cmd
            )
        }
        ActionabilityClass::WaitingOnUpstream { reason } => {
            format!(
                "No fix available yet for {} in {}: {}. Monitor https://security-tracker.debian.org/tracker/{}",
                cve_id, package, reason, cve_id
            )
        }
        ActionabilityClass::AcceptedRisk { reason } => {
            format!(
                "{} in {} is low risk: {}. No immediate action required.",
                cve_id, package, reason
            )
        }
        ActionabilityClass::Disputed { reason } => {
            format!(
                "{} in {} may not apply: {}.",
                cve_id, package, reason
            )
        }
        ActionabilityClass::Unknown => {
            format!(
                "No Debian tracker data available for {} in {}. Check https://security-tracker.debian.org/tracker/{} manually.",
                cve_id, package, cve_id
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protectinator_core::{FindingSource, Severity};

    fn make_entry(
        status: TrackerStatus,
        sub_state: SubState,
        urgency: &str,
        fixed_version: Option<&str>,
    ) -> DebianCveEntry {
        DebianCveEntry {
            cve_id: "CVE-2024-1234".to_string(),
            status,
            sub_state,
            urgency: urgency.to_string(),
            fixed_version: fixed_version.map(|s| s.to_string()),
            scope: Some("remote".to_string()),
            description: Some("Test vulnerability".to_string()),
        }
    }

    #[test]
    fn test_classify_patchable_now() {
        let entry = make_entry(
            TrackerStatus::Resolved,
            SubState::None,
            "medium",
            Some("7.88.1-10+deb12u5"),
        );
        let class = classify_cve(&entry, None, "curl");
        match class {
            ActionabilityClass::PatchableNow {
                fixed_version,
                install_cmd,
            } => {
                assert_eq!(fixed_version, "7.88.1-10+deb12u5");
                assert_eq!(install_cmd, "apt install curl=7.88.1-10+deb12u5");
            }
            other => panic!("Expected PatchableNow, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_patchable_already_fixed() {
        let entry = make_entry(
            TrackerStatus::Resolved,
            SubState::None,
            "medium",
            Some("7.88.1-10+deb12u5"),
        );
        let class = classify_cve(&entry, Some("7.88.1-10+deb12u5"), "curl");
        match class {
            ActionabilityClass::AcceptedRisk { reason } => {
                assert!(reason.contains("Already running fixed version"));
            }
            other => panic!("Expected AcceptedRisk, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_patchable_outdated() {
        let entry = make_entry(
            TrackerStatus::Resolved,
            SubState::None,
            "high",
            Some("7.88.1-10+deb12u5"),
        );
        let class = classify_cve(&entry, Some("7.88.1-10+deb12u4"), "curl");
        match class {
            ActionabilityClass::PatchableNow { .. } => {}
            other => panic!("Expected PatchableNow, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_waiting_on_upstream() {
        let entry = make_entry(TrackerStatus::Unfixed, SubState::None, "medium", None);
        let class = classify_cve(&entry, None, "openssl");
        match class {
            ActionabilityClass::WaitingOnUpstream { reason } => {
                assert!(reason.contains("No fix in Debian yet"));
                assert!(reason.contains("medium"));
            }
            other => panic!("Expected WaitingOnUpstream, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_accepted_risk_unimportant() {
        let entry = make_entry(TrackerStatus::Unfixed, SubState::None, "unimportant", None);
        let class = classify_cve(&entry, None, "pkg");
        match class {
            ActionabilityClass::AcceptedRisk { reason } => {
                assert!(reason.contains("unimportant"));
            }
            other => panic!("Expected AcceptedRisk, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_accepted_risk_ignored() {
        let entry = make_entry(TrackerStatus::Unfixed, SubState::Ignored, "low", None);
        let class = classify_cve(&entry, None, "pkg");
        match class {
            ActionabilityClass::AcceptedRisk { reason } => {
                assert!(reason.contains("ignored"));
            }
            other => panic!("Expected AcceptedRisk, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_accepted_risk_postponed() {
        let entry = make_entry(TrackerStatus::Unfixed, SubState::Postponed, "low", None);
        let class = classify_cve(&entry, None, "pkg");
        match class {
            ActionabilityClass::AcceptedRisk { reason } => {
                assert!(reason.contains("postponed"));
            }
            other => panic!("Expected AcceptedRisk, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_disputed() {
        let entry = make_entry(TrackerStatus::NotAffected, SubState::None, "low", None);
        let class = classify_cve(&entry, None, "pkg");
        match class {
            ActionabilityClass::Disputed { .. } => {}
            other => panic!("Expected Disputed, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_unknown_undetermined() {
        let entry = make_entry(TrackerStatus::Undetermined, SubState::None, "low", None);
        let class = classify_cve(&entry, None, "pkg");
        assert_eq!(class, ActionabilityClass::Unknown);
    }

    #[test]
    fn test_classify_resolved_no_fixed_version() {
        let entry = make_entry(TrackerStatus::Resolved, SubState::None, "medium", None);
        let class = classify_cve(&entry, None, "pkg");
        assert_eq!(class, ActionabilityClass::Unknown);
    }

    #[test]
    fn test_build_intelligence() {
        let entry = make_entry(
            TrackerStatus::Resolved,
            SubState::None,
            "high",
            Some("1.0-1"),
        );
        let intel = build_intelligence(&entry, None, "curl");
        assert_eq!(intel.cve_id, "CVE-2024-1234");
        assert_eq!(intel.debian_status, Some("resolved".to_string()));
        assert_eq!(intel.debian_urgency, Some("high".to_string()));
        match intel.actionability {
            ActionabilityClass::PatchableNow { .. } => {}
            other => panic!("Expected PatchableNow, got {:?}", other),
        }
    }

    #[test]
    fn test_enrich_finding() {
        let mut finding = Finding::new(
            "CVE-2024-1234",
            "Test CVE",
            "A test vulnerability",
            Severity::High,
            FindingSource::SupplyChain {
                check_category: "vulnerability".to_string(),
                ecosystem: Some("debian".to_string()),
            },
        )
        .with_resource("curl");

        let intel = CveIntelligence {
            cve_id: "CVE-2024-1234".to_string(),
            actionability: ActionabilityClass::PatchableNow {
                fixed_version: "1.0-1".to_string(),
                install_cmd: "apt install curl=1.0-1".to_string(),
            },
            debian_status: Some("resolved".to_string()),
            debian_urgency: Some("high".to_string()),
            debian_sub_state: Some("none".to_string()),
        };

        enrich_finding(&mut finding, &intel);

        assert!(finding.metadata.contains_key("actionability"));
        assert!(finding.metadata.contains_key("debian_status"));
        assert!(finding.metadata.contains_key("debian_urgency"));
        assert!(finding.remediation.is_some());
        let remediation = finding.remediation.unwrap();
        assert!(remediation.contains("apt install curl=1.0-1"));
    }

    #[test]
    fn test_generate_remediation_patchable() {
        let text = generate_remediation_text(
            &ActionabilityClass::PatchableNow {
                fixed_version: "1.0-1".to_string(),
                install_cmd: "apt install curl=1.0-1".to_string(),
            },
            "curl",
            "CVE-2024-1234",
        );
        assert!(text.contains("Fix available"));
        assert!(text.contains("apt install curl=1.0-1"));
    }

    #[test]
    fn test_generate_remediation_waiting() {
        let text = generate_remediation_text(
            &ActionabilityClass::WaitingOnUpstream {
                reason: "No fix in Debian yet. Urgency: medium".to_string(),
            },
            "openssl",
            "CVE-2024-5678",
        );
        assert!(text.contains("No fix available yet"));
        assert!(text.contains("security-tracker.debian.org"));
    }

    #[test]
    fn test_generate_remediation_accepted_risk() {
        let text = generate_remediation_text(
            &ActionabilityClass::AcceptedRisk {
                reason: "Debian classifies as unimportant".to_string(),
            },
            "pkg",
            "CVE-2024-0001",
        );
        assert!(text.contains("low risk"));
        assert!(text.contains("No immediate action required"));
    }

    #[test]
    fn test_generate_remediation_disputed() {
        let text = generate_remediation_text(
            &ActionabilityClass::Disputed {
                reason: "Not affected".to_string(),
            },
            "pkg",
            "CVE-2024-0001",
        );
        assert!(text.contains("may not apply"));
    }

    #[test]
    fn test_generate_remediation_unknown() {
        let text = generate_remediation_text(
            &ActionabilityClass::Unknown,
            "pkg",
            "CVE-2024-0001",
        );
        assert!(text.contains("No Debian tracker data"));
        assert!(text.contains("manually"));
    }

    #[test]
    fn test_actionability_class_serialization() {
        let class = ActionabilityClass::PatchableNow {
            fixed_version: "1.0-1".to_string(),
            install_cmd: "apt install foo=1.0-1".to_string(),
        };
        let json = serde_json::to_string(&class).expect("serialize");
        assert!(json.contains("patchable_now"));
        let deserialized: ActionabilityClass =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, class);
    }

    #[test]
    fn test_cve_intelligence_serialization() {
        let intel = CveIntelligence {
            cve_id: "CVE-2024-1234".to_string(),
            actionability: ActionabilityClass::Unknown,
            debian_status: None,
            debian_urgency: None,
            debian_sub_state: None,
        };
        let json = serde_json::to_string(&intel).expect("serialize");
        let deserialized: CveIntelligence =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.cve_id, "CVE-2024-1234");
        assert_eq!(deserialized.actionability, ActionabilityClass::Unknown);
    }
}
