//! High-level penalty box management

use crate::discovery::PackageDiscovery;
use crate::profile::{self, PenaltyBoxProfile};
use crate::restrictions::{EnforcementLevel, SandboxRestrictions};
use protectinator_core::Finding;
use std::collections::HashMap;
use tracing::info;

/// Manages penalty box profiles -- create, apply, check, and lift.
pub struct PenaltyBoxManager;

impl PenaltyBoxManager {
    /// Create a penalty box profile for a package based on CVE data.
    ///
    /// Discovers the package's binaries via dpkg, generates restrictions
    /// based on the CVSS vector and description, and builds a profile.
    pub fn create_profile(
        package: &str,
        cvss_vector: Option<&str>,
        cve_description: Option<&str>,
        cve_ids: Vec<String>,
        fixed_version: Option<String>,
        enforcement: EnforcementLevel,
    ) -> Result<PenaltyBoxProfile, String> {
        let binaries = PackageDiscovery::find_binaries(package)?;
        if binaries.is_empty() {
            return Err(format!(
                "No executable binaries found for package '{}'",
                package
            ));
        }

        let binary_paths: Vec<_> = binaries.iter().map(|b| b.path.clone()).collect();

        let restrictions = SandboxRestrictions::for_cve(cvss_vector, cve_description, enforcement);

        let reason = format!(
            "Unpatchable CVEs: {}. {}",
            cve_ids.join(", "),
            match enforcement {
                EnforcementLevel::Monitor => "Monitoring access patterns only.",
                EnforcementLevel::Restrict => "Restricted filesystem and network access.",
                EnforcementLevel::Quarantine => "Full quarantine -- minimal access allowed.",
            }
        );

        let mut profile =
            PenaltyBoxProfile::new(package.to_string(), binary_paths, restrictions, cve_ids, reason);

        if let Some(ver) = fixed_version {
            profile = profile.with_auto_lift(ver);
        }

        Ok(profile)
    }

    /// Save and activate a penalty box profile.
    pub fn apply_profile(profile: &PenaltyBoxProfile) -> Result<std::path::PathBuf, String> {
        info!(package = %profile.package, cves = ?profile.cves, "Applying penalty box profile");
        profile::save_profile(profile)
    }

    /// List all active penalty box profiles.
    pub fn list_active() -> Result<Vec<PenaltyBoxProfile>, String> {
        let profiles = profile::list_profiles()?;
        Ok(profiles.into_iter().filter(|p| p.active).collect())
    }

    /// Check if any penalty-boxed packages now have fixes available.
    ///
    /// Returns `(package, current_version, fixed_version)` tuples for
    /// profiles that can be lifted.
    pub fn check_liftable() -> Result<Vec<(String, String, String)>, String> {
        let profiles = profile::list_profiles()?;
        let mut liftable = Vec::new();

        for p in profiles {
            if !p.active {
                continue;
            }
            if let Some(ref lift_version) = p.auto_lift_version {
                if let Ok(current) = PackageDiscovery::get_package_version(&p.package) {
                    if current == *lift_version || current.contains(lift_version.as_str()) {
                        liftable.push((p.package.clone(), current, lift_version.clone()));
                    }
                }
            }
        }

        Ok(liftable)
    }

    /// Lift (deactivate) a penalty box for a package.
    pub fn lift(package: &str) -> Result<bool, String> {
        if let Some(mut profile) = profile::load_profile(package)? {
            profile.active = false;
            profile::save_profile(&profile)?;
            info!(package = %package, "Penalty box lifted");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove a penalty box profile entirely.
    pub fn remove(package: &str) -> Result<bool, String> {
        profile::remove_profile(package)
    }

    /// Create profiles for all findings that match criteria:
    /// - High or Critical severity
    /// - Has actionability metadata showing waiting_on_upstream
    pub fn auto_profiles_from_findings(
        findings: &[Finding],
        enforcement: EnforcementLevel,
    ) -> Vec<Result<PenaltyBoxProfile, String>> {
        // Group findings by package (from resource field)
        let mut by_package: HashMap<String, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            // Only high/critical severity
            if finding.severity != protectinator_core::Severity::High
                && finding.severity != protectinator_core::Severity::Critical
            {
                continue;
            }

            // Check if waiting on upstream (from actionability metadata)
            let is_waiting = finding
                .metadata
                .get("actionability")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("waiting_on_upstream"))
                .unwrap_or(false);

            if !is_waiting {
                continue;
            }

            // Extract package name from the finding title
            if finding.resource.is_some() {
                if let Some(pkg) = extract_package_name(&finding.title) {
                    by_package.entry(pkg).or_default().push(finding);
                }
            }
        }

        // Create a profile for each package
        by_package
            .into_iter()
            .map(|(package, findings)| {
                let cve_ids: Vec<String> = findings
                    .iter()
                    .filter_map(|f| {
                        f.metadata
                            .get("cve_aliases")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect::<Vec<_>>()
                            })
                    })
                    .flatten()
                    .collect();

                let cvss = findings
                    .first()
                    .and_then(|f| f.metadata.get("cvss_vector"))
                    .and_then(|v| v.as_str());

                Self::create_profile(
                    &package,
                    cvss,
                    Some(&findings[0].description),
                    if cve_ids.is_empty() {
                        vec![findings[0].id.clone()]
                    } else {
                        cve_ids
                    },
                    None,
                    enforcement,
                )
            })
            .collect()
    }
}

/// Try to extract a package name from a finding title.
///
/// e.g., "Known vulnerability in curl (CVE-2024-1234)" -> "curl"
fn extract_package_name(title: &str) -> Option<String> {
    if let Some(idx) = title.find(" in ") {
        let rest = &title[idx + 4..];
        let end = rest
            .find(|c: char| c == ' ' || c == '(')
            .unwrap_or(rest.len());
        let name = rest[..end].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use protectinator_core::{Finding, FindingSource, Severity};
    use std::collections::HashMap;

    #[test]
    fn test_extract_package_name_standard() {
        assert_eq!(
            extract_package_name("Known vulnerability in curl (CVE-2024-1234)"),
            Some("curl".to_string())
        );
    }

    #[test]
    fn test_extract_package_name_no_cve() {
        assert_eq!(
            extract_package_name("Known vulnerability in openssl"),
            Some("openssl".to_string())
        );
    }

    #[test]
    fn test_extract_package_name_with_space_after() {
        assert_eq!(
            extract_package_name("Buffer overflow in libxml2 allows RCE"),
            Some("libxml2".to_string())
        );
    }

    #[test]
    fn test_extract_package_name_no_match() {
        assert_eq!(extract_package_name("Some random title"), None);
    }

    #[test]
    fn test_extract_package_name_empty_after_in() {
        // "ends in " has "in " but then there's nothing useful
        assert_eq!(extract_package_name("Found in "), None);
    }

    fn make_finding(
        title: &str,
        severity: Severity,
        actionability: Option<&str>,
        resource: Option<&str>,
    ) -> Finding {
        let mut metadata = HashMap::new();
        if let Some(act) = actionability {
            metadata.insert(
                "actionability".to_string(),
                serde_json::Value::String(act.to_string()),
            );
        }

        Finding {
            id: "TEST-001".to_string(),
            title: title.to_string(),
            description: "Test description".to_string(),
            severity,
            source: FindingSource::Hardening {
                check_id: "test".to_string(),
                category: "test".to_string(),
            },
            timestamp: chrono::Utc::now(),
            resource: resource.map(String::from),
            remediation: None,
            metadata,
            references: vec![],
        }
    }

    #[test]
    fn test_auto_profiles_filters_low_severity() {
        let findings = vec![make_finding(
            "Vuln in curl (CVE-2024-1234)",
            Severity::Low,
            Some("waiting_on_upstream"),
            Some("/usr/bin/curl"),
        )];
        let results =
            PenaltyBoxManager::auto_profiles_from_findings(&findings, EnforcementLevel::Restrict);
        assert!(results.is_empty(), "Low severity should be filtered out");
    }

    #[test]
    fn test_auto_profiles_filters_non_waiting() {
        let findings = vec![make_finding(
            "Vuln in curl (CVE-2024-1234)",
            Severity::High,
            Some("patch_available"),
            Some("/usr/bin/curl"),
        )];
        let results =
            PenaltyBoxManager::auto_profiles_from_findings(&findings, EnforcementLevel::Restrict);
        assert!(
            results.is_empty(),
            "Non-waiting-on-upstream should be filtered out"
        );
    }

    #[test]
    fn test_auto_profiles_filters_no_resource() {
        let findings = vec![make_finding(
            "Vuln in curl (CVE-2024-1234)",
            Severity::Critical,
            Some("waiting_on_upstream"),
            None,
        )];
        let results =
            PenaltyBoxManager::auto_profiles_from_findings(&findings, EnforcementLevel::Restrict);
        assert!(results.is_empty(), "No resource should be filtered out");
    }

    #[test]
    fn test_auto_profiles_groups_by_package() {
        let findings = vec![
            make_finding(
                "Vuln in curl (CVE-2024-1234)",
                Severity::High,
                Some("waiting_on_upstream"),
                Some("Cargo.lock"),
            ),
            make_finding(
                "Another vuln in curl (CVE-2024-5678)",
                Severity::Critical,
                Some("waiting_on_upstream"),
                Some("Cargo.lock"),
            ),
        ];
        let results =
            PenaltyBoxManager::auto_profiles_from_findings(&findings, EnforcementLevel::Restrict);
        // Both findings are for "curl", so should produce 1 result
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_auto_profiles_requires_no_actionability() {
        let findings = vec![make_finding(
            "Vuln in curl (CVE-2024-1234)",
            Severity::High,
            None, // no actionability metadata
            Some("/usr/bin/curl"),
        )];
        let results =
            PenaltyBoxManager::auto_profiles_from_findings(&findings, EnforcementLevel::Restrict);
        assert!(
            results.is_empty(),
            "No actionability metadata should be filtered out"
        );
    }
}
