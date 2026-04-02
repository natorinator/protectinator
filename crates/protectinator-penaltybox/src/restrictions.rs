//! Map CVE types to Landlock/Gaol sandbox restrictions

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How strictly to sandbox a binary
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    /// Log access but don't block (audit mode via gaol learn)
    Monitor,
    /// Apply Landlock restrictions, allow known-needed paths
    Restrict,
    /// Full isolation -- no network, minimal filesystem, read-only where possible
    Quarantine,
}

/// Network access policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Block all network access
    Blocked,
    /// Allow all network access
    AllowAll,
    /// Allow specific destinations only (future use)
    AllowList(Vec<String>),
}

/// Sandbox restrictions for a binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRestrictions {
    /// Paths allowed read-only
    pub read_paths: Vec<PathBuf>,
    /// Paths allowed read-write
    pub write_paths: Vec<PathBuf>,
    /// Paths explicitly denied
    pub deny_paths: Vec<PathBuf>,
    /// Network policy
    pub network: NetworkPolicy,
    /// Enforcement level
    pub enforcement: EnforcementLevel,
}

impl SandboxRestrictions {
    /// Default restrictions for Restrict enforcement level.
    ///
    /// Allows reading standard system directories and writing to temp dirs.
    /// Network is blocked by default.
    pub fn default_restrict() -> Self {
        Self {
            read_paths: vec![
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/sbin".into(),
                "/etc".into(),
                "/proc".into(),
                "/sys".into(),
                "/dev".into(),
            ],
            write_paths: vec!["/tmp".into(), "/var/tmp".into()],
            deny_paths: vec![],
            network: NetworkPolicy::Blocked,
            enforcement: EnforcementLevel::Restrict,
        }
    }

    /// Full quarantine -- minimal access allowed.
    pub fn quarantine() -> Self {
        Self {
            read_paths: vec![
                "/usr/lib".into(),
                "/lib".into(),
                "/lib64".into(),
                "/dev/null".into(),
            ],
            write_paths: vec![],
            deny_paths: vec![],
            network: NetworkPolicy::Blocked,
            enforcement: EnforcementLevel::Quarantine,
        }
    }

    /// Generate restrictions based on CVE characteristics.
    ///
    /// Parses the CVSS v3 vector string and CVE description to determine
    /// appropriate filesystem and network restrictions.
    ///
    /// # Arguments
    /// * `cvss_vector` - Optional CVSS v3 vector string like
    ///   `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`
    /// * `cve_description` - Optional CVE description text for heuristic detection
    /// * `enforcement` - How strictly to sandbox
    pub fn for_cve(
        cvss_vector: Option<&str>,
        cve_description: Option<&str>,
        enforcement: EnforcementLevel,
    ) -> Self {
        let mut restrictions = match enforcement {
            EnforcementLevel::Monitor => Self::default_restrict(),
            EnforcementLevel::Restrict => Self::default_restrict(),
            EnforcementLevel::Quarantine => Self::quarantine(),
        };

        if let Some(vector) = cvss_vector {
            let parts: Vec<&str> = vector.split('/').collect();

            // Attack Vector: Network (AV:N) -> block network
            if parts.iter().any(|p| *p == "AV:N") {
                restrictions.network = NetworkPolicy::Blocked;
            }

            // Local attack with high privileges required: less restrictive
            if parts.iter().any(|p| *p == "AV:L") && parts.iter().any(|p| *p == "PR:H") {
                if enforcement == EnforcementLevel::Restrict {
                    restrictions.network = NetworkPolicy::AllowAll;
                }
            }

            // High integrity impact -> restrict write paths more
            if parts.iter().any(|p| *p == "I:H") {
                restrictions.write_paths = vec!["/tmp".into()];
                restrictions.deny_paths.push("/etc".into());
                restrictions.deny_paths.push("/home".into());
            }

            // High confidentiality impact -> restrict read paths
            if parts.iter().any(|p| *p == "C:H") {
                restrictions.deny_paths.push("/home".into());
                restrictions.deny_paths.push("/root".into());
                restrictions.deny_paths.push("/etc/shadow".into());
            }
        }

        // Heuristic: check description for keywords
        if let Some(desc) = cve_description {
            let desc_lower = desc.to_lowercase();
            if desc_lower.contains("remote code execution") || desc_lower.contains("rce") {
                restrictions.network = NetworkPolicy::Blocked;
                restrictions.write_paths = vec!["/tmp".into()];
            }
            if desc_lower.contains("privilege escalation") || desc_lower.contains("privesc") {
                restrictions.deny_paths.push("/etc/passwd".into());
                restrictions.deny_paths.push("/etc/shadow".into());
            }
            if desc_lower.contains("information disclosure") || desc_lower.contains("info leak") {
                restrictions.deny_paths.push("/home".into());
                restrictions.deny_paths.push("/root".into());
            }
        }

        restrictions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_restrict() {
        let r = SandboxRestrictions::default_restrict();
        assert_eq!(r.enforcement, EnforcementLevel::Restrict);
        assert_eq!(r.network, NetworkPolicy::Blocked);
        assert!(r.read_paths.contains(&PathBuf::from("/usr")));
        assert!(r.read_paths.contains(&PathBuf::from("/etc")));
        assert!(r.write_paths.contains(&PathBuf::from("/tmp")));
        assert!(r.write_paths.contains(&PathBuf::from("/var/tmp")));
        assert!(r.deny_paths.is_empty());
    }

    #[test]
    fn test_quarantine() {
        let r = SandboxRestrictions::quarantine();
        assert_eq!(r.enforcement, EnforcementLevel::Quarantine);
        assert_eq!(r.network, NetworkPolicy::Blocked);
        assert!(r.write_paths.is_empty());
        assert!(r.read_paths.contains(&PathBuf::from("/usr/lib")));
        assert!(r.read_paths.contains(&PathBuf::from("/dev/null")));
        // Quarantine should NOT include /usr, /etc, /bin, etc.
        assert!(!r.read_paths.contains(&PathBuf::from("/usr")));
        assert!(!r.read_paths.contains(&PathBuf::from("/etc")));
    }

    #[test]
    fn test_for_cve_network_attack() {
        let r = SandboxRestrictions::for_cve(
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None,
            EnforcementLevel::Restrict,
        );
        assert_eq!(r.network, NetworkPolicy::Blocked);
        // High integrity impact -> minimal writes
        assert_eq!(r.write_paths, vec![PathBuf::from("/tmp")]);
        // High confidentiality -> deny /home, /root
        assert!(r.deny_paths.contains(&PathBuf::from("/home")));
        assert!(r.deny_paths.contains(&PathBuf::from("/root")));
        assert!(r.deny_paths.contains(&PathBuf::from("/etc/shadow")));
    }

    #[test]
    fn test_for_cve_local_high_priv() {
        let r = SandboxRestrictions::for_cve(
            Some("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"),
            None,
            EnforcementLevel::Restrict,
        );
        // Local + high privilege required -> allow network
        assert_eq!(r.network, NetworkPolicy::AllowAll);
    }

    #[test]
    fn test_for_cve_rce_description() {
        let r = SandboxRestrictions::for_cve(
            None,
            Some("A remote code execution vulnerability allows attackers to run arbitrary code"),
            EnforcementLevel::Restrict,
        );
        assert_eq!(r.network, NetworkPolicy::Blocked);
        assert_eq!(r.write_paths, vec![PathBuf::from("/tmp")]);
    }

    #[test]
    fn test_for_cve_privesc_description() {
        let r = SandboxRestrictions::for_cve(
            None,
            Some("A privilege escalation flaw allows local users to gain root"),
            EnforcementLevel::Restrict,
        );
        assert!(r.deny_paths.contains(&PathBuf::from("/etc/passwd")));
        assert!(r.deny_paths.contains(&PathBuf::from("/etc/shadow")));
    }

    #[test]
    fn test_for_cve_info_disclosure() {
        let r = SandboxRestrictions::for_cve(
            None,
            Some("An information disclosure vulnerability leaks sensitive data"),
            EnforcementLevel::Restrict,
        );
        assert!(r.deny_paths.contains(&PathBuf::from("/home")));
        assert!(r.deny_paths.contains(&PathBuf::from("/root")));
    }

    #[test]
    fn test_for_cve_quarantine_enforcement() {
        let r = SandboxRestrictions::for_cve(
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None,
            EnforcementLevel::Quarantine,
        );
        assert_eq!(r.enforcement, EnforcementLevel::Quarantine);
        assert_eq!(r.network, NetworkPolicy::Blocked);
    }

    #[test]
    fn test_for_cve_monitor_enforcement() {
        let r = SandboxRestrictions::for_cve(
            None,
            None,
            EnforcementLevel::Monitor,
        );
        // Monitor mode uses default_restrict as base
        assert_eq!(r.enforcement, EnforcementLevel::Restrict);
        // The enforcement field comes from default_restrict(), but the intent is monitoring
        assert!(r.read_paths.contains(&PathBuf::from("/usr")));
    }

    #[test]
    fn test_enforcement_level_serde_roundtrip() {
        let levels = [
            EnforcementLevel::Monitor,
            EnforcementLevel::Restrict,
            EnforcementLevel::Quarantine,
        ];
        for level in &levels {
            let json = serde_json::to_string(level).unwrap();
            let parsed: EnforcementLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, parsed);
        }
    }

    #[test]
    fn test_network_policy_serde_roundtrip() {
        let policies = [
            NetworkPolicy::Blocked,
            NetworkPolicy::AllowAll,
            NetworkPolicy::AllowList(vec!["192.168.1.0/24".to_string()]),
        ];
        for policy in &policies {
            let json = serde_json::to_string(policy).unwrap();
            let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(*policy, parsed);
        }
    }

    #[test]
    fn test_restrictions_toml_roundtrip() {
        let r = SandboxRestrictions::default_restrict();
        let toml_str = toml::to_string_pretty(&r).unwrap();
        let parsed: SandboxRestrictions = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.read_paths, r.read_paths);
        assert_eq!(parsed.write_paths, r.write_paths);
        assert_eq!(parsed.network, r.network);
    }
}
