//! Finding suppression
//!
//! Allows users to suppress specific findings by ID, title pattern,
//! or resource pattern. Suppressions are loaded from a TOML config file.

use crate::Finding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Suppression configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Suppressions {
    /// Individual suppression rules
    #[serde(default)]
    pub rules: Vec<SuppressionRule>,
}

/// A single suppression rule — finding is suppressed if ALL specified fields match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    /// Optional comment explaining why this is suppressed
    pub reason: Option<String>,

    /// Match finding ID exactly
    pub finding_id: Option<String>,

    /// Match title containing this substring (case-insensitive)
    pub title_contains: Option<String>,

    /// Match resource containing this substring (case-insensitive)
    pub resource_contains: Option<String>,

    /// Match only for specific hosts (by scan key prefix, e.g. "container:dev-")
    pub host_pattern: Option<String>,
}

impl Suppressions {
    /// Load suppressions from the default config path
    pub fn load_default() -> Self {
        match Self::default_path() {
            Ok(path) if path.exists() => Self::load(&path).unwrap_or_default(),
            _ => Self::default(),
        }
    }

    /// Load suppressions from a specific file
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read suppressions: {}", e))?;
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse suppressions: {}", e))
    }

    /// Default suppressions file path
    pub fn default_path() -> Result<PathBuf, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        Ok(PathBuf::from(home).join(".config/protectinator/suppressions.toml"))
    }

    /// Check if a finding should be suppressed
    pub fn is_suppressed(&self, finding: &Finding, scan_key: Option<&str>) -> bool {
        self.rules.iter().any(|rule| rule.matches(finding, scan_key))
    }

    /// Filter a list of findings, removing suppressed ones
    pub fn filter(&self, findings: Vec<Finding>, scan_key: Option<&str>) -> Vec<Finding> {
        if self.rules.is_empty() {
            return findings;
        }
        findings
            .into_iter()
            .filter(|f| !self.is_suppressed(f, scan_key))
            .collect()
    }

    /// Generate a template suppressions file
    pub fn template() -> String {
        r#"# Protectinator Suppressions
#
# Suppress specific findings by ID, title, or resource pattern.
# All specified fields in a rule must match for the finding to be suppressed.

# Example: suppress SUID findings for disk images inside containers
# [[rules]]
# reason = "SUID binaries in nspawn container filesystems are expected"
# title_contains = "non-standard location"
# resource_contains = "/var/lib/machines/"

# Example: suppress a specific CVE you've accepted the risk for
# [[rules]]
# reason = "Accepted risk - not exploitable in our config"
# finding_id = "DEBIAN-CVE-2001-1534"

# Example: suppress info-level findings for a specific container
# [[rules]]
# reason = "Dev container, don't care about login shells"
# title_contains = "login shells"
# host_pattern = "container:dev-"
"#
        .to_string()
    }
}

impl SuppressionRule {
    fn matches(&self, finding: &Finding, scan_key: Option<&str>) -> bool {
        // All specified fields must match
        if let Some(ref id) = self.finding_id {
            if finding.id != *id {
                return false;
            }
        }

        if let Some(ref pattern) = self.title_contains {
            if !finding.title.to_lowercase().contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        if let Some(ref pattern) = self.resource_contains {
            match &finding.resource {
                Some(resource) => {
                    if !resource.to_lowercase().contains(&pattern.to_lowercase()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(ref pattern) = self.host_pattern {
            match scan_key {
                Some(key) => {
                    if !key.contains(pattern) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}
