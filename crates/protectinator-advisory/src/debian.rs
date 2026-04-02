//! Debian Security Tracker client
//!
//! Fetches and parses CVE data from the Debian Security Tracker's bulk JSON endpoint.

use crate::error::AdvisoryError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

/// URL for the Debian Security Tracker bulk JSON data
const TRACKER_URL: &str = "https://security-tracker.debian.org/tracker/data/json";

/// Raw per-release status from the Debian tracker JSON
#[derive(Debug, Clone, Deserialize)]
pub struct RawReleaseStatus {
    pub status: Option<String>,
    pub fixed_version: Option<String>,
    pub urgency: Option<String>,
    #[serde(default)]
    pub nodsa: Option<String>,
    #[serde(default)]
    pub nodsa_reason: Option<String>,
}

/// Raw CVE entry from the Debian tracker JSON
#[derive(Debug, Clone, Deserialize)]
pub struct RawDebianCve {
    #[serde(default)]
    pub releases: HashMap<String, RawReleaseStatus>,
    pub scope: Option<String>,
    pub description: Option<String>,
}

/// Status of a CVE in the Debian tracker
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackerStatus {
    /// Fix has been released
    Resolved,
    /// No fix available yet
    Unfixed,
    /// Status not yet determined
    Undetermined,
    /// Package/release is not affected
    NotAffected,
}

impl TrackerStatus {
    /// Parse a status string from the Debian tracker
    pub fn parse(s: &str) -> Self {
        let cleaned = strip_tags(s).to_lowercase();
        match cleaned.trim() {
            "resolved" => TrackerStatus::Resolved,
            "open" => TrackerStatus::Unfixed,
            "undetermined" => TrackerStatus::Undetermined,
            "not affected" | "not-affected" => TrackerStatus::NotAffected,
            _ => {
                // Default unfixed for unknown statuses
                debug!("Unknown Debian tracker status: {}", s);
                TrackerStatus::Unfixed
            }
        }
    }
}

impl std::fmt::Display for TrackerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrackerStatus::Resolved => write!(f, "resolved"),
            TrackerStatus::Unfixed => write!(f, "unfixed"),
            TrackerStatus::Undetermined => write!(f, "undetermined"),
            TrackerStatus::NotAffected => write!(f, "not_affected"),
        }
    }
}

/// Sub-state modifiers on a CVE status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubState {
    /// No sub-state
    None,
    /// Debian security team has decided not to issue a DSA
    Ignored,
    /// Fix postponed for a future point release
    Postponed,
}

impl SubState {
    /// Parse sub-state from a status string by extracting angle-bracket tags
    pub fn parse(status: &str, nodsa: Option<&str>) -> Self {
        let lower = status.to_lowercase();
        if lower.contains("<ignored>") || lower.contains("ignored") {
            return SubState::Ignored;
        }
        if lower.contains("<postponed>") || lower.contains("postponed") {
            return SubState::Postponed;
        }
        // nodsa field also indicates ignored
        if let Some(val) = nodsa {
            if !val.is_empty() {
                return SubState::Ignored;
            }
        }
        SubState::None
    }
}

impl std::fmt::Display for SubState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubState::None => write!(f, "none"),
            SubState::Ignored => write!(f, "ignored"),
            SubState::Postponed => write!(f, "postponed"),
        }
    }
}

/// Parsed CVE entry from the Debian Security Tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebianCveEntry {
    /// CVE identifier (e.g. "CVE-2024-1234")
    pub cve_id: String,
    /// Tracker status for this release
    pub status: TrackerStatus,
    /// Sub-state modifier
    pub sub_state: SubState,
    /// Urgency level from the tracker
    pub urgency: String,
    /// Fixed version (if resolved)
    pub fixed_version: Option<String>,
    /// Scope (remote, local, etc.)
    pub scope: Option<String>,
    /// Description of the vulnerability
    pub description: Option<String>,
}

/// Client for the Debian Security Tracker
pub struct DebianTracker {
    agent: ureq::Agent,
}

impl DebianTracker {
    /// Create a new Debian tracker client
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(30))
            .build();
        Self { agent }
    }

    /// Fetch the entire Debian Security Tracker dataset
    ///
    /// Returns a map of source_package -> cve_id -> RawDebianCve
    pub fn fetch_all(
        &self,
    ) -> Result<HashMap<String, HashMap<String, RawDebianCve>>, AdvisoryError> {
        debug!("Fetching Debian Security Tracker data from {}", TRACKER_URL);

        let response = self
            .agent
            .get(TRACKER_URL)
            .set("Accept-Encoding", "gzip")
            .call()
            .map_err(|e| AdvisoryError::Http(format!("Failed to fetch tracker data: {}", e)))?;

        let data: HashMap<String, HashMap<String, RawDebianCve>> = response
            .into_json()
            .map_err(|e| AdvisoryError::Parse(format!("Failed to parse tracker JSON: {}", e)))?;

        debug!("Fetched {} source packages from tracker", data.len());
        Ok(data)
    }

    /// Parse raw tracker data into structured entries for a specific release
    pub fn parse_for_release(
        raw: &HashMap<String, HashMap<String, RawDebianCve>>,
        release: &str,
    ) -> Vec<(String, String, DebianCveEntry)> {
        let mut entries = Vec::new();

        for (source_pkg, cves) in raw {
            for (cve_id, raw_cve) in cves {
                if let Some(rel_status) = raw_cve.releases.get(release) {
                    let status_str = rel_status.status.as_deref().unwrap_or("undetermined");
                    let status = TrackerStatus::parse(status_str);
                    let sub_state =
                        SubState::parse(status_str, rel_status.nodsa.as_deref());
                    let urgency = rel_status
                        .urgency
                        .as_deref()
                        .unwrap_or("not yet assigned")
                        .to_string();

                    let entry = DebianCveEntry {
                        cve_id: cve_id.clone(),
                        status,
                        sub_state,
                        urgency,
                        fixed_version: rel_status.fixed_version.clone(),
                        scope: raw_cve.scope.clone(),
                        description: raw_cve.description.clone(),
                    };

                    entries.push((source_pkg.clone(), cve_id.clone(), entry));
                }
            }
        }

        entries
    }
}

impl Default for DebianTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the current Debian release codename by reading /etc/os-release
pub fn detect_debian_release() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("VERSION_CODENAME=") {
            let codename = value.trim().trim_matches('"').to_string();
            if !codename.is_empty() {
                return Some(codename);
            }
        }
    }

    // Fallback: try ID and VERSION_ID for Debian
    let mut is_debian = false;
    for line in content.lines() {
        if line.starts_with("ID=") {
            let id = line
                .strip_prefix("ID=")
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            if id == "debian" {
                is_debian = true;
            }
        }
    }

    if is_debian {
        warn!("Debian detected but VERSION_CODENAME not found in /etc/os-release");
    }

    None
}

/// Strip angle-bracket tags from a status string
fn strip_tags(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_status_parse() {
        assert_eq!(TrackerStatus::parse("resolved"), TrackerStatus::Resolved);
        assert_eq!(TrackerStatus::parse("open"), TrackerStatus::Unfixed);
        assert_eq!(
            TrackerStatus::parse("undetermined"),
            TrackerStatus::Undetermined
        );
        assert_eq!(
            TrackerStatus::parse("not affected"),
            TrackerStatus::NotAffected
        );
        // Unknown defaults to Unfixed
        assert_eq!(TrackerStatus::parse("something_else"), TrackerStatus::Unfixed);
    }

    #[test]
    fn test_tracker_status_with_tags() {
        assert_eq!(
            TrackerStatus::parse("<ignored>resolved"),
            TrackerStatus::Resolved
        );
        assert_eq!(
            TrackerStatus::parse("open<postponed>"),
            TrackerStatus::Unfixed
        );
    }

    #[test]
    fn test_sub_state_parse() {
        assert_eq!(SubState::parse("open", None), SubState::None);
        assert_eq!(SubState::parse("<ignored>open", None), SubState::Ignored);
        assert_eq!(
            SubState::parse("open<postponed>", None),
            SubState::Postponed
        );
        assert_eq!(SubState::parse("open", Some("true")), SubState::Ignored);
        assert_eq!(SubState::parse("open", Some("")), SubState::None);
    }

    #[test]
    fn test_strip_tags() {
        assert_eq!(strip_tags("resolved"), "resolved");
        assert_eq!(strip_tags("<ignored>resolved"), "resolved");
        assert_eq!(strip_tags("open<postponed>"), "open");
        assert_eq!(strip_tags("<a><b>text<c>"), "text");
    }

    #[test]
    fn test_parse_sample_tracker_json() {
        let json = r#"{
            "curl": {
                "CVE-2024-1234": {
                    "releases": {
                        "bookworm": {
                            "status": "resolved",
                            "fixed_version": "7.88.1-10+deb12u5",
                            "urgency": "medium"
                        },
                        "trixie": {
                            "status": "open",
                            "urgency": "not yet assigned"
                        }
                    },
                    "scope": "remote",
                    "description": "Buffer overflow in curl"
                }
            },
            "openssl": {
                "CVE-2024-5678": {
                    "releases": {
                        "bookworm": {
                            "status": "open",
                            "urgency": "unimportant",
                            "nodsa": "true"
                        }
                    },
                    "scope": "remote",
                    "description": "Minor issue in openssl"
                }
            }
        }"#;

        let raw: HashMap<String, HashMap<String, RawDebianCve>> =
            serde_json::from_str(json).expect("Failed to parse sample JSON");

        assert_eq!(raw.len(), 2);
        assert!(raw.contains_key("curl"));
        assert!(raw.contains_key("openssl"));

        // Parse for bookworm
        let entries = DebianTracker::parse_for_release(&raw, "bookworm");
        assert_eq!(entries.len(), 2);

        // Find the curl entry
        let curl_entry = entries
            .iter()
            .find(|(pkg, cve, _)| pkg == "curl" && cve == "CVE-2024-1234")
            .map(|(_, _, e)| e)
            .expect("curl entry not found");
        assert_eq!(curl_entry.status, TrackerStatus::Resolved);
        assert_eq!(
            curl_entry.fixed_version.as_deref(),
            Some("7.88.1-10+deb12u5")
        );
        assert_eq!(curl_entry.urgency, "medium");
        assert_eq!(curl_entry.sub_state, SubState::None);

        // Find the openssl entry
        let openssl_entry = entries
            .iter()
            .find(|(pkg, _, _)| pkg == "openssl")
            .map(|(_, _, e)| e)
            .expect("openssl entry not found");
        assert_eq!(openssl_entry.status, TrackerStatus::Unfixed);
        assert_eq!(openssl_entry.sub_state, SubState::Ignored);
        assert_eq!(openssl_entry.urgency, "unimportant");

        // Parse for trixie — should only have curl
        let trixie_entries = DebianTracker::parse_for_release(&raw, "trixie");
        assert_eq!(trixie_entries.len(), 1);
        assert_eq!(trixie_entries[0].0, "curl");
        assert_eq!(trixie_entries[0].2.status, TrackerStatus::Unfixed);
    }

    #[test]
    fn test_detect_debian_release_missing_file() {
        // On non-Debian systems or in test envs, this returns None or a codename
        // We just verify it doesn't panic
        let _result = detect_debian_release();
    }

    #[test]
    fn test_debian_cve_entry_serialization() {
        let entry = DebianCveEntry {
            cve_id: "CVE-2024-1234".to_string(),
            status: TrackerStatus::Resolved,
            sub_state: SubState::None,
            urgency: "high".to_string(),
            fixed_version: Some("1.2.3-4".to_string()),
            scope: Some("remote".to_string()),
            description: Some("Test vuln".to_string()),
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let deserialized: DebianCveEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.cve_id, "CVE-2024-1234");
        assert_eq!(deserialized.status, TrackerStatus::Resolved);
        assert_eq!(deserialized.sub_state, SubState::None);
    }
}
