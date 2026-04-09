//! Shared types for data queries and responses

use serde::{Deserialize, Serialize};

/// A stored scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredScan {
    pub id: i64,
    pub repo_path: String,
    pub scanned_at: String,
    pub packages_scanned: usize,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// A stored finding record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: i64,
    pub scan_id: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub resource: Option<String>,
    pub check_category: Option<String>,
    pub remediation: Option<String>,
    /// CVE actionability class (patchable_now, waiting_on_upstream, accepted_risk, disputed, unknown)
    pub actionability: Option<String>,
    /// Debian security tracker urgency (unimportant, low, medium, high, etc.)
    pub debian_urgency: Option<String>,
}

/// Query parameters for listing scans
#[derive(Debug, Default)]
pub struct ScanQuery {
    pub host: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Query parameters for filtering findings
#[derive(Debug, Default)]
pub struct FindingQuery {
    pub scan_id: Option<i64>,
    pub severity: Option<String>,
    pub check_category: Option<String>,
    pub actionability: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Host summary (aggregated from scan history)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSummary {
    pub name: String,
    pub last_scanned: String,
    pub scan_count: usize,
    pub latest_critical: usize,
    pub latest_high: usize,
    pub latest_medium: usize,
    pub latest_low: usize,
    pub latest_info: usize,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Scan diff between two scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub new_findings: Vec<StoredFinding>,
    pub resolved_findings: Vec<StoredFinding>,
}

/// Cached vulnerability classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVuln {
    pub advisory_id: String,
    pub severity_type: Option<String>,
    pub severity_score: Option<String>,
    pub cwe_ids: Option<String>,
    pub cached_at: String,
}

/// SBOM package entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub sbom_name: String,
    pub sbom_path: String,
}

/// Stored remediation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPlan {
    pub id: i64,
    pub host: String,
    pub created_at: String,
    pub status: String,
    pub actions_json: String,
    pub source_findings: String,
    pub approved_at: Option<String>,
    pub executed_at: Option<String>,
    pub result_json: Option<String>,
}

/// Overall data store status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStoreStatus {
    pub scan_count: usize,
    pub finding_count: usize,
    pub last_scan: Option<StoredScan>,
    pub vuln_cache_count: usize,
    pub sbom_count: usize,
}
