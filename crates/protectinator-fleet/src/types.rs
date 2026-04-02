//! Fleet scan result types

use protectinator_core::Finding;
use serde::{Deserialize, Serialize};

/// Complete results from a fleet scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetScanResults {
    pub timestamp: String,
    pub host_results: Vec<FleetTargetResult>,
    pub container_results: Vec<FleetTargetResult>,
    pub repo_results: Vec<FleetTargetResult>,
    pub summary: FleetSummary,
}

/// Result for a single scan target (host, container, or repo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTargetResult {
    /// Target identifier (host name, container name, repo path)
    pub name: String,
    /// Target type for display
    pub target_type: String,
    /// Total findings
    pub total_findings: usize,
    /// Severity breakdown
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// New findings since last scan (if diff available)
    pub new_findings: usize,
    /// Resolved findings since last scan
    pub resolved_findings: usize,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
    /// Error message if scan failed
    pub error: Option<String>,
}

/// Aggregated fleet summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    pub hosts_scanned: usize,
    pub containers_scanned: usize,
    pub repos_scanned: usize,
    pub hosts_failed: usize,
    pub total_findings: usize,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub total_info: usize,
    pub total_new_findings: usize,
    pub total_resolved_findings: usize,
    pub duration_ms: u64,
}

/// Findings that should trigger notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifiableFindings {
    pub new_critical: Vec<NotifiableFinding>,
    pub new_high: Vec<NotifiableFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifiableFinding {
    pub host: String,
    pub title: String,
    pub severity: String,
    pub resource: Option<String>,
}

impl FleetTargetResult {
    pub fn from_findings(name: String, target_type: &str, findings: &[Finding], duration_ms: u64) -> Self {
        let mut r = Self {
            name,
            target_type: target_type.to_string(),
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            new_findings: 0,
            resolved_findings: 0,
            duration_ms,
            error: None,
        };
        for f in findings {
            match f.severity {
                protectinator_core::Severity::Critical => r.critical += 1,
                protectinator_core::Severity::High => r.high += 1,
                protectinator_core::Severity::Medium => r.medium += 1,
                protectinator_core::Severity::Low => r.low += 1,
                protectinator_core::Severity::Info => r.info += 1,
            }
        }
        r
    }

    pub fn error(name: String, target_type: &str, error: String) -> Self {
        Self {
            name,
            target_type: target_type.to_string(),
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            new_findings: 0,
            resolved_findings: 0,
            duration_ms: 0,
            error: Some(error),
        }
    }
}

impl FleetSummary {
    pub fn from_results(
        host_results: &[FleetTargetResult],
        container_results: &[FleetTargetResult],
        repo_results: &[FleetTargetResult],
        duration_ms: u64,
    ) -> Self {
        let all: Vec<&FleetTargetResult> = host_results
            .iter()
            .chain(container_results.iter())
            .chain(repo_results.iter())
            .collect();

        Self {
            hosts_scanned: host_results.iter().filter(|r| r.error.is_none()).count(),
            containers_scanned: container_results.iter().filter(|r| r.error.is_none()).count(),
            repos_scanned: repo_results.iter().filter(|r| r.error.is_none()).count(),
            hosts_failed: host_results.iter().filter(|r| r.error.is_some()).count(),
            total_findings: all.iter().map(|r| r.total_findings).sum(),
            total_critical: all.iter().map(|r| r.critical).sum(),
            total_high: all.iter().map(|r| r.high).sum(),
            total_medium: all.iter().map(|r| r.medium).sum(),
            total_low: all.iter().map(|r| r.low).sum(),
            total_info: all.iter().map(|r| r.info).sum(),
            total_new_findings: all.iter().map(|r| r.new_findings).sum(),
            total_resolved_findings: all.iter().map(|r| r.resolved_findings).sum(),
            duration_ms,
        }
    }
}
