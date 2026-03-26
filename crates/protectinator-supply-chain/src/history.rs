//! Scan history storage and diff-based alerting
//!
//! Stores scan results in a SQLite database and provides diff logic
//! to identify only net-new findings since the last scan of the same repo.

use chrono::Utc;
use protectinator_core::{Finding, Severity};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Default database path
const DEFAULT_DB_DIR: &str = ".local/share/protectinator";
const DB_FILENAME: &str = "scan_history.db";

/// A stored finding record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub resource: Option<String>,
    pub check_category: Option<String>,
    pub remediation: Option<String>,
}

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

/// Diff result comparing current scan against previous
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    /// Findings that are new since the last scan
    pub new_findings: Vec<Finding>,
    /// Findings that were resolved (present before, gone now)
    pub resolved_findings: Vec<StoredFinding>,
    /// Whether a previous scan existed to diff against
    pub has_baseline: bool,
    /// When the baseline scan was run
    pub baseline_timestamp: Option<String>,
}

/// Scan history database
pub struct ScanHistory {
    conn: Connection,
}

impl ScanHistory {
    /// Open the history database at the default location
    pub fn open_default() -> Result<Self, String> {
        let db_path = default_db_path()?;
        Self::open(&db_path)
    }

    /// Open the history database at a specific path
    pub fn open(path: &Path) -> Result<Self, String> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create database directory: {}", e))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let history = Self { conn };
        history.init_schema()?;
        Ok(history)
    }

    /// Open an in-memory database (for testing)
    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory database: {}", e))?;
        let history = Self { conn };
        history.init_schema()?;
        Ok(history)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_path TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                packages_scanned INTEGER NOT NULL DEFAULT 0,
                total_findings INTEGER NOT NULL DEFAULT 0,
                critical INTEGER NOT NULL DEFAULT 0,
                high INTEGER NOT NULL DEFAULT 0,
                medium INTEGER NOT NULL DEFAULT 0,
                low INTEGER NOT NULL DEFAULT 0,
                info INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                resource TEXT,
                check_category TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_path, scanned_at DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_id ON findings(finding_id);
            ",
            )
            .map_err(|e| format!("Failed to initialize schema: {}", e))?;

        Ok(())
    }

    /// Store scan results and return the scan ID
    pub fn store_scan(
        &self,
        repo_path: &str,
        findings: &[Finding],
        packages_scanned: usize,
    ) -> Result<i64, String> {
        let now = Utc::now().to_rfc3339();

        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info_count = 0usize;

        for f in findings {
            match f.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info_count += 1,
            }
        }

        self.conn
            .execute(
                "INSERT INTO scans (repo_path, scanned_at, packages_scanned, total_findings, critical, high, medium, low, info)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    repo_path,
                    now,
                    packages_scanned,
                    findings.len(),
                    critical,
                    high,
                    medium,
                    low,
                    info_count
                ],
            )
            .map_err(|e| format!("Failed to store scan: {}", e))?;

        let scan_id = self.conn.last_insert_rowid();

        // Store individual findings
        for f in findings {
            let check_category = extract_check_category(&f.source);
            self.conn
                .execute(
                    "INSERT INTO findings (scan_id, finding_id, title, severity, resource, check_category, remediation)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        scan_id,
                        f.id,
                        f.title,
                        f.severity.to_string(),
                        f.resource,
                        check_category,
                        f.remediation,
                    ],
                )
                .map_err(|e| format!("Failed to store finding: {}", e))?;
        }

        info!(
            "Stored scan {} for {} ({} findings)",
            scan_id,
            repo_path,
            findings.len()
        );

        Ok(scan_id)
    }

    /// Get the most recent scan for a repo
    pub fn latest_scan(&self, repo_path: &str) -> Result<Option<StoredScan>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, repo_path, scanned_at, packages_scanned, total_findings,
                        critical, high, medium, low, info
                 FROM scans WHERE repo_path = ?1
                 ORDER BY scanned_at DESC LIMIT 1",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let result = stmt
            .query_row(params![repo_path], |row| {
                Ok(StoredScan {
                    id: row.get(0)?,
                    repo_path: row.get(1)?,
                    scanned_at: row.get(2)?,
                    packages_scanned: row.get(3)?,
                    total_findings: row.get(4)?,
                    critical: row.get(5)?,
                    high: row.get(6)?,
                    medium: row.get(7)?,
                    low: row.get(8)?,
                    info: row.get(9)?,
                })
            })
            .ok();

        Ok(result)
    }

    /// Get findings from a specific scan
    pub fn scan_findings(&self, scan_id: i64) -> Result<Vec<StoredFinding>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT finding_id, title, severity, resource, check_category, remediation
                 FROM findings WHERE scan_id = ?1",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let findings = stmt
            .query_map(params![scan_id], |row| {
                Ok(StoredFinding {
                    finding_id: row.get(0)?,
                    title: row.get(1)?,
                    severity: row.get(2)?,
                    resource: row.get(3)?,
                    check_category: row.get(4)?,
                    remediation: row.get(5)?,
                })
            })
            .map_err(|e| format!("Failed to query findings: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(findings)
    }

    /// Compute diff: given current findings, compare against the latest stored scan
    /// for the same repo. Returns only net-new and resolved findings.
    pub fn diff(
        &self,
        repo_path: &str,
        current_findings: &[Finding],
    ) -> Result<ScanDiff, String> {
        let previous = self.latest_scan(repo_path)?;

        let Some(prev_scan) = previous else {
            debug!("No previous scan found for {} — all findings are new", repo_path);
            return Ok(ScanDiff {
                new_findings: current_findings.to_vec(),
                resolved_findings: Vec::new(),
                has_baseline: false,
                baseline_timestamp: None,
            });
        };

        let prev_findings = self.scan_findings(prev_scan.id)?;

        // Build set of previous finding fingerprints (id + title)
        let prev_set: HashSet<String> = prev_findings
            .iter()
            .map(|f| finding_fingerprint_stored(f))
            .collect();

        // Build set of current finding fingerprints
        let current_set: HashSet<String> = current_findings
            .iter()
            .map(|f| finding_fingerprint(f))
            .collect();

        // New: in current but not in previous
        let new_findings: Vec<Finding> = current_findings
            .iter()
            .filter(|f| !prev_set.contains(&finding_fingerprint(f)))
            .cloned()
            .collect();

        // Resolved: in previous but not in current
        let resolved_findings: Vec<StoredFinding> = prev_findings
            .into_iter()
            .filter(|f| !current_set.contains(&finding_fingerprint_stored(f)))
            .collect();

        info!(
            "Diff against scan from {}: {} new, {} resolved",
            prev_scan.scanned_at,
            new_findings.len(),
            resolved_findings.len()
        );

        Ok(ScanDiff {
            new_findings,
            resolved_findings,
            has_baseline: true,
            baseline_timestamp: Some(prev_scan.scanned_at),
        })
    }

    /// List scan history for a repo
    pub fn list_scans(
        &self,
        repo_path: &str,
        limit: usize,
    ) -> Result<Vec<StoredScan>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, repo_path, scanned_at, packages_scanned, total_findings,
                        critical, high, medium, low, info
                 FROM scans WHERE repo_path = ?1
                 ORDER BY scanned_at DESC LIMIT ?2",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let limit_i64 = limit.min(i64::MAX as usize) as i64;
        let scans = stmt
            .query_map(params![repo_path, limit_i64], |row| {
                Ok(StoredScan {
                    id: row.get(0)?,
                    repo_path: row.get(1)?,
                    scanned_at: row.get(2)?,
                    packages_scanned: row.get(3)?,
                    total_findings: row.get(4)?,
                    critical: row.get(5)?,
                    high: row.get(6)?,
                    medium: row.get(7)?,
                    low: row.get(8)?,
                    info: row.get(9)?,
                })
            })
            .map_err(|e| format!("Failed to query scans: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(scans)
    }

    /// List all repos that have been scanned
    pub fn list_repos(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT repo_path FROM scans ORDER BY repo_path",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let repos = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| format!("Failed to query repos: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(repos)
    }

    /// Delete old scans, keeping the N most recent per repo
    pub fn prune(&self, keep_per_repo: usize) -> Result<usize, String> {
        // Get all repos
        let repos = self.list_repos()?;
        let mut total_deleted = 0;

        for repo in repos {
            let scans = self.list_scans(&repo, usize::MAX)?;
            if scans.len() <= keep_per_repo {
                continue;
            }

            let to_delete: Vec<i64> = scans[keep_per_repo..]
                .iter()
                .map(|s| s.id)
                .collect();

            for scan_id in &to_delete {
                self.conn
                    .execute("DELETE FROM findings WHERE scan_id = ?1", params![scan_id])
                    .map_err(|e| format!("Failed to delete findings: {}", e))?;
                self.conn
                    .execute("DELETE FROM scans WHERE id = ?1", params![scan_id])
                    .map_err(|e| format!("Failed to delete scan: {}", e))?;
                total_deleted += 1;
            }
        }

        Ok(total_deleted)
    }
}

/// Create a fingerprint for a Finding to use in diff comparison.
/// Uses id + title as the key — this ensures that the same check finding
/// on the same resource is considered the same across scans.
fn finding_fingerprint(f: &Finding) -> String {
    format!(
        "{}:{}:{}",
        f.id,
        f.title,
        f.resource.as_deref().unwrap_or("")
    )
}

/// Same fingerprint but from a StoredFinding
fn finding_fingerprint_stored(f: &StoredFinding) -> String {
    format!(
        "{}:{}:{}",
        f.finding_id,
        f.title,
        f.resource.as_deref().unwrap_or("")
    )
}

/// Extract check_category from a FindingSource
fn extract_check_category(source: &protectinator_core::FindingSource) -> Option<String> {
    match source {
        protectinator_core::FindingSource::SupplyChain {
            check_category, ..
        } => Some(check_category.clone()),
        _ => None,
    }
}

/// Get the default database path
fn default_db_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home)
        .join(DEFAULT_DB_DIR)
        .join(DB_FILENAME))
}

/// Get the default database path (public for CLI)
pub fn get_default_db_path() -> Result<PathBuf, String> {
    default_db_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protectinator_core::{Finding, FindingSource, Severity};

    fn make_finding(id: &str, title: &str, severity: Severity, resource: Option<&str>) -> Finding {
        let mut f = Finding::new(
            id,
            title,
            "test description",
            severity,
            FindingSource::SupplyChain {
                check_category: "test".to_string(),
                ecosystem: None,
            },
        );
        if let Some(r) = resource {
            f = f.with_resource(r);
        }
        f
    }

    #[test]
    fn test_store_and_retrieve_scan() {
        let db = ScanHistory::open_memory().unwrap();
        let findings = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, Some("/Cargo.lock")),
            make_finding("vuln-2", "CVE-2024-5678", Severity::Critical, Some("/Cargo.lock")),
        ];

        let scan_id = db.store_scan("/test/repo", &findings, 100).unwrap();
        assert!(scan_id > 0);

        let latest = db.latest_scan("/test/repo").unwrap().unwrap();
        assert_eq!(latest.total_findings, 2);
        assert_eq!(latest.critical, 1);
        assert_eq!(latest.high, 1);
        assert_eq!(latest.packages_scanned, 100);

        let stored = db.scan_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 2);
    }

    #[test]
    fn test_diff_no_baseline() {
        let db = ScanHistory::open_memory().unwrap();
        let findings = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, None),
        ];

        let diff = db.diff("/test/repo", &findings).unwrap();
        assert!(!diff.has_baseline);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 0);
    }

    #[test]
    fn test_diff_detects_new_findings() {
        let db = ScanHistory::open_memory().unwrap();

        // Store baseline with 1 finding
        let baseline = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, Some("/Cargo.lock")),
        ];
        db.store_scan("/test/repo", &baseline, 100).unwrap();

        // Current scan has 2 findings (1 old, 1 new)
        let current = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, Some("/Cargo.lock")),
            make_finding("vuln-2", "CVE-2024-9999", Severity::Critical, Some("/Cargo.lock")),
        ];

        let diff = db.diff("/test/repo", &current).unwrap();
        assert!(diff.has_baseline);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].id, "vuln-2");
        assert_eq!(diff.resolved_findings.len(), 0);
    }

    #[test]
    fn test_diff_detects_resolved_findings() {
        let db = ScanHistory::open_memory().unwrap();

        // Store baseline with 2 findings
        let baseline = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, Some("/Cargo.lock")),
            make_finding("vuln-2", "CVE-2024-5678", Severity::Medium, Some("/Cargo.lock")),
        ];
        db.store_scan("/test/repo", &baseline, 100).unwrap();

        // Current scan has only 1 finding (the other was fixed)
        let current = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, Some("/Cargo.lock")),
        ];

        let diff = db.diff("/test/repo", &current).unwrap();
        assert!(diff.has_baseline);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0].finding_id, "vuln-2");
    }

    #[test]
    fn test_diff_no_changes() {
        let db = ScanHistory::open_memory().unwrap();

        let findings = vec![
            make_finding("vuln-1", "CVE-2024-1234", Severity::High, Some("/Cargo.lock")),
        ];
        db.store_scan("/test/repo", &findings, 100).unwrap();

        let diff = db.diff("/test/repo", &findings).unwrap();
        assert!(diff.has_baseline);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 0);
    }

    #[test]
    fn test_list_scans() {
        let db = ScanHistory::open_memory().unwrap();

        db.store_scan("/repo1", &[], 10).unwrap();
        db.store_scan("/repo1", &[], 20).unwrap();
        db.store_scan("/repo2", &[], 30).unwrap();

        let repo1_scans = db.list_scans("/repo1", 10).unwrap();
        assert_eq!(repo1_scans.len(), 2);
        // Most recent first
        assert_eq!(repo1_scans[0].packages_scanned, 20);

        let repos = db.list_repos().unwrap();
        assert_eq!(repos.len(), 2);
    }

    #[test]
    fn test_prune() {
        let db = ScanHistory::open_memory().unwrap();

        db.store_scan("/repo", &[], 10).unwrap();
        db.store_scan("/repo", &[], 20).unwrap();
        db.store_scan("/repo", &[], 30).unwrap();
        db.store_scan("/repo", &[], 40).unwrap();

        let deleted = db.prune(2).unwrap();
        assert_eq!(deleted, 2);

        let remaining = db.list_scans("/repo", 10).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].packages_scanned, 40); // newest kept
    }

    #[test]
    fn test_no_previous_scan_returns_none() {
        let db = ScanHistory::open_memory().unwrap();
        let latest = db.latest_scan("/nonexistent").unwrap();
        assert!(latest.is_none());
    }
}
