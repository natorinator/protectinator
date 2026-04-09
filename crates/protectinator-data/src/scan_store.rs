//! Access to scan_history.db (read + write)

use crate::types::*;
use protectinator_core::{Finding, FindingSource, Severity};
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::info;

/// Scan history store (read + write)
pub struct ScanStore {
    conn: Connection,
}

impl ScanStore {
    /// Open the scan history database
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Self::open_empty(path);
        }
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open scan history: {}", e))?;
        // Migrate schema: add new columns if they don't exist
        conn.execute_batch(
            "ALTER TABLE findings ADD COLUMN actionability TEXT;",
        ).ok();
        conn.execute_batch(
            "ALTER TABLE findings ADD COLUMN debian_urgency TEXT;",
        ).ok();
        conn.execute_batch(
            "ALTER TABLE scans ADD COLUMN tags TEXT;",
        ).ok();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS remediation_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                actions_json TEXT NOT NULL,
                source_findings TEXT NOT NULL,
                approved_at TEXT,
                executed_at TEXT,
                result_json TEXT
            );",
        ).ok();
        Ok(Self { conn })
    }

    /// Create an empty database with schema
    fn open_empty(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to create scan history: {}", e))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_path TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                packages_scanned INTEGER NOT NULL DEFAULT 0,
                total_findings INTEGER NOT NULL DEFAULT 0,
                critical INTEGER NOT NULL DEFAULT 0,
                high INTEGER NOT NULL DEFAULT 0,
                medium INTEGER NOT NULL DEFAULT 0,
                low INTEGER NOT NULL DEFAULT 0,
                info INTEGER NOT NULL DEFAULT 0,
                tags TEXT
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
                actionability TEXT,
                debian_urgency TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_path, scanned_at DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_id ON findings(finding_id);
            CREATE TABLE IF NOT EXISTS remediation_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                actions_json TEXT NOT NULL,
                source_findings TEXT NOT NULL,
                approved_at TEXT,
                executed_at TEXT,
                result_json TEXT
            );",
        )
        .map_err(|e| format!("Failed to initialize schema: {}", e))?;
        Ok(Self { conn })
    }

    /// Total number of scans
    pub fn total_scan_count(&self) -> Result<usize, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .map_err(|e| format!("Query failed: {}", e))
    }

    /// Total number of findings across all scans
    pub fn total_finding_count(&self) -> Result<usize, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .map_err(|e| format!("Query failed: {}", e))
    }

    /// Most recent scan across all hosts
    pub fn most_recent_scan(&self) -> Result<Option<StoredScan>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, repo_path, scanned_at, packages_scanned, total_findings,
                        critical, high, medium, low, info
                 FROM scans ORDER BY scanned_at DESC LIMIT 1",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let result = stmt.query_row([], |row| row_to_scan(row)).ok();
        Ok(result)
    }

    /// List scans matching query parameters
    pub fn list_scans(&self, query: &ScanQuery) -> Result<Vec<StoredScan>, String> {
        let mut sql = String::from(
            "SELECT id, repo_path, scanned_at, packages_scanned, total_findings,
                    critical, high, medium, low, info
             FROM scans",
        );

        let mut conditions = Vec::new();
        if query.host.is_some() {
            conditions.push("repo_path = ?1");
        }
        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        sql.push_str(" ORDER BY scanned_at DESC");

        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0);
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| format!("Query failed: {}", e))?;

        let scans: Vec<StoredScan> = if let Some(ref host) = query.host {
            stmt.query_map(params![host], |row| row_to_scan(row))
                .map_err(|e| format!("Query failed: {}", e))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            stmt.query_map([], |row| row_to_scan(row))
                .map_err(|e| format!("Query failed: {}", e))?
                .filter_map(|r| r.ok())
                .collect()
        };

        Ok(scans)
    }

    /// Get a single scan by ID
    pub fn get_scan(&self, scan_id: i64) -> Result<Option<StoredScan>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, repo_path, scanned_at, packages_scanned, total_findings,
                        critical, high, medium, low, info
                 FROM scans WHERE id = ?1",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let result = stmt.query_row(params![scan_id], |row| row_to_scan(row)).ok();
        Ok(result)
    }

    /// Get findings for a scan
    pub fn scan_findings(&self, scan_id: i64) -> Result<Vec<StoredFinding>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, scan_id, finding_id, title, severity, resource, check_category, remediation, actionability, debian_urgency
                 FROM findings WHERE scan_id = ?1
                 ORDER BY CASE severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    WHEN 'Info' THEN 5
                    ELSE 6
                 END",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let findings = stmt
            .query_map(params![scan_id], |row| row_to_finding(row))
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(findings)
    }

    /// Query findings across all scans
    pub fn query_findings(&self, query: &FindingQuery) -> Result<Vec<StoredFinding>, String> {
        let mut sql = String::from(
            "SELECT f.id, f.scan_id, f.finding_id, f.title, f.severity, f.resource, f.check_category, f.remediation, f.actionability, f.debian_urgency
             FROM findings f",
        );

        let mut conditions = Vec::new();
        let mut param_idx = 1;
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref scan_id) = query.scan_id {
            conditions.push(format!("f.scan_id = ?{}", param_idx));
            params_vec.push(Box::new(*scan_id));
            param_idx += 1;
        }
        if let Some(ref severity) = query.severity {
            conditions.push(format!("f.severity = ?{}", param_idx));
            params_vec.push(Box::new(severity.clone()));
            param_idx += 1;
        }
        if let Some(ref category) = query.check_category {
            conditions.push(format!("f.check_category = ?{}", param_idx));
            params_vec.push(Box::new(category.clone()));
            param_idx += 1;
        }
        if let Some(ref actionability) = query.actionability {
            conditions.push(format!("f.actionability = ?{}", param_idx));
            params_vec.push(Box::new(actionability.clone()));
            // param_idx not needed after last use
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        sql.push_str(" ORDER BY f.id DESC");

        let limit = query.limit.unwrap_or(100);
        let offset = query.offset.unwrap_or(0);
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| format!("Query failed: {}", e))?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let findings = stmt
            .query_map(params_refs.as_slice(), |row| row_to_finding(row))
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(findings)
    }

    /// Get all unique hosts and their latest scan info
    pub fn list_hosts(&self) -> Result<Vec<HostSummary>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT repo_path, MAX(scanned_at) as last_scanned, COUNT(*) as scan_count
                 FROM scans
                 GROUP BY repo_path
                 ORDER BY last_scanned DESC",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let hosts: Vec<(String, String, usize)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, usize>(2)?,
                ))
            })
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        let mut result = Vec::new();
        for (name, last_scanned, scan_count) in hosts {
            // Get severity counts and tags from the most recent scan
            let latest = self
                .conn
                .query_row(
                    "SELECT critical, high, medium, low, info, tags
                     FROM scans WHERE repo_path = ?1
                     ORDER BY scanned_at DESC LIMIT 1",
                    params![name],
                    |row| {
                        Ok((
                            row.get::<_, usize>(0)?,
                            row.get::<_, usize>(1)?,
                            row.get::<_, usize>(2)?,
                            row.get::<_, usize>(3)?,
                            row.get::<_, usize>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .unwrap_or((0, 0, 0, 0, 0, None));

            let tags = latest.5
                .map(|t| t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default();

            result.push(HostSummary {
                name,
                last_scanned,
                scan_count,
                latest_critical: latest.0,
                latest_high: latest.1,
                latest_medium: latest.2,
                latest_low: latest.3,
                latest_info: latest.4,
                tags,
            });
        }

        Ok(result)
    }

    /// Get scan timeline for a specific host
    pub fn host_timeline(&self, host: &str, limit: usize) -> Result<Vec<StoredScan>, String> {
        let query = ScanQuery {
            host: Some(host.to_string()),
            limit: Some(limit),
            offset: None,
        };
        self.list_scans(&query)
    }

    /// Diff two scans by finding_id
    pub fn diff_scans(&self, scan_a: i64, scan_b: i64) -> Result<ScanDiff, String> {
        let findings_a = self.scan_findings(scan_a)?;
        let findings_b = self.scan_findings(scan_b)?;

        let ids_a: std::collections::HashSet<String> =
            findings_a.iter().map(|f| f.finding_id.clone()).collect();
        let ids_b: std::collections::HashSet<String> =
            findings_b.iter().map(|f| f.finding_id.clone()).collect();

        let new_findings = findings_b
            .into_iter()
            .filter(|f| !ids_a.contains(&f.finding_id))
            .collect();
        let resolved_findings = findings_a
            .into_iter()
            .filter(|f| !ids_b.contains(&f.finding_id))
            .collect();

        Ok(ScanDiff {
            new_findings,
            resolved_findings,
        })
    }

    /// Severity trend data for a host (for charts)
    pub fn host_trends(
        &self,
        host: &str,
        limit: usize,
    ) -> Result<Vec<StoredScan>, String> {
        // Returns scans in chronological order (oldest first) for charting
        let mut scans = self.host_timeline(host, limit)?;
        scans.reverse();
        Ok(scans)
    }

    /// Store scan results and return the scan ID
    pub fn store_scan(
        &self,
        scan_key: &str,
        findings: &[Finding],
        packages_scanned: usize,
    ) -> Result<i64, String> {
        self.store_scan_with_tags(scan_key, findings, packages_scanned, &[])
    }

    /// Store scan results with optional tags
    pub fn store_scan_with_tags(
        &self,
        scan_key: &str,
        findings: &[Finding],
        packages_scanned: usize,
        tags: &[String],
    ) -> Result<i64, String> {
        let now = chrono::Utc::now().to_rfc3339();

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

        let tags_str = if tags.is_empty() {
            None
        } else {
            Some(tags.join(","))
        };

        self.conn
            .execute(
                "INSERT INTO scans (repo_path, scanned_at, packages_scanned, total_findings, critical, high, medium, low, info, tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    scan_key,
                    now,
                    packages_scanned,
                    findings.len(),
                    critical,
                    high,
                    medium,
                    low,
                    info_count,
                    tags_str
                ],
            )
            .map_err(|e| format!("Failed to store scan: {}", e))?;

        let scan_id = self.conn.last_insert_rowid();

        for f in findings {
            let check_category = extract_check_category(&f.source);

            // Extract actionability class from metadata
            let actionability = f
                .metadata
                .get("actionability")
                .and_then(|v| v.get("class"))
                .and_then(|v| v.as_str())
                .map(String::from);

            // Extract debian urgency from metadata
            let debian_urgency = f
                .metadata
                .get("debian_urgency")
                .and_then(|v| v.as_str())
                .map(String::from);

            self.conn
                .execute(
                    "INSERT INTO findings (scan_id, finding_id, title, severity, resource, check_category, remediation, actionability, debian_urgency)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        scan_id,
                        f.id,
                        f.title,
                        f.severity.to_string(),
                        f.resource,
                        check_category,
                        f.remediation,
                        actionability,
                        debian_urgency,
                    ],
                )
                .map_err(|e| format!("Failed to store finding: {}", e))?;
        }

        info!("Stored scan {} for {} ({} findings)", scan_id, scan_key, findings.len());

        Ok(scan_id)
    }

    /// Store a remediation plan and return its ID
    pub fn store_plan(
        &self,
        host: &str,
        status: &str,
        actions_json: &str,
        source_findings: &str,
    ) -> Result<i64, String> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO remediation_plans (host, created_at, status, actions_json, source_findings)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![host, now, status, actions_json, source_findings],
            )
            .map_err(|e| format!("Failed to store plan: {}", e))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// List remediation plans with optional filters
    pub fn list_plans(
        &self,
        host: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<StoredPlan>, String> {
        let mut sql = String::from(
            "SELECT id, host, created_at, status, actions_json, source_findings, approved_at, executed_at, result_json
             FROM remediation_plans",
        );

        let mut conditions = Vec::new();
        let mut param_idx = 1;
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(h) = host {
            conditions.push(format!("host = ?{}", param_idx));
            params_vec.push(Box::new(h.to_string()));
            param_idx += 1;
        }
        if let Some(s) = status {
            conditions.push(format!("status = ?{}", param_idx));
            params_vec.push(Box::new(s.to_string()));
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        sql.push_str(" ORDER BY created_at DESC");

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| format!("Query failed: {}", e))?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let plans = stmt
            .query_map(params_refs.as_slice(), |row| row_to_plan(row))
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(plans)
    }

    /// Get a single plan by ID
    pub fn get_plan(&self, id: i64) -> Result<Option<StoredPlan>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, host, created_at, status, actions_json, source_findings, approved_at, executed_at, result_json
                 FROM remediation_plans WHERE id = ?1",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let result = stmt.query_row(params![id], |row| row_to_plan(row)).ok();
        Ok(result)
    }

    /// Update plan status, optionally setting an extra timestamp field
    pub fn update_plan_status(
        &self,
        id: i64,
        status: &str,
        extra_field: Option<(&str, &str)>,
    ) -> Result<(), String> {
        if let Some((field, value)) = extra_field {
            // Validate field name to prevent SQL injection
            let allowed = ["approved_at", "executed_at", "result_json"];
            if !allowed.contains(&field) {
                return Err(format!("Invalid extra field: {}", field));
            }
            let sql = format!(
                "UPDATE remediation_plans SET status = ?1, {} = ?2 WHERE id = ?3",
                field
            );
            self.conn
                .execute(&sql, params![status, value, id])
                .map_err(|e| format!("Failed to update plan: {}", e))?;
        } else {
            self.conn
                .execute(
                    "UPDATE remediation_plans SET status = ?1 WHERE id = ?2",
                    params![status, id],
                )
                .map_err(|e| format!("Failed to update plan: {}", e))?;
        }
        Ok(())
    }
}

fn row_to_scan(row: &rusqlite::Row) -> rusqlite::Result<StoredScan> {
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
}

/// Extract a category string from any FindingSource variant
fn extract_check_category(source: &FindingSource) -> Option<String> {
    match source {
        FindingSource::SupplyChain { check_category, .. } => Some(check_category.clone()),
        FindingSource::Hardening { category, .. } => Some(category.clone()),
        FindingSource::AgentDetection { category, .. } => Some(category.clone()),
        FindingSource::Persistence { persistence_type, .. } => Some(persistence_type.clone()),
        FindingSource::PrivilegeEscalation { vector_type, .. } => Some(vector_type.clone()),
        FindingSource::Sigma { rule_name, .. } => Some(rule_name.clone()),
        FindingSource::Yara { rule_name, .. } => Some(rule_name.clone()),
        FindingSource::FileIntegrity { change_type, .. } => Some(format!("{:?}", change_type)),
        FindingSource::OsVerification { .. } => Some("os_verification".to_string()),
        FindingSource::ProcessMonitor { .. } => Some("process_monitor".to_string()),
        FindingSource::LogAnalysis { log_source, .. } => Some(log_source.clone()),
        // For wrapped types, extract from inner source
        FindingSource::Container { inner_source, .. } => extract_check_category(inner_source),
        FindingSource::IoT { inner_source, .. } => extract_check_category(inner_source),
        FindingSource::Remote { inner_source, .. } => extract_check_category(inner_source),
        FindingSource::Secrets { check_category, .. } => Some(check_category.clone()),
        FindingSource::Defense { check_category, .. } => Some(check_category.clone()),
    }
}

fn row_to_plan(row: &rusqlite::Row) -> rusqlite::Result<StoredPlan> {
    Ok(StoredPlan {
        id: row.get(0)?,
        host: row.get(1)?,
        created_at: row.get(2)?,
        status: row.get(3)?,
        actions_json: row.get(4)?,
        source_findings: row.get(5)?,
        approved_at: row.get(6)?,
        executed_at: row.get(7)?,
        result_json: row.get(8)?,
    })
}

fn row_to_finding(row: &rusqlite::Row) -> rusqlite::Result<StoredFinding> {
    Ok(StoredFinding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        finding_id: row.get(2)?,
        title: row.get(3)?,
        severity: row.get(4)?,
        resource: row.get(5)?,
        check_category: row.get(6)?,
        remediation: row.get(7)?,
        actionability: row.get(8)?,
        debian_urgency: row.get(9)?,
    })
}
