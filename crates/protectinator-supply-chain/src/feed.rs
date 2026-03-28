//! Feed monitoring for supply chain advisories
//!
//! Polls the OSV API for new advisories affecting packages in stored SBOMs,
//! compares against previously known advisories, and reports only net-new alerts.

use crate::osv::{classify_vulnerability, map_cvss_to_severity, OsvClient, OsvVulnerability};
use crate::types::{Ecosystem, PackageEntry};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Default SBOM storage directory relative to HOME
const SBOM_DIR: &str = ".local/share/protectinator/sboms";

/// Default database directory and filename (shared with scan history)
const DEFAULT_DB_DIR: &str = ".local/share/protectinator";
const DB_FILENAME: &str = "scan_history.db";

/// Result of checking feeds for new advisories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedCheckResult {
    pub repos_checked: usize,
    pub packages_checked: usize,
    pub new_advisories: Vec<NewAdvisory>,
    pub total_known_advisories: usize,
}

/// A newly discovered advisory not previously seen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAdvisory {
    pub advisory_id: String,
    pub summary: Option<String>,
    pub severity: String,
    pub classification: String,
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: String,
    pub repo_name: String,
    pub aliases: Vec<String>,
}

/// Summary of the current advisory state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSummary {
    pub total_advisories: usize,
    pub unnotified: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_ecosystem: HashMap<String, usize>,
}

/// A stored advisory record from the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAdvisory {
    pub advisory_id: String,
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: String,
    pub severity: Option<String>,
    pub summary: Option<String>,
    pub first_seen: String,
    pub notified: bool,
}

/// Feed monitor that tracks advisory state in SQLite
pub struct FeedMonitor {
    conn: Connection,
}

impl FeedMonitor {
    /// Open the feed monitor database at the default location
    /// (~/.local/share/protectinator/scan_history.db)
    pub fn open_default() -> Result<Self, String> {
        let db_path = default_db_path()?;
        Self::open(&db_path)
    }

    /// Open the feed monitor database at a specific path
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create database directory: {}", e))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let monitor = Self { conn };
        monitor.init_schema()?;
        Ok(monitor)
    }

    /// Open an in-memory database (for testing)
    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory database: {}", e))?;
        let monitor = Self { conn };
        monitor.init_schema()?;
        Ok(monitor)
    }

    /// Initialize the advisory_state table
    fn init_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS advisory_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    advisory_id TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    severity TEXT,
                    summary TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    notified INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(advisory_id, package_name, package_version)
                );

                CREATE INDEX IF NOT EXISTS idx_advisory_state_pkg
                    ON advisory_state(package_name);
                CREATE INDEX IF NOT EXISTS idx_advisory_state_advisory
                    ON advisory_state(advisory_id);
                CREATE INDEX IF NOT EXISTS idx_advisory_state_notified
                    ON advisory_state(notified);",
            )
            .map_err(|e| format!("Failed to initialize advisory_state schema: {}", e))?;

        Ok(())
    }

    /// Check all stored SBOMs for new advisories.
    /// Returns only advisories not previously seen.
    pub fn check_feeds(&self) -> Result<FeedCheckResult, String> {
        let sbom_dir = default_sbom_dir()?;

        if !sbom_dir.exists() {
            return Ok(FeedCheckResult {
                repos_checked: 0,
                packages_checked: 0,
                new_advisories: Vec::new(),
                total_known_advisories: self.count_known_advisories()?,
            });
        }

        // Load all SBOM files and extract packages per repo
        let sbom_entries = load_sbom_packages(&sbom_dir)?;
        let repos_checked = sbom_entries.len();

        // Build a deduplicated package list for querying, tracking which repos each package appears in
        let mut pkg_key_to_repos: HashMap<(String, String, Ecosystem), Vec<String>> =
            HashMap::new();
        let mut unique_packages: Vec<PackageEntry> = Vec::new();
        let mut seen_keys: HashSet<(String, String, Ecosystem)> = HashSet::new();

        for (repo_name, packages) in &sbom_entries {
            for pkg in packages {
                let key = (pkg.name.clone(), pkg.version.clone(), pkg.ecosystem);
                pkg_key_to_repos
                    .entry(key.clone())
                    .or_default()
                    .push(repo_name.clone());
                if seen_keys.insert(key) {
                    unique_packages.push(pkg.clone());
                }
            }
        }

        let packages_checked = unique_packages.len();

        if unique_packages.is_empty() {
            return Ok(FeedCheckResult {
                repos_checked,
                packages_checked: 0,
                new_advisories: Vec::new(),
                total_known_advisories: self.count_known_advisories()?,
            });
        }

        // Query OSV for vulnerabilities
        let client = OsvClient::new();
        let vulns = client.query_batch(&unique_packages).map_err(|e| {
            format!(
                "Failed to query OSV API (is the network available?): {}",
                e
            )
        })?;

        // Determine which are new
        let now = Utc::now().to_rfc3339();
        let mut new_advisories = Vec::new();

        for vuln in &vulns {
            let is_new = self.is_advisory_new(&vuln.id, &vuln.package_name, &vuln.package_version)?;

            let severity_str = map_cvss_to_severity(&vuln.severity).to_string();

            if is_new {
                // Insert into advisory_state
                self.insert_advisory(vuln, &severity_str, &now)?;

                // Find which repos this package appears in
                let key = (
                    vuln.package_name.clone(),
                    vuln.package_version.clone(),
                    vuln.ecosystem,
                );
                let repos = pkg_key_to_repos
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();

                let repo_name = if repos.is_empty() {
                    "unknown".to_string()
                } else {
                    repos.join(", ")
                };

                let classification = classify_vulnerability(&vuln.severity, &vuln.cwe_ids);

                new_advisories.push(NewAdvisory {
                    advisory_id: vuln.id.clone(),
                    summary: vuln.summary.clone(),
                    severity: severity_str,
                    classification,
                    package_name: vuln.package_name.clone(),
                    package_version: vuln.package_version.clone(),
                    ecosystem: vuln.ecosystem.to_string(),
                    repo_name,
                    aliases: vuln.aliases.clone(),
                });
            } else {
                // Update last_seen timestamp
                self.update_last_seen(&vuln.id, &vuln.package_name, &vuln.package_version, &now)?;
            }
        }

        let total_known = self.count_known_advisories()?;

        info!(
            "Feed check complete: {} repos, {} packages, {} new advisories ({} total known)",
            repos_checked,
            packages_checked,
            new_advisories.len(),
            total_known
        );

        Ok(FeedCheckResult {
            repos_checked,
            packages_checked,
            new_advisories,
            total_known_advisories: total_known,
        })
    }

    /// Check feeds using a pre-built package list and repo mapping (for testing / custom use)
    pub fn check_feeds_with_packages(
        &self,
        packages: &[PackageEntry],
        pkg_to_repos: &HashMap<(String, String, Ecosystem), Vec<String>>,
        client: &OsvClient,
    ) -> Result<FeedCheckResult, String> {
        let repos: HashSet<&String> = pkg_to_repos.values().flatten().collect();
        let repos_checked = repos.len();
        let packages_checked = packages.len();

        if packages.is_empty() {
            return Ok(FeedCheckResult {
                repos_checked,
                packages_checked: 0,
                new_advisories: Vec::new(),
                total_known_advisories: self.count_known_advisories()?,
            });
        }

        let vulns = client.query_batch(packages).map_err(|e| {
            format!(
                "Failed to query OSV API (is the network available?): {}",
                e
            )
        })?;

        let now = Utc::now().to_rfc3339();
        let mut new_advisories = Vec::new();

        for vuln in &vulns {
            let is_new = self.is_advisory_new(&vuln.id, &vuln.package_name, &vuln.package_version)?;
            let severity_str = map_cvss_to_severity(&vuln.severity).to_string();

            if is_new {
                self.insert_advisory(vuln, &severity_str, &now)?;

                let key = (
                    vuln.package_name.clone(),
                    vuln.package_version.clone(),
                    vuln.ecosystem,
                );
                let repos = pkg_to_repos.get(&key).cloned().unwrap_or_default();
                let repo_name = if repos.is_empty() {
                    "unknown".to_string()
                } else {
                    repos.join(", ")
                };

                let classification = classify_vulnerability(&vuln.severity, &vuln.cwe_ids);

                new_advisories.push(NewAdvisory {
                    advisory_id: vuln.id.clone(),
                    summary: vuln.summary.clone(),
                    severity: severity_str,
                    classification,
                    package_name: vuln.package_name.clone(),
                    package_version: vuln.package_version.clone(),
                    ecosystem: vuln.ecosystem.to_string(),
                    repo_name,
                    aliases: vuln.aliases.clone(),
                });
            } else {
                self.update_last_seen(&vuln.id, &vuln.package_name, &vuln.package_version, &now)?;
            }
        }

        let total_known = self.count_known_advisories()?;

        Ok(FeedCheckResult {
            repos_checked,
            packages_checked,
            new_advisories,
            total_known_advisories: total_known,
        })
    }

    /// Mark advisories as notified (so they don't show up again)
    pub fn mark_notified(&self, advisory_ids: &[String]) -> Result<(), String> {
        for id in advisory_ids {
            self.conn
                .execute(
                    "UPDATE advisory_state SET notified = 1 WHERE advisory_id = ?1",
                    params![id],
                )
                .map_err(|e| format!("Failed to mark advisory {} as notified: {}", id, e))?;
        }
        Ok(())
    }

    /// Get all known advisories for a package
    pub fn advisories_for_package(
        &self,
        package_name: &str,
    ) -> Result<Vec<StoredAdvisory>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT advisory_id, package_name, package_version, ecosystem,
                        severity, summary, first_seen, notified
                 FROM advisory_state
                 WHERE package_name = ?1
                 ORDER BY first_seen DESC",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let advisories = stmt
            .query_map(params![package_name], |row| {
                let notified_int: i32 = row.get(7)?;
                Ok(StoredAdvisory {
                    advisory_id: row.get(0)?,
                    package_name: row.get(1)?,
                    package_version: row.get(2)?,
                    ecosystem: row.get(3)?,
                    severity: row.get(4)?,
                    summary: row.get(5)?,
                    first_seen: row.get(6)?,
                    notified: notified_int != 0,
                })
            })
            .map_err(|e| format!("Failed to query advisories: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(advisories)
    }

    /// Get summary of advisory state across all repos
    pub fn summary(&self) -> Result<FeedSummary, String> {
        let total_advisories: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM advisory_state", [], |row| row.get(0))
            .map_err(|e| format!("Failed to count advisories: {}", e))?;

        let unnotified: usize = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM advisory_state WHERE notified = 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("Failed to count unnotified: {}", e))?;

        let mut by_severity = HashMap::new();
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT COALESCE(severity, 'unknown'), COUNT(*)
                     FROM advisory_state
                     GROUP BY COALESCE(severity, 'unknown')",
                )
                .map_err(|e| format!("Failed to prepare severity query: {}", e))?;

            let rows = stmt
                .query_map([], |row| {
                    let sev: String = row.get(0)?;
                    let count: usize = row.get(1)?;
                    Ok((sev, count))
                })
                .map_err(|e| format!("Failed to query by severity: {}", e))?;

            for row in rows.flatten() {
                by_severity.insert(row.0, row.1);
            }
        }

        let mut by_ecosystem = HashMap::new();
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT ecosystem, COUNT(*)
                     FROM advisory_state
                     GROUP BY ecosystem",
                )
                .map_err(|e| format!("Failed to prepare ecosystem query: {}", e))?;

            let rows = stmt
                .query_map([], |row| {
                    let eco: String = row.get(0)?;
                    let count: usize = row.get(1)?;
                    Ok((eco, count))
                })
                .map_err(|e| format!("Failed to query by ecosystem: {}", e))?;

            for row in rows.flatten() {
                by_ecosystem.insert(row.0, row.1);
            }
        }

        Ok(FeedSummary {
            total_advisories,
            unnotified,
            by_severity,
            by_ecosystem,
        })
    }

    // --- Internal helpers ---

    /// Check if an advisory is new (not yet in the database)
    fn is_advisory_new(
        &self,
        advisory_id: &str,
        package_name: &str,
        package_version: &str,
    ) -> Result<bool, String> {
        let count: usize = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM advisory_state
                 WHERE advisory_id = ?1 AND package_name = ?2 AND package_version = ?3",
                params![advisory_id, package_name, package_version],
                |row| row.get(0),
            )
            .map_err(|e| format!("Failed to check advisory existence: {}", e))?;

        Ok(count == 0)
    }

    /// Insert a new advisory into the database
    fn insert_advisory(
        &self,
        vuln: &OsvVulnerability,
        severity_str: &str,
        now: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO advisory_state
                 (advisory_id, package_name, package_version, ecosystem, severity, summary, first_seen, last_seen, notified)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                params![
                    vuln.id,
                    vuln.package_name,
                    vuln.package_version,
                    vuln.ecosystem.to_string(),
                    severity_str,
                    vuln.summary,
                    now,
                    now,
                ],
            )
            .map_err(|e| format!("Failed to insert advisory: {}", e))?;

        debug!("Stored new advisory {} for {}@{}", vuln.id, vuln.package_name, vuln.package_version);
        Ok(())
    }

    /// Update the last_seen timestamp for an existing advisory
    fn update_last_seen(
        &self,
        advisory_id: &str,
        package_name: &str,
        package_version: &str,
        now: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE advisory_state SET last_seen = ?1
                 WHERE advisory_id = ?2 AND package_name = ?3 AND package_version = ?4",
                params![now, advisory_id, package_name, package_version],
            )
            .map_err(|e| format!("Failed to update last_seen: {}", e))?;
        Ok(())
    }

    /// Count total known advisories in the database
    fn count_known_advisories(&self) -> Result<usize, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM advisory_state", [], |row| row.get(0))
            .map_err(|e| format!("Failed to count advisories: {}", e))
    }

    /// Insert a stored advisory directly (for testing)
    #[cfg(test)]
    fn insert_test_advisory(
        &self,
        advisory_id: &str,
        package_name: &str,
        package_version: &str,
        ecosystem: &str,
        severity: Option<&str>,
        summary: Option<&str>,
        notified: bool,
    ) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT OR IGNORE INTO advisory_state
                 (advisory_id, package_name, package_version, ecosystem, severity, summary, first_seen, last_seen, notified)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    advisory_id,
                    package_name,
                    package_version,
                    ecosystem,
                    severity,
                    summary,
                    now,
                    now,
                    if notified { 1 } else { 0 },
                ],
            )
            .map_err(|e| format!("Failed to insert test advisory: {}", e))?;
        Ok(())
    }
}

// --- PURL Parsing ---

/// Parse a Package URL (PURL) into (Ecosystem, name, version).
///
/// Supports:
/// - `pkg:pypi/requests@2.31.0` -> (PyPI, "requests", "2.31.0")
/// - `pkg:npm/%40scope/name@1.0.0` -> (Npm, "@scope/name", "1.0.0")
/// - `pkg:cargo/serde@1.0.0` -> (CratesIo, "serde", "1.0.0")
pub fn parse_purl(purl: &str) -> Option<(Ecosystem, String, String)> {
    // PURL format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    // Minimal: pkg:<type>/<name>@<version>
    let stripped = purl.strip_prefix("pkg:")?;

    // Split type from the rest
    let (purl_type, rest) = stripped.split_once('/')?;

    let ecosystem = match purl_type {
        "pypi" => Ecosystem::PyPI,
        "npm" => Ecosystem::Npm,
        "cargo" => Ecosystem::CratesIo,
        _ => return None,
    };

    // Split off qualifiers and subpath (everything after ? or #)
    let name_version = rest.split('?').next().unwrap_or(rest);
    let name_version = name_version.split('#').next().unwrap_or(name_version);

    // Split name@version
    let (name_part, version) = name_version.rsplit_once('@')?;

    if name_part.is_empty() || version.is_empty() {
        return None;
    }

    // URL-decode the name (e.g., %40 -> @)
    let name = url_decode(name_part);

    Some((ecosystem, name, version.to_string()))
}

/// Simple URL decoding for PURL names (handles %XX sequences)
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Fallback: keep the percent sign and whatever we consumed
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

// --- SBOM Loading ---

/// A parsed SBOM with its repo name and extracted packages
struct SbomEntry {
    repo_name: String,
    packages: Vec<PackageEntry>,
}

/// Load all SBOM files from the given directory and extract packages
fn load_sbom_packages(sbom_dir: &Path) -> Result<Vec<(String, Vec<PackageEntry>)>, String> {
    let mut entries = Vec::new();

    let read_dir = std::fs::read_dir(sbom_dir)
        .map_err(|e| format!("Failed to read SBOM directory {}: {}", sbom_dir.display(), e))?;

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".cdx.json"))
                .unwrap_or(false)
        {
            match parse_cdx_sbom(&path) {
                Ok(sbom) => {
                    debug!(
                        "Loaded SBOM {} with {} packages",
                        sbom.repo_name,
                        sbom.packages.len()
                    );
                    entries.push((sbom.repo_name, sbom.packages));
                }
                Err(e) => {
                    warn!("Failed to parse SBOM {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(entries)
}

/// Parse a CycloneDX SBOM JSON file and extract PackageEntry list
fn parse_cdx_sbom(path: &Path) -> Result<SbomEntry, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse JSON {}: {}", path.display(), e))?;

    // Extract repo name from metadata.component.name or filename
    let repo_name = doc
        .pointer("/metadata/component/name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                // Strip .cdx suffix if present
                .map(|s| s.strip_suffix(".cdx").unwrap_or(s))
                .unwrap_or("unknown")
                .to_string()
        });

    // Extract components
    let components = doc
        .get("components")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut packages = Vec::new();

    for component in &components {
        // Try to get package info from PURL first
        if let Some(purl) = component.get("purl").and_then(|v| v.as_str()) {
            if let Some((ecosystem, name, version)) = parse_purl(purl) {
                packages.push(PackageEntry {
                    name,
                    version,
                    ecosystem,
                    source_url: Some(purl.to_string()),
                    checksum: extract_checksum(component),
                });
                continue;
            }
        }

        // Fallback: use name and version fields directly
        let name = component.get("name").and_then(|v| v.as_str());
        let version = component.get("version").and_then(|v| v.as_str());

        if let (Some(name), Some(version)) = (name, version) {
            // Try to infer ecosystem from PURL type or other hints
            if let Some(ecosystem) = infer_ecosystem(component) {
                packages.push(PackageEntry {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem,
                    source_url: None,
                    checksum: extract_checksum(component),
                });
            }
        }
    }

    Ok(SbomEntry {
        repo_name,
        packages,
    })
}

/// Try to infer ecosystem from a CycloneDX component
fn infer_ecosystem(component: &serde_json::Value) -> Option<Ecosystem> {
    // Check for purl type hint in properties or external references
    if let Some(purl) = component.get("purl").and_then(|v| v.as_str()) {
        if purl.starts_with("pkg:pypi/") {
            return Some(Ecosystem::PyPI);
        } else if purl.starts_with("pkg:npm/") {
            return Some(Ecosystem::Npm);
        } else if purl.starts_with("pkg:cargo/") {
            return Some(Ecosystem::CratesIo);
        }
    }

    // Check component type field
    if let Some(comp_type) = component.get("type").and_then(|v| v.as_str()) {
        match comp_type {
            "library" => {
                // Could be any ecosystem, can't determine
            }
            _ => {}
        }
    }

    None
}

/// Extract checksum from a CycloneDX component's hashes array
fn extract_checksum(component: &serde_json::Value) -> Option<String> {
    component
        .get("hashes")
        .and_then(|v| v.as_array())
        .and_then(|hashes| hashes.first())
        .and_then(|h| h.get("content"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Get the default SBOM directory path
fn default_sbom_dir() -> Result<PathBuf, String> {
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(SBOM_DIR))
}

/// Get the default database path
fn default_db_path() -> Result<PathBuf, String> {
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(DEFAULT_DB_DIR).join(DB_FILENAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PURL parsing tests ---

    #[test]
    fn test_parse_purl_pypi() {
        let result = parse_purl("pkg:pypi/requests@2.31.0");
        assert!(result.is_some());
        let (eco, name, version) = result.unwrap();
        assert_eq!(eco, Ecosystem::PyPI);
        assert_eq!(name, "requests");
        assert_eq!(version, "2.31.0");
    }

    #[test]
    fn test_parse_purl_npm_scoped() {
        let result = parse_purl("pkg:npm/%40angular/core@16.2.0");
        assert!(result.is_some());
        let (eco, name, version) = result.unwrap();
        assert_eq!(eco, Ecosystem::Npm);
        assert_eq!(name, "@angular/core");
        assert_eq!(version, "16.2.0");
    }

    #[test]
    fn test_parse_purl_npm_unscoped() {
        let result = parse_purl("pkg:npm/express@4.18.2");
        assert!(result.is_some());
        let (eco, name, version) = result.unwrap();
        assert_eq!(eco, Ecosystem::Npm);
        assert_eq!(name, "express");
        assert_eq!(version, "4.18.2");
    }

    #[test]
    fn test_parse_purl_cargo() {
        let result = parse_purl("pkg:cargo/serde@1.0.193");
        assert!(result.is_some());
        let (eco, name, version) = result.unwrap();
        assert_eq!(eco, Ecosystem::CratesIo);
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.193");
    }

    #[test]
    fn test_parse_purl_with_qualifiers() {
        // PURLs can have qualifiers after ? and subpath after #
        let result = parse_purl("pkg:pypi/flask@2.3.3?vcs_url=https://github.com/pallets/flask");
        assert!(result.is_some());
        let (eco, name, version) = result.unwrap();
        assert_eq!(eco, Ecosystem::PyPI);
        assert_eq!(name, "flask");
        assert_eq!(version, "2.3.3");
    }

    #[test]
    fn test_parse_purl_unknown_ecosystem() {
        let result = parse_purl("pkg:maven/org.apache/commons-lang3@3.14.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_purl_invalid() {
        assert!(parse_purl("not-a-purl").is_none());
        assert!(parse_purl("pkg:pypi/").is_none());
        assert!(parse_purl("pkg:pypi/requests").is_none()); // no version
        assert!(parse_purl("").is_none());
    }

    // --- Advisory state storage and retrieval ---

    #[test]
    fn test_advisory_storage_and_retrieval() {
        let monitor = FeedMonitor::open_memory().unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-xxxx-yyyy-zzzz",
                "requests",
                "2.25.0",
                "pypi",
                Some("high"),
                Some("HTTP request smuggling"),
                false,
            )
            .unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-aaaa-bbbb-cccc",
                "requests",
                "2.25.0",
                "pypi",
                Some("critical"),
                Some("Remote code execution"),
                true,
            )
            .unwrap();

        let advisories = monitor.advisories_for_package("requests").unwrap();
        assert_eq!(advisories.len(), 2);

        // Check that both are returned
        let ids: Vec<&str> = advisories.iter().map(|a| a.advisory_id.as_str()).collect();
        assert!(ids.contains(&"GHSA-xxxx-yyyy-zzzz"));
        assert!(ids.contains(&"GHSA-aaaa-bbbb-cccc"));

        // Check notified status
        let notified_adv = advisories
            .iter()
            .find(|a| a.advisory_id == "GHSA-aaaa-bbbb-cccc")
            .unwrap();
        assert!(notified_adv.notified);

        let unnotified_adv = advisories
            .iter()
            .find(|a| a.advisory_id == "GHSA-xxxx-yyyy-zzzz")
            .unwrap();
        assert!(!unnotified_adv.notified);
    }

    #[test]
    fn test_new_advisory_detection() {
        let monitor = FeedMonitor::open_memory().unwrap();

        // Pre-populate with one known advisory
        monitor
            .insert_test_advisory(
                "GHSA-xxxx-yyyy-zzzz",
                "requests",
                "2.25.0",
                "pypi",
                Some("high"),
                Some("Known vuln"),
                false,
            )
            .unwrap();

        // The known advisory should not be new
        assert!(
            !monitor
                .is_advisory_new("GHSA-xxxx-yyyy-zzzz", "requests", "2.25.0")
                .unwrap()
        );

        // A different advisory should be new
        assert!(
            monitor
                .is_advisory_new("GHSA-new-one-here", "requests", "2.25.0")
                .unwrap()
        );

        // Same advisory for a different version should be new
        assert!(
            monitor
                .is_advisory_new("GHSA-xxxx-yyyy-zzzz", "requests", "2.26.0")
                .unwrap()
        );
    }

    #[test]
    fn test_mark_notified() {
        let monitor = FeedMonitor::open_memory().unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-1111-2222-3333",
                "flask",
                "2.0.0",
                "pypi",
                Some("medium"),
                Some("XSS vulnerability"),
                false,
            )
            .unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-4444-5555-6666",
                "flask",
                "2.0.0",
                "pypi",
                Some("high"),
                Some("CSRF bypass"),
                false,
            )
            .unwrap();

        // Both should be unnotified initially
        let summary = monitor.summary().unwrap();
        assert_eq!(summary.unnotified, 2);

        // Mark one as notified
        monitor
            .mark_notified(&["GHSA-1111-2222-3333".to_string()])
            .unwrap();

        let summary = monitor.summary().unwrap();
        assert_eq!(summary.unnotified, 1);
        assert_eq!(summary.total_advisories, 2);

        // Check that the right one was marked
        let advisories = monitor.advisories_for_package("flask").unwrap();
        let marked = advisories
            .iter()
            .find(|a| a.advisory_id == "GHSA-1111-2222-3333")
            .unwrap();
        assert!(marked.notified);

        let unmarked = advisories
            .iter()
            .find(|a| a.advisory_id == "GHSA-4444-5555-6666")
            .unwrap();
        assert!(!unmarked.notified);
    }

    #[test]
    fn test_summary() {
        let monitor = FeedMonitor::open_memory().unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-1111",
                "requests",
                "2.25.0",
                "pypi",
                Some("high"),
                None,
                false,
            )
            .unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-2222",
                "express",
                "4.17.0",
                "npm",
                Some("critical"),
                None,
                true,
            )
            .unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-3333",
                "serde",
                "1.0.100",
                "crates.io",
                Some("high"),
                None,
                false,
            )
            .unwrap();

        let summary = monitor.summary().unwrap();
        assert_eq!(summary.total_advisories, 3);
        assert_eq!(summary.unnotified, 2);

        // Check severity breakdown
        assert_eq!(summary.by_severity.get("high"), Some(&2));
        assert_eq!(summary.by_severity.get("critical"), Some(&1));

        // Check ecosystem breakdown
        assert_eq!(summary.by_ecosystem.get("pypi"), Some(&1));
        assert_eq!(summary.by_ecosystem.get("npm"), Some(&1));
        assert_eq!(summary.by_ecosystem.get("crates.io"), Some(&1));
    }

    #[test]
    fn test_empty_summary() {
        let monitor = FeedMonitor::open_memory().unwrap();

        let summary = monitor.summary().unwrap();
        assert_eq!(summary.total_advisories, 0);
        assert_eq!(summary.unnotified, 0);
        assert!(summary.by_severity.is_empty());
        assert!(summary.by_ecosystem.is_empty());
    }

    #[test]
    fn test_duplicate_advisory_ignored() {
        let monitor = FeedMonitor::open_memory().unwrap();

        // Insert the same advisory twice
        monitor
            .insert_test_advisory(
                "GHSA-dupe",
                "requests",
                "2.25.0",
                "pypi",
                Some("high"),
                None,
                false,
            )
            .unwrap();

        monitor
            .insert_test_advisory(
                "GHSA-dupe",
                "requests",
                "2.25.0",
                "pypi",
                Some("critical"), // different severity - should be ignored due to UNIQUE
                None,
                false,
            )
            .unwrap();

        let advisories = monitor.advisories_for_package("requests").unwrap();
        assert_eq!(advisories.len(), 1);
        // Original severity should be preserved
        assert_eq!(advisories[0].severity.as_deref(), Some("high"));
    }

    #[test]
    fn test_advisories_for_nonexistent_package() {
        let monitor = FeedMonitor::open_memory().unwrap();

        let advisories = monitor.advisories_for_package("nonexistent").unwrap();
        assert!(advisories.is_empty());
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("%40scope/name"), "@scope/name");
        assert_eq!(url_decode("no-encoding"), "no-encoding");
        assert_eq!(url_decode("%40foo%2Fbar"), "@foo/bar");
        assert_eq!(url_decode(""), "");
    }
}
