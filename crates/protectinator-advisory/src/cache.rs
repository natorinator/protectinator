//! SQLite cache for Debian Security Tracker data
//!
//! Caches parsed tracker entries locally to avoid re-fetching the bulk JSON
//! on every scan. Default staleness threshold is 6 hours.

use crate::debian::DebianCveEntry;
use crate::error::AdvisoryError;
use crate::{SubState, TrackerStatus};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use tracing::debug;

/// SQLite-backed cache for Debian advisory data
pub struct AdvisoryCache {
    conn: Connection,
}

impl AdvisoryCache {
    /// Open (or create) a cache at the given path
    pub fn open(path: &Path) -> Result<Self, AdvisoryError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AdvisoryError::Cache(format!("Failed to create cache dir: {}", e)))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| AdvisoryError::Cache(format!("Failed to open cache db: {}", e)))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS debian_cves (
                source_package TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                release TEXT NOT NULL,
                status TEXT NOT NULL,
                sub_state TEXT NOT NULL,
                urgency TEXT NOT NULL,
                fixed_version TEXT,
                scope TEXT,
                description TEXT,
                cached_at TEXT NOT NULL,
                PRIMARY KEY (source_package, cve_id, release)
            );
            CREATE TABLE IF NOT EXISTS package_mapping (
                binary_name TEXT PRIMARY KEY,
                source_name TEXT NOT NULL,
                cached_at TEXT NOT NULL
            );",
        )
        .map_err(|e| AdvisoryError::Cache(format!("Failed to create tables: {}", e)))?;

        Ok(Self { conn })
    }

    /// Open the cache at the default location (~/.local/share/protectinator/debian_advisory.db)
    pub fn open_default() -> Result<Self, AdvisoryError> {
        let path = default_cache_path();
        Self::open(&path)
    }

    /// Check if the cached data is older than `max_age_hours`
    pub fn is_stale(&self, max_age_hours: u64) -> bool {
        let result: Result<Option<String>, _> = self.conn.query_row(
            "SELECT MAX(cached_at) FROM debian_cves",
            [],
            |row| row.get(0),
        );

        match result {
            Ok(Some(cached_at)) => {
                let parsed = chrono::DateTime::parse_from_rfc3339(&cached_at);
                match parsed {
                    Ok(ts) => {
                        let age = chrono::Utc::now().signed_duration_since(ts);
                        age.num_hours() >= max_age_hours as i64
                    }
                    Err(_) => true,
                }
            }
            _ => true, // No data or error means stale
        }
    }

    /// Bulk-insert parsed entries using a transaction
    ///
    /// Each tuple is (source_package, cve_id, entry).
    /// The `release` field is extracted from the caller context.
    pub fn store_entries(
        &mut self,
        release: &str,
        entries: &[(String, String, DebianCveEntry)],
    ) -> Result<(), AdvisoryError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| AdvisoryError::Cache(format!("Transaction start failed: {}", e)))?;

        let now = chrono::Utc::now().to_rfc3339();

        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR REPLACE INTO debian_cves
                     (source_package, cve_id, release, status, sub_state, urgency,
                      fixed_version, scope, description, cached_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .map_err(|e| AdvisoryError::Cache(format!("Prepare failed: {}", e)))?;

            for (source_pkg, cve_id, entry) in entries {
                stmt.execute(params![
                    source_pkg,
                    cve_id,
                    release,
                    entry.status.to_string(),
                    entry.sub_state.to_string(),
                    entry.urgency,
                    entry.fixed_version,
                    entry.scope,
                    entry.description,
                    now,
                ])
                .map_err(|e| AdvisoryError::Cache(format!("Insert failed: {}", e)))?;
            }
        }

        tx.commit()
            .map_err(|e| AdvisoryError::Cache(format!("Transaction commit failed: {}", e)))?;

        debug!("Stored {} entries in advisory cache", entries.len());
        Ok(())
    }

    /// Look up all CVEs for a source package in a specific release
    pub fn lookup_package(
        &self,
        source_package: &str,
        release: &str,
    ) -> Result<Vec<DebianCveEntry>, AdvisoryError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT cve_id, status, sub_state, urgency, fixed_version, scope, description
                 FROM debian_cves
                 WHERE source_package = ?1 AND release = ?2",
            )
            .map_err(|e| AdvisoryError::Cache(format!("Query failed: {}", e)))?;

        let entries = stmt
            .query_map(params![source_package, release], |row| {
                let status_str: String = row.get(1)?;
                let sub_state_str: String = row.get(2)?;
                Ok(DebianCveEntry {
                    cve_id: row.get(0)?,
                    status: TrackerStatus::parse(&status_str),
                    sub_state: parse_sub_state(&sub_state_str),
                    urgency: row.get(3)?,
                    fixed_version: row.get(4)?,
                    scope: row.get(5)?,
                    description: row.get(6)?,
                })
            })
            .map_err(|e| AdvisoryError::Cache(format!("Query failed: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Look up all packages affected by a specific CVE
    pub fn lookup_cve(
        &self,
        cve_id: &str,
    ) -> Result<Vec<(String, DebianCveEntry)>, AdvisoryError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source_package, cve_id, status, sub_state, urgency,
                        fixed_version, scope, description
                 FROM debian_cves
                 WHERE cve_id = ?1",
            )
            .map_err(|e| AdvisoryError::Cache(format!("Query failed: {}", e)))?;

        let entries = stmt
            .query_map(params![cve_id], |row| {
                let source_pkg: String = row.get(0)?;
                let status_str: String = row.get(2)?;
                let sub_state_str: String = row.get(3)?;
                Ok((
                    source_pkg,
                    DebianCveEntry {
                        cve_id: row.get(1)?,
                        status: TrackerStatus::parse(&status_str),
                        sub_state: parse_sub_state(&sub_state_str),
                        urgency: row.get(4)?,
                        fixed_version: row.get(5)?,
                        scope: row.get(6)?,
                        description: row.get(7)?,
                    },
                ))
            })
            .map_err(|e| AdvisoryError::Cache(format!("Query failed: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Drop all cached data
    pub fn clear(&mut self) -> Result<(), AdvisoryError> {
        self.conn
            .execute_batch("DELETE FROM debian_cves; DELETE FROM package_mapping;")
            .map_err(|e| AdvisoryError::Cache(format!("Clear failed: {}", e)))?;
        Ok(())
    }

    /// Resolve a binary package name to its source package name
    ///
    /// First checks the local mapping cache, then falls back to reading
    /// `/var/lib/dpkg/status` to find the Source field.
    pub fn resolve_source_package(&mut self, binary_package: &str) -> Option<String> {
        // Check cache first
        if let Ok(Some(source)) = self.lookup_mapping(binary_package) {
            return Some(source);
        }

        // Try to resolve from dpkg status
        let source = resolve_from_dpkg_status(binary_package)?;

        // Cache the mapping
        let _ = self.store_mapping(binary_package, &source);

        Some(source)
    }

    fn lookup_mapping(&self, binary_name: &str) -> Result<Option<String>, AdvisoryError> {
        let result = self
            .conn
            .query_row(
                "SELECT source_name FROM package_mapping WHERE binary_name = ?1",
                params![binary_name],
                |row| row.get(0),
            );

        match result {
            Ok(name) => Ok(Some(name)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AdvisoryError::Cache(format!("Mapping lookup failed: {}", e))),
        }
    }

    fn store_mapping(&mut self, binary_name: &str, source_name: &str) -> Result<(), AdvisoryError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO package_mapping (binary_name, source_name, cached_at)
                 VALUES (?1, ?2, ?3)",
                params![binary_name, source_name, now],
            )
            .map_err(|e| AdvisoryError::Cache(format!("Mapping store failed: {}", e)))?;
        Ok(())
    }
}

/// Parse a sub_state string back to the enum
fn parse_sub_state(s: &str) -> SubState {
    match s {
        "ignored" => SubState::Ignored,
        "postponed" => SubState::Postponed,
        _ => SubState::None,
    }
}

/// Resolve binary→source package name from /var/lib/dpkg/status
fn resolve_from_dpkg_status(binary_package: &str) -> Option<String> {
    let content = std::fs::read_to_string("/var/lib/dpkg/status").ok()?;

    let mut in_package = false;
    let mut found_source = None;

    for line in content.lines() {
        if line.starts_with("Package: ") {
            let pkg = line.strip_prefix("Package: ").unwrap_or("").trim();
            in_package = pkg == binary_package;
            found_source = None;
        } else if in_package && line.starts_with("Source: ") {
            // Source field may include version: "Source: foo (1.2.3-4)"
            let source_raw = line.strip_prefix("Source: ").unwrap_or("").trim();
            let source = source_raw
                .split_whitespace()
                .next()
                .unwrap_or(source_raw);
            found_source = Some(source.to_string());
        } else if in_package && line.is_empty() {
            // End of this package stanza
            if let Some(ref src) = found_source {
                return Some(src.clone());
            }
            // If no Source field, binary name == source name
            return Some(binary_package.to_string());
        }
    }

    // Handle last stanza (no trailing empty line)
    if in_package {
        if let Some(src) = found_source {
            return Some(src);
        }
        return Some(binary_package.to_string());
    }

    None
}

/// Default cache path
fn default_cache_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("protectinator")
        .join("debian_advisory.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debian::{SubState, TrackerStatus};

    fn temp_cache() -> (AdvisoryCache, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("test_advisory.db");
        let cache = AdvisoryCache::open(&path).expect("open cache");
        (cache, dir)
    }

    #[test]
    fn test_open_and_create_tables() {
        let (_cache, _dir) = temp_cache();
        // If we got here, tables were created successfully
    }

    #[test]
    fn test_is_stale_empty_db() {
        let (cache, _dir) = temp_cache();
        assert!(cache.is_stale(6));
    }

    #[test]
    fn test_store_and_lookup_package() {
        let (mut cache, _dir) = temp_cache();

        let entries = vec![(
            "curl".to_string(),
            "CVE-2024-1234".to_string(),
            DebianCveEntry {
                cve_id: "CVE-2024-1234".to_string(),
                status: TrackerStatus::Resolved,
                sub_state: SubState::None,
                urgency: "medium".to_string(),
                fixed_version: Some("7.88.1-10+deb12u5".to_string()),
                scope: Some("remote".to_string()),
                description: Some("Buffer overflow".to_string()),
            },
        )];

        cache
            .store_entries("bookworm", &entries)
            .expect("store entries");

        let results = cache
            .lookup_package("curl", "bookworm")
            .expect("lookup package");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-1234");
        assert_eq!(results[0].status, TrackerStatus::Resolved);
        assert_eq!(
            results[0].fixed_version.as_deref(),
            Some("7.88.1-10+deb12u5")
        );
    }

    #[test]
    fn test_store_and_lookup_cve() {
        let (mut cache, _dir) = temp_cache();

        let entries = vec![
            (
                "curl".to_string(),
                "CVE-2024-1234".to_string(),
                DebianCveEntry {
                    cve_id: "CVE-2024-1234".to_string(),
                    status: TrackerStatus::Resolved,
                    sub_state: SubState::None,
                    urgency: "high".to_string(),
                    fixed_version: Some("1.0-1".to_string()),
                    scope: None,
                    description: None,
                },
            ),
            (
                "libcurl".to_string(),
                "CVE-2024-1234".to_string(),
                DebianCveEntry {
                    cve_id: "CVE-2024-1234".to_string(),
                    status: TrackerStatus::Unfixed,
                    sub_state: SubState::None,
                    urgency: "high".to_string(),
                    fixed_version: None,
                    scope: None,
                    description: None,
                },
            ),
        ];

        cache
            .store_entries("bookworm", &entries)
            .expect("store entries");

        let results = cache.lookup_cve("CVE-2024-1234").expect("lookup cve");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_is_stale_after_store() {
        let (mut cache, _dir) = temp_cache();

        let entries = vec![(
            "test".to_string(),
            "CVE-2024-0001".to_string(),
            DebianCveEntry {
                cve_id: "CVE-2024-0001".to_string(),
                status: TrackerStatus::Unfixed,
                sub_state: SubState::None,
                urgency: "low".to_string(),
                fixed_version: None,
                scope: None,
                description: None,
            },
        )];

        cache
            .store_entries("bookworm", &entries)
            .expect("store entries");

        // Just stored, so not stale at 6 hours
        assert!(!cache.is_stale(6));
        // But stale at 0 hours (immediate)
        assert!(cache.is_stale(0));
    }

    #[test]
    fn test_clear() {
        let (mut cache, _dir) = temp_cache();

        let entries = vec![(
            "test".to_string(),
            "CVE-2024-0001".to_string(),
            DebianCveEntry {
                cve_id: "CVE-2024-0001".to_string(),
                status: TrackerStatus::Unfixed,
                sub_state: SubState::None,
                urgency: "low".to_string(),
                fixed_version: None,
                scope: None,
                description: None,
            },
        )];

        cache
            .store_entries("bookworm", &entries)
            .expect("store entries");
        cache.clear().expect("clear");

        let results = cache
            .lookup_package("test", "bookworm")
            .expect("lookup after clear");
        assert!(results.is_empty());
        assert!(cache.is_stale(6));
    }

    #[test]
    fn test_package_mapping_cache() {
        let (mut cache, _dir) = temp_cache();

        // Store a mapping directly
        cache
            .store_mapping("libcurl4", "curl")
            .expect("store mapping");

        let result = cache
            .lookup_mapping("libcurl4")
            .expect("lookup mapping");
        assert_eq!(result, Some("curl".to_string()));

        // Non-existent mapping
        let result = cache
            .lookup_mapping("nonexistent")
            .expect("lookup missing");
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_source_package_from_cache() {
        let (mut cache, _dir) = temp_cache();

        // Pre-populate mapping
        cache
            .store_mapping("libcurl4", "curl")
            .expect("store mapping");

        let result = cache.resolve_source_package("libcurl4");
        assert_eq!(result, Some("curl".to_string()));
    }

    #[test]
    fn test_parse_sub_state() {
        assert_eq!(parse_sub_state("none"), SubState::None);
        assert_eq!(parse_sub_state("ignored"), SubState::Ignored);
        assert_eq!(parse_sub_state("postponed"), SubState::Postponed);
        assert_eq!(parse_sub_state("unknown"), SubState::None);
    }
}
