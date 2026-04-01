//! Read-only access to vuln_cache.db

use crate::types::CachedVuln;
use rusqlite::{params, Connection};
use std::path::Path;

/// Read-only vulnerability cache store
pub struct VulnStore {
    conn: Connection,
}

impl VulnStore {
    /// Open the vulnerability cache (read-only)
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Self::open_empty(path);
        }
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("Failed to open vuln cache: {}", e))?;
        Ok(Self { conn })
    }

    fn open_empty(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to create vuln cache: {}", e))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vuln_classification (
                advisory_id TEXT PRIMARY KEY,
                severity_type TEXT,
                severity_score TEXT,
                cwe_ids TEXT,
                cached_at TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("Failed to initialize schema: {}", e))?;
        Ok(Self { conn })
    }

    /// Number of cached advisory classifications
    pub fn cached_count(&self) -> Result<usize, String> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM vuln_classification",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("Query failed: {}", e))
    }

    /// Look up a cached advisory
    pub fn get_advisory(&self, advisory_id: &str) -> Result<Option<CachedVuln>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT advisory_id, severity_type, severity_score, cwe_ids, cached_at
                 FROM vuln_classification WHERE advisory_id = ?1",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let result = stmt
            .query_row(params![advisory_id], |row| {
                Ok(CachedVuln {
                    advisory_id: row.get(0)?,
                    severity_type: row.get(1)?,
                    severity_score: row.get(2)?,
                    cwe_ids: row.get(3)?,
                    cached_at: row.get(4)?,
                })
            })
            .ok();

        Ok(result)
    }

    /// List all cached advisories (paginated)
    pub fn list_advisories(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CachedVuln>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT advisory_id, severity_type, severity_score, cwe_ids, cached_at
                 FROM vuln_classification
                 ORDER BY cached_at DESC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| format!("Query failed: {}", e))?;

        let advisories = stmt
            .query_map(params![limit, offset], |row| {
                Ok(CachedVuln {
                    advisory_id: row.get(0)?,
                    severity_type: row.get(1)?,
                    severity_score: row.get(2)?,
                    cwe_ids: row.get(3)?,
                    cached_at: row.get(4)?,
                })
            })
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(advisories)
    }
}
