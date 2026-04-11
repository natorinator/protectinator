//! Baseline database for package binary integrity tracking
//!
//! Stores SHA256 hashes and metadata for binaries installed by package managers.
//! Uses SQLite for persistent storage, similar to protectinator-fim.

use crate::types::{MonitoredBinary, PackageManager};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use tracing::debug;

/// SQLite-backed baseline database for tracked package binaries
pub struct BaselineDb {
    conn: Connection,
}

impl BaselineDb {
    /// Open or create a baseline database at the given path
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS binaries (
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                md5 TEXT,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_manager TEXT NOT NULL,
                symlink_target TEXT,
                size INTEGER NOT NULL,
                last_verified TEXT NOT NULL,
                PRIMARY KEY (path, package_manager)
            );

            CREATE INDEX IF NOT EXISTS idx_binaries_package
                ON binaries (package_manager, package_name);

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Store or update a monitored binary in the baseline
    pub fn upsert_binary(&self, binary: &MonitoredBinary) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO binaries (path, sha256, md5, package_name, package_version,
                                   package_manager, symlink_target, size, last_verified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (path, package_manager) DO UPDATE SET
                sha256 = excluded.sha256,
                md5 = excluded.md5,
                package_name = excluded.package_name,
                package_version = excluded.package_version,
                symlink_target = excluded.symlink_target,
                size = excluded.size,
                last_verified = excluded.last_verified",
            params![
                binary.path.to_string_lossy().as_ref(),
                binary.sha256,
                binary.md5,
                binary.package_name,
                binary.package_version,
                binary.package_manager.to_string(),
                binary.symlink_target.as_ref().map(|p| p.to_string_lossy().to_string()),
                binary.size,
                binary.last_verified.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Store multiple binaries in a transaction
    pub fn upsert_binaries(&mut self, binaries: &[MonitoredBinary]) -> Result<(), rusqlite::Error> {
        let tx = self.conn.transaction()?;
        for binary in binaries {
            tx.execute(
                "INSERT INTO binaries (path, sha256, md5, package_name, package_version,
                                       package_manager, symlink_target, size, last_verified)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (path, package_manager) DO UPDATE SET
                    sha256 = excluded.sha256,
                    md5 = excluded.md5,
                    package_name = excluded.package_name,
                    package_version = excluded.package_version,
                    symlink_target = excluded.symlink_target,
                    size = excluded.size,
                    last_verified = excluded.last_verified",
                params![
                    binary.path.to_string_lossy().as_ref(),
                    binary.sha256,
                    binary.md5,
                    binary.package_name,
                    binary.package_version,
                    binary.package_manager.to_string(),
                    binary.symlink_target.as_ref().map(|p| p.to_string_lossy().to_string()),
                    binary.size,
                    binary.last_verified.to_rfc3339(),
                ],
            )?;
        }
        tx.commit()?;
        debug!("Stored {} binaries in baseline", binaries.len());
        Ok(())
    }

    /// Get a stored binary by path and package manager
    pub fn get_binary(
        &self,
        path: &Path,
        manager: PackageManager,
    ) -> Result<Option<MonitoredBinary>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT path, sha256, md5, package_name, package_version,
                        package_manager, symlink_target, size, last_verified
                 FROM binaries WHERE path = ?1 AND package_manager = ?2",
                params![path.to_string_lossy().as_ref(), manager.to_string()],
                |row| row_to_binary(row),
            )
            .optional()
    }

    /// Get all stored binaries for a package manager
    pub fn get_binaries_by_manager(
        &self,
        manager: PackageManager,
    ) -> Result<Vec<MonitoredBinary>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, md5, package_name, package_version,
                    package_manager, symlink_target, size, last_verified
             FROM binaries WHERE package_manager = ?1",
        )?;
        let rows = stmt.query_map(params![manager.to_string()], |row| row_to_binary(row))?;
        rows.collect()
    }

    /// Get all stored binaries for a specific package
    pub fn get_binaries_by_package(
        &self,
        manager: PackageManager,
        package_name: &str,
    ) -> Result<Vec<MonitoredBinary>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, md5, package_name, package_version,
                    package_manager, symlink_target, size, last_verified
             FROM binaries WHERE package_manager = ?1 AND package_name = ?2",
        )?;
        let rows = stmt.query_map(params![manager.to_string(), package_name], |row| {
            row_to_binary(row)
        })?;
        rows.collect()
    }

    /// Remove all binaries for a package
    pub fn remove_package(
        &self,
        manager: PackageManager,
        package_name: &str,
    ) -> Result<usize, rusqlite::Error> {
        let count = self.conn.execute(
            "DELETE FROM binaries WHERE package_manager = ?1 AND package_name = ?2",
            params![manager.to_string(), package_name],
        )?;
        debug!("Removed {} binaries for package {}", count, package_name);
        Ok(count)
    }

    /// Count binaries by package manager
    pub fn count_by_manager(&self, manager: PackageManager) -> Result<usize, rusqlite::Error> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM binaries WHERE package_manager = ?1",
            params![manager.to_string()],
            |row| row.get(0),
        )
    }

    /// Count distinct packages by package manager
    pub fn count_packages_by_manager(
        &self,
        manager: PackageManager,
    ) -> Result<usize, rusqlite::Error> {
        self.conn.query_row(
            "SELECT COUNT(DISTINCT package_name) FROM binaries WHERE package_manager = ?1",
            params![manager.to_string()],
            |row| row.get(0),
        )
    }

    /// Get stored package version for a package
    pub fn get_package_version(
        &self,
        manager: PackageManager,
        package_name: &str,
    ) -> Result<Option<String>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT package_version FROM binaries
                 WHERE package_manager = ?1 AND package_name = ?2 LIMIT 1",
                params![manager.to_string(), package_name],
                |row| row.get(0),
            )
            .optional()
    }

    /// Set a metadata key-value pair
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a metadata value
    pub fn get_metadata(&self, key: &str) -> Result<Option<String>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }
}

fn row_to_binary(row: &rusqlite::Row<'_>) -> Result<MonitoredBinary, rusqlite::Error> {
    let path_str: String = row.get(0)?;
    let manager_str: String = row.get(5)?;
    let symlink_str: Option<String> = row.get(6)?;
    let verified_str: String = row.get(8)?;

    let manager = manager_str
        .parse::<PackageManager>()
        .unwrap_or(PackageManager::Apt);

    let last_verified = DateTime::parse_from_rfc3339(&verified_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(MonitoredBinary {
        path: PathBuf::from(path_str),
        sha256: row.get(1)?,
        md5: row.get(2)?,
        package_name: row.get(3)?,
        package_version: row.get(4)?,
        package_manager: manager,
        symlink_target: symlink_str.map(PathBuf::from),
        size: row.get::<_, i64>(7)? as u64,
        last_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PackageManager;

    fn test_binary(name: &str, hash: &str) -> MonitoredBinary {
        MonitoredBinary {
            path: PathBuf::from(format!("/usr/bin/{}", name)),
            sha256: hash.to_string(),
            md5: Some("md5hash".to_string()),
            package_name: name.to_string(),
            package_version: "1.0.0".to_string(),
            package_manager: PackageManager::Apt,
            symlink_target: None,
            size: 1024,
            last_verified: Utc::now(),
        }
    }

    #[test]
    fn create_and_open_database() {
        let db = BaselineDb::in_memory().unwrap();
        assert_eq!(db.count_by_manager(PackageManager::Apt).unwrap(), 0);
    }

    #[test]
    fn upsert_and_retrieve_binary() {
        let db = BaselineDb::in_memory().unwrap();
        let binary = test_binary("curl", "sha256abc");

        db.upsert_binary(&binary).unwrap();

        let retrieved = db
            .get_binary(Path::new("/usr/bin/curl"), PackageManager::Apt)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.sha256, "sha256abc");
        assert_eq!(retrieved.package_name, "curl");
    }

    #[test]
    fn upsert_updates_existing() {
        let db = BaselineDb::in_memory().unwrap();
        let mut binary = test_binary("curl", "hash1");
        db.upsert_binary(&binary).unwrap();

        binary.sha256 = "hash2".to_string();
        binary.package_version = "2.0.0".to_string();
        db.upsert_binary(&binary).unwrap();

        let retrieved = db
            .get_binary(Path::new("/usr/bin/curl"), PackageManager::Apt)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.sha256, "hash2");
        assert_eq!(retrieved.package_version, "2.0.0");
        assert_eq!(db.count_by_manager(PackageManager::Apt).unwrap(), 1);
    }

    #[test]
    fn batch_upsert() {
        let mut db = BaselineDb::in_memory().unwrap();
        let binaries = vec![
            test_binary("curl", "h1"),
            test_binary("wget", "h2"),
            test_binary("ssh", "h3"),
        ];
        db.upsert_binaries(&binaries).unwrap();
        assert_eq!(db.count_by_manager(PackageManager::Apt).unwrap(), 3);
    }

    #[test]
    fn get_binaries_by_manager() {
        let mut db = BaselineDb::in_memory().unwrap();
        let apt_binary = test_binary("curl", "h1");
        let mut brew_binary = test_binary("rg", "h2");
        brew_binary.package_manager = PackageManager::Homebrew;
        brew_binary.path = PathBuf::from("/opt/homebrew/bin/rg");

        db.upsert_binaries(&[apt_binary, brew_binary]).unwrap();

        let apt_bins = db.get_binaries_by_manager(PackageManager::Apt).unwrap();
        assert_eq!(apt_bins.len(), 1);
        let brew_bins = db.get_binaries_by_manager(PackageManager::Homebrew).unwrap();
        assert_eq!(brew_bins.len(), 1);
    }

    #[test]
    fn remove_package() {
        let mut db = BaselineDb::in_memory().unwrap();
        let binaries = vec![test_binary("curl", "h1"), test_binary("wget", "h2")];
        db.upsert_binaries(&binaries).unwrap();

        let removed = db.remove_package(PackageManager::Apt, "curl").unwrap();
        assert_eq!(removed, 1);
        assert_eq!(db.count_by_manager(PackageManager::Apt).unwrap(), 1);
    }

    #[test]
    fn count_packages() {
        let mut db = BaselineDb::in_memory().unwrap();
        let b1 = test_binary("curl", "h1");
        let mut b2 = test_binary("curl-dev", "h2");
        b2.package_name = "curl".to_string(); // same package, different binary
        b2.path = PathBuf::from("/usr/bin/curl-dev");
        let b3 = test_binary("wget", "h3");

        db.upsert_binaries(&[b1, b2, b3]).unwrap();
        assert_eq!(db.count_packages_by_manager(PackageManager::Apt).unwrap(), 2);
    }

    #[test]
    fn get_package_version() {
        let db = BaselineDb::in_memory().unwrap();
        let binary = test_binary("curl", "h1");
        db.upsert_binary(&binary).unwrap();

        let version = db
            .get_package_version(PackageManager::Apt, "curl")
            .unwrap();
        assert_eq!(version, Some("1.0.0".to_string()));
    }

    #[test]
    fn metadata_operations() {
        let db = BaselineDb::in_memory().unwrap();
        db.set_metadata("last_scan", "2026-04-11T00:00:00Z").unwrap();
        let val = db.get_metadata("last_scan").unwrap();
        assert_eq!(val, Some("2026-04-11T00:00:00Z".to_string()));

        db.set_metadata("last_scan", "2026-04-12T00:00:00Z").unwrap();
        let val = db.get_metadata("last_scan").unwrap();
        assert_eq!(val, Some("2026-04-12T00:00:00Z".to_string()));
    }

    #[test]
    fn persistent_database() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("test.db");

        {
            let mut db = BaselineDb::open(&db_path).unwrap();
            db.upsert_binaries(&[test_binary("curl", "h1")]).unwrap();
        }

        {
            let db = BaselineDb::open(&db_path).unwrap();
            assert_eq!(db.count_by_manager(PackageManager::Apt).unwrap(), 1);
        }
    }
}
