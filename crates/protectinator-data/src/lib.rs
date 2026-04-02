//! Read-only query layer for Protectinator scan data
//!
//! Provides typed access to scan history, vulnerability cache, and SBOM files
//! without duplicating query logic across CLI and web interfaces.

pub mod scan_store;
pub mod sbom_store;
pub mod types;
pub mod vuln_store;

pub use scan_store::ScanStore;
pub use sbom_store::SbomStore;
pub use types::*;
pub use vuln_store::VulnStore;

pub use protectinator_core::suppress::Suppressions;
use std::path::{Path, PathBuf};

/// Default data directory: ~/.local/share/protectinator
pub fn default_data_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".local/share/protectinator"))
}

/// Combined data store providing access to all Protectinator data sources
pub struct DataStore {
    pub scans: ScanStore,
    pub vulns: VulnStore,
    pub sboms: SbomStore,
}

impl DataStore {
    /// Open all data stores from the default directory
    pub fn open_default() -> Result<Self, String> {
        let dir = default_data_dir()?;
        Self::open(&dir)
    }

    /// Open all data stores from a specific directory
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let scans = ScanStore::open(&data_dir.join("scan_history.db"))?;
        let vulns = VulnStore::open(&data_dir.join("vuln_cache.db"))?;
        let sboms = SbomStore::new(&data_dir.join("sboms"));
        Ok(Self { scans, vulns, sboms })
    }

    /// Status summary for health check endpoints
    pub fn status(&self) -> DataStoreStatus {
        DataStoreStatus {
            scan_count: self.scans.total_scan_count().unwrap_or(0),
            finding_count: self.scans.total_finding_count().unwrap_or(0),
            last_scan: self.scans.most_recent_scan().ok().flatten(),
            vuln_cache_count: self.vulns.cached_count().unwrap_or(0),
            sbom_count: self.sboms.count(),
        }
    }
}
