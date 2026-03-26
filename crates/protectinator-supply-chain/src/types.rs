//! Supply chain scanner types and context

use protectinator_core::ScanResults;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Package ecosystem identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    PyPI,
    Npm,
    CratesIo,
}

impl Ecosystem {
    /// OSV ecosystem name for API queries
    pub fn osv_name(&self) -> &str {
        match self {
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Npm => "npm",
            Ecosystem::CratesIo => "crates.io",
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::PyPI => write!(f, "pypi"),
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::CratesIo => write!(f, "crates.io"),
        }
    }
}

/// A discovered lock file on the filesystem
#[derive(Debug, Clone)]
pub struct DiscoveredLockFile {
    /// Path to the lock file
    pub path: PathBuf,
    /// Ecosystem this lock file belongs to
    pub ecosystem: Ecosystem,
    /// Lock file format
    pub format: LockFileFormat,
}

/// Lock file format variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockFileFormat {
    CargoLock,
    PackageLockJson,
    RequirementsTxt,
    PipfileLock,
    PoetryLock,
    UvLock,
    YarnLock,
    PnpmLock,
}

/// Normalized package entry parsed from any lock file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub source_url: Option<String>,
    pub checksum: Option<String>,
}

/// Shared context passed to all supply chain checks
pub struct SupplyChainContext {
    /// Root filesystem path
    pub root: PathBuf,
    /// Discovered user home directories
    pub user_homes: Vec<PathBuf>,
    /// Pre-discovered lock files
    pub lock_files: Vec<DiscoveredLockFile>,
    /// Parsed packages from all lock files
    pub packages: Vec<PackageEntry>,
    /// Whether network access is available (for OSV queries)
    pub online: bool,
}

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainScanResults {
    /// Standard scan results with all findings
    pub scan_results: ScanResults,
    /// Number of packages scanned
    pub packages_scanned: usize,
    /// Number of lock files found
    pub lock_files_found: usize,
    /// Ecosystems detected
    pub ecosystems: Vec<String>,
}
