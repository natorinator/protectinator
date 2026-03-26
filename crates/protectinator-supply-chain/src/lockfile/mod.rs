//! Lock file discovery and parsing
//!
//! Discovers and parses lock files from various package ecosystems:
//! Cargo.lock (Rust), package-lock.json (npm), requirements.txt / Pipfile.lock (Python).

pub mod cargo_lock;
pub mod npm_lock;
pub mod pipfile_lock;
pub mod requirements_txt;

use crate::types::{DiscoveredLockFile, Ecosystem, LockFileFormat, PackageEntry};
use protectinator_container::filesystem::ContainerFs;
use walkdir::WalkDir;

/// Lock file names and their corresponding ecosystem/format mappings
const LOCK_FILE_MAPPINGS: &[(&str, Ecosystem, LockFileFormat)] = &[
    ("Cargo.lock", Ecosystem::CratesIo, LockFileFormat::CargoLock),
    (
        "package-lock.json",
        Ecosystem::Npm,
        LockFileFormat::PackageLockJson,
    ),
    ("yarn.lock", Ecosystem::Npm, LockFileFormat::YarnLock),
    ("pnpm-lock.yaml", Ecosystem::Npm, LockFileFormat::PnpmLock),
    (
        "requirements.txt",
        Ecosystem::PyPI,
        LockFileFormat::RequirementsTxt,
    ),
    (
        "Pipfile.lock",
        Ecosystem::PyPI,
        LockFileFormat::PipfileLock,
    ),
    ("poetry.lock", Ecosystem::PyPI, LockFileFormat::PoetryLock),
    ("uv.lock", Ecosystem::PyPI, LockFileFormat::UvLock),
];

/// Walk the filesystem from the container root to discover lock files.
///
/// Searches the current directory and up to 3 levels of subdirectories
/// (max_depth=4 for walkdir) for known lock file names.
pub fn discover_lock_files(fs: &ContainerFs) -> Vec<DiscoveredLockFile> {
    let mut results = Vec::new();

    for entry in WalkDir::new(fs.root())
        .max_depth(4)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let file_name = match entry.file_name().to_str() {
            Some(name) => name,
            None => continue,
        };

        for &(lock_name, ecosystem, format) in LOCK_FILE_MAPPINGS {
            if file_name == lock_name {
                results.push(DiscoveredLockFile {
                    path: entry.path().to_path_buf(),
                    ecosystem,
                    format,
                });
                break;
            }
        }
    }

    results
}

/// Parse a discovered lock file into normalized package entries.
///
/// Reads the file content via the ContainerFs and dispatches to the
/// appropriate format-specific parser.
pub fn parse_lock_file(_fs: &ContainerFs, lock_file: &DiscoveredLockFile) -> Vec<PackageEntry> {
    let path_str = lock_file.path.to_string_lossy();
    let content = match std::fs::read_to_string(&lock_file.path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to read lock file {}: {}", path_str, e);
            return Vec::new();
        }
    };

    match lock_file.format {
        LockFileFormat::CargoLock => cargo_lock::parse(&content),
        LockFileFormat::PackageLockJson => npm_lock::parse(&content),
        LockFileFormat::RequirementsTxt => requirements_txt::parse(&content),
        LockFileFormat::PipfileLock => pipfile_lock::parse(&content),
        LockFileFormat::PoetryLock | LockFileFormat::UvLock => {
            tracing::warn!(
                "Parser for {:?} not yet implemented, skipping {}",
                lock_file.format,
                path_str
            );
            Vec::new()
        }
        LockFileFormat::YarnLock | LockFileFormat::PnpmLock => {
            tracing::warn!(
                "Parser for {:?} not yet implemented, skipping {}",
                lock_file.format,
                path_str
            );
            Vec::new()
        }
    }
}
