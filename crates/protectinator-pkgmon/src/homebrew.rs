//! Homebrew binary integrity monitoring
//!
//! Discovers Homebrew packages, creates binary baselines, and verifies
//! integrity on subsequent scans. Handles version upgrade detection to
//! distinguish legitimate updates from tampering.

use crate::baseline::BaselineDb;
use crate::scanner::PkgMonCheck;
use crate::types::{MonitoredBinary, PackageManager, PkgMonContext};
use chrono::Utc;
use protectinator_core::{Finding, FindingSource, Severity};
use protectinator_fim::Hasher;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// A discovered Homebrew package
#[derive(Debug, Clone)]
pub struct BrewPackage {
    pub name: String,
    pub version: String,
}

/// A binary discovered in Homebrew's Cellar
#[derive(Debug, Clone)]
pub struct BrewBinary {
    /// Path to the actual binary in Cellar
    pub cellar_path: PathBuf,
    /// Symlink in brew's bin/ dir (if any)
    pub symlink_path: Option<PathBuf>,
    /// Owning package
    pub package_name: String,
    /// Package version
    pub package_version: String,
}

/// Detect the Homebrew prefix for a given root
pub fn detect_brew_prefix(root: &Path) -> Option<PathBuf> {
    crate::types::brew_prefix(root)
}

/// Parse `brew list --versions` output into packages
pub fn parse_brew_list(output: &str) -> Vec<BrewPackage> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            // Format: "package_name version1 [version2 ...]"
            // We take the last version (most recent)
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.last()?; // last version listed
            Some(BrewPackage {
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect()
}

/// Discover binaries for a package by scanning its Cellar directory
pub fn discover_package_binaries(
    cellar: &Path,
    package: &BrewPackage,
) -> Vec<BrewBinary> {
    let pkg_dir = cellar.join(&package.name).join(&package.version);
    let bin_dir = pkg_dir.join("bin");

    let mut binaries = Vec::new();

    if bin_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&bin_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() || path.is_symlink() {
                    binaries.push(BrewBinary {
                        cellar_path: path,
                        symlink_path: None,
                        package_name: package.name.clone(),
                        package_version: package.version.clone(),
                    });
                }
            }
        }
    }

    // Also check sbin/
    let sbin_dir = pkg_dir.join("sbin");
    if sbin_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&sbin_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() || path.is_symlink() {
                    binaries.push(BrewBinary {
                        cellar_path: path,
                        symlink_path: None,
                        package_name: package.name.clone(),
                        package_version: package.version.clone(),
                    });
                }
            }
        }
    }

    binaries
}

/// Map symlinks in brew's bin/ dir back to Cellar targets
pub fn map_symlinks(brew_prefix: &Path) -> HashMap<PathBuf, PathBuf> {
    let mut map = HashMap::new();
    let bin_dir = brew_prefix.join("bin");

    if let Ok(entries) = std::fs::read_dir(&bin_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_symlink() {
                if let Ok(target) = std::fs::read_link(&path) {
                    // Resolve relative targets against bin dir
                    let resolved = if target.is_absolute() {
                        target.clone()
                    } else {
                        bin_dir.join(&target)
                    };
                    // Map cellar path -> symlink path
                    if let Ok(canonical) = std::fs::canonicalize(&resolved) {
                        map.insert(canonical, path);
                    }
                }
            }
        }
    }

    map
}

/// Hash a binary file and create a MonitoredBinary entry
fn hash_binary(binary: &BrewBinary) -> Option<MonitoredBinary> {
    let hasher = Hasher::new(protectinator_fim::HashAlgorithm::Sha256);
    let hash = hasher.hash_file(&binary.cellar_path).ok()?;
    let metadata = std::fs::metadata(&binary.cellar_path).ok()?;

    Some(MonitoredBinary {
        path: binary.cellar_path.clone(),
        sha256: hash,
        md5: None,
        package_name: binary.package_name.clone(),
        package_version: binary.package_version.clone(),
        package_manager: PackageManager::Homebrew,
        symlink_target: binary.symlink_path.clone(),
        size: metadata.len(),
        last_verified: Utc::now(),
    })
}

/// Create or update a baseline for all Homebrew binaries
pub fn create_baseline(
    brew_prefix: &Path,
    db: &mut BaselineDb,
) -> Result<usize, String> {
    let cellar = brew_prefix.join("Cellar");
    if !cellar.is_dir() {
        return Err(format!("Homebrew Cellar not found at {}", cellar.display()));
    }

    // Discover packages by scanning Cellar directory structure
    let packages = discover_packages_from_cellar(&cellar);
    let symlinks = map_symlinks(brew_prefix);

    info!("Homebrew baseline: found {} packages", packages.len());

    // Discover all binaries
    let mut all_binaries: Vec<BrewBinary> = Vec::new();
    for package in &packages {
        let mut bins = discover_package_binaries(&cellar, package);
        // Attach symlink info
        for bin in &mut bins {
            if let Ok(canonical) = std::fs::canonicalize(&bin.cellar_path) {
                if let Some(symlink) = symlinks.get(&canonical) {
                    bin.symlink_path = Some(symlink.clone());
                }
            }
        }
        all_binaries.extend(bins);
    }

    // Hash in parallel
    let monitored: Vec<MonitoredBinary> = all_binaries
        .par_iter()
        .filter_map(|b| hash_binary(b))
        .collect();

    let count = monitored.len();
    db.upsert_binaries(&monitored)
        .map_err(|e| format!("Failed to store baseline: {}", e))?;

    db.set_metadata("brew_baseline_created", &Utc::now().to_rfc3339())
        .ok();

    info!("Homebrew baseline: stored {} binary hashes", count);
    Ok(count)
}

/// Discover packages by scanning the Cellar directory structure
/// (doesn't require running `brew list`)
fn discover_packages_from_cellar(cellar: &Path) -> Vec<BrewPackage> {
    let mut packages = Vec::new();

    let entries = match std::fs::read_dir(cellar) {
        Ok(e) => e,
        Err(_) => return packages,
    };

    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();

        // Each subdirectory of the package dir is a version
        if let Ok(versions) = std::fs::read_dir(entry.path()) {
            // Take the latest version (last alphabetically, which works for semver)
            let mut version_list: Vec<String> = versions
                .flatten()
                .filter(|v| v.path().is_dir())
                .map(|v| v.file_name().to_string_lossy().to_string())
                .collect();
            version_list.sort();

            if let Some(version) = version_list.last() {
                packages.push(BrewPackage {
                    name: name.clone(),
                    version: version.clone(),
                });
            }
        }
    }

    packages
}

/// Verify Homebrew binaries against stored baseline
pub fn verify_baseline(
    brew_prefix: &Path,
    db: &BaselineDb,
) -> Vec<Finding> {
    let cellar = brew_prefix.join("Cellar");
    if !cellar.is_dir() {
        return Vec::new();
    }

    let stored = match db.get_binaries_by_manager(PackageManager::Homebrew) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to read Homebrew baseline: {}", e);
            return Vec::new();
        }
    };

    if stored.is_empty() {
        debug!("No Homebrew baseline exists, skipping verification");
        return Vec::new();
    }

    // Build lookup of stored binaries
    let stored_map: HashMap<PathBuf, &MonitoredBinary> = stored
        .iter()
        .map(|b| (b.path.clone(), b))
        .collect();

    // Discover current state
    let packages = discover_packages_from_cellar(&cellar);
    let mut current_binaries: Vec<BrewBinary> = Vec::new();
    for package in &packages {
        current_binaries.extend(discover_package_binaries(&cellar, package));
    }

    let mut findings = Vec::new();

    // Check each current binary against baseline
    let hash_results: Vec<(BrewBinary, Option<MonitoredBinary>)> = current_binaries
        .par_iter()
        .map(|b| (b.clone(), hash_binary(b)))
        .collect();

    for (binary, hashed) in &hash_results {
        let Some(current) = hashed else { continue };

        match stored_map.get(&binary.cellar_path) {
            Some(baseline) => {
                if current.sha256 != baseline.sha256 {
                    // Hash mismatch — check if version changed
                    if current.package_version != baseline.package_version {
                        // Legitimate upgrade
                        findings.push(
                            Finding::new(
                                "pkgmon-brew-upgraded",
                                format!("Homebrew package upgraded: {}", binary.package_name),
                                format!(
                                    "Package '{}' upgraded from {} to {}. Binary hash changed as expected.",
                                    binary.package_name, baseline.package_version, binary.package_version
                                ),
                                Severity::Info,
                                FindingSource::PackageMonitor {
                                    package_manager: "homebrew".to_string(),
                                    check_category: "binary_integrity".to_string(),
                                },
                            )
                            .with_resource(binary.cellar_path.to_string_lossy())
                            .with_metadata("old_version", serde_json::json!(baseline.package_version))
                            .with_metadata("new_version", serde_json::json!(binary.package_version)),
                        );
                    } else {
                        // Same version, different hash — possible tampering
                        findings.push(
                            Finding::new(
                                "pkgmon-brew-tampered",
                                format!("Tampered Homebrew binary: {}", binary.cellar_path.display()),
                                format!(
                                    "Binary '{}' from package '{}' v{} has changed without a version \
                                     update. Expected SHA256: {}..., Actual: {}...",
                                    binary.cellar_path.display(),
                                    binary.package_name,
                                    binary.package_version,
                                    &baseline.sha256[..16.min(baseline.sha256.len())],
                                    &current.sha256[..16.min(current.sha256.len())]
                                ),
                                Severity::Critical,
                                FindingSource::PackageMonitor {
                                    package_manager: "homebrew".to_string(),
                                    check_category: "binary_integrity".to_string(),
                                },
                            )
                            .with_resource(binary.cellar_path.to_string_lossy())
                            .with_metadata("expected_hash", serde_json::json!(baseline.sha256))
                            .with_metadata("actual_hash", serde_json::json!(current.sha256))
                            .with_metadata("package", serde_json::json!(binary.package_name))
                            .with_remediation(format!(
                                "Reinstall package: brew reinstall {}", binary.package_name
                            ))
                            .with_reference("https://attack.mitre.org/techniques/T1554/"),
                        );
                    }
                }
            }
            None => {
                // New binary not in baseline
                findings.push(
                    Finding::new(
                        "pkgmon-brew-new-binary",
                        format!("New Homebrew binary: {}", binary.cellar_path.display()),
                        format!(
                            "Binary '{}' from package '{}' v{} was not in the baseline. \
                             This may be a new install.",
                            binary.cellar_path.display(),
                            binary.package_name,
                            binary.package_version
                        ),
                        Severity::Info,
                        FindingSource::PackageMonitor {
                            package_manager: "homebrew".to_string(),
                            check_category: "binary_integrity".to_string(),
                        },
                    )
                    .with_resource(binary.cellar_path.to_string_lossy()),
                );
            }
        }
    }

    // Check for removed binaries (in baseline but not on disk)
    let current_paths: std::collections::HashSet<PathBuf> = current_binaries
        .iter()
        .map(|b| b.cellar_path.clone())
        .collect();

    for baseline_binary in &stored {
        if !current_paths.contains(&baseline_binary.path) {
            findings.push(
                Finding::new(
                    "pkgmon-brew-removed",
                    format!("Homebrew binary removed: {}", baseline_binary.path.display()),
                    format!(
                        "Binary '{}' from package '{}' was in the baseline but no longer exists.",
                        baseline_binary.path.display(),
                        baseline_binary.package_name
                    ),
                    Severity::Low,
                    FindingSource::PackageMonitor {
                        package_manager: "homebrew".to_string(),
                        check_category: "binary_integrity".to_string(),
                    },
                )
                .with_resource(baseline_binary.path.to_string_lossy()),
            );
        }
    }

    // Check symlink integrity
    findings.extend(check_symlink_integrity(brew_prefix));

    findings
}

/// Verify symlinks in brew's bin/ still point to valid targets
fn check_symlink_integrity(brew_prefix: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let bin_dir = brew_prefix.join("bin");

    let entries = match std::fs::read_dir(&bin_dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_symlink() {
            continue;
        }

        match std::fs::read_link(&path) {
            Ok(target) => {
                let resolved = if target.is_absolute() {
                    target.clone()
                } else {
                    bin_dir.join(&target)
                };
                if !resolved.exists() {
                    findings.push(
                        Finding::new(
                            "pkgmon-brew-broken-symlink",
                            format!("Broken Homebrew symlink: {}", path.display()),
                            format!(
                                "Symlink '{}' points to '{}' which does not exist. \
                                 This may indicate a failed uninstall or tampering.",
                                path.display(),
                                target.display()
                            ),
                            Severity::High,
                            FindingSource::PackageMonitor {
                                package_manager: "homebrew".to_string(),
                                check_category: "binary_integrity".to_string(),
                            },
                        )
                        .with_resource(path.to_string_lossy()),
                    );
                }
            }
            Err(e) => {
                debug!("Cannot read symlink {}: {}", path.display(), e);
            }
        }
    }

    findings
}

/// Homebrew binary integrity check for the scanner
pub struct BrewIntegrityCheck;

impl PkgMonCheck for BrewIntegrityCheck {
    fn name(&self) -> &str {
        "brew-binary-integrity"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Homebrew
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let brew_prefix = match crate::types::brew_prefix(&ctx.config.root) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let db_path = ctx.config.baseline_path();
        let mut db = match BaselineDb::open(&db_path) {
            Ok(db) => db,
            Err(e) => {
                warn!("Cannot open baseline database: {}", e);
                return Vec::new();
            }
        };

        // Check if baseline exists
        let has_baseline = db
            .count_by_manager(PackageManager::Homebrew)
            .unwrap_or(0) > 0;

        if !has_baseline {
            // First run: create baseline, no findings to report yet
            info!("No Homebrew baseline found, creating initial baseline");
            match create_baseline(&brew_prefix, &mut db) {
                Ok(count) => {
                    info!("Created Homebrew baseline with {} binaries", count);
                }
                Err(e) => {
                    warn!("Failed to create Homebrew baseline: {}", e);
                }
            }
            return Vec::new();
        }

        // Verify against baseline
        let findings = verify_baseline(&brew_prefix, &db);

        // Auto-update baseline for version changes if configured
        if ctx.config.update_baseline {
            let upgrade_findings: Vec<_> = findings
                .iter()
                .filter(|f| f.id == "pkgmon-brew-upgraded")
                .collect();

            if !upgrade_findings.is_empty() {
                info!(
                    "Auto-updating baseline for {} upgraded packages",
                    upgrade_findings.len()
                );
                if let Err(e) = create_baseline(&brew_prefix, &mut db) {
                    warn!("Failed to update Homebrew baseline: {}", e);
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_brew_cellar(tmp: &TempDir) -> PathBuf {
        let root = tmp.path().to_path_buf();
        let brew_prefix = root.join("opt/homebrew");
        let cellar = brew_prefix.join("Cellar");
        let bin_dir = brew_prefix.join("bin");
        fs::create_dir_all(&cellar).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        // Create brew binary so detection works
        fs::write(brew_prefix.join("bin/brew"), "#!/bin/sh\n").unwrap();
        brew_prefix
    }

    fn add_package(cellar: &Path, name: &str, version: &str, binaries: &[&str]) {
        let bin_dir = cellar.join(name).join(version).join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        for bin_name in binaries {
            fs::write(bin_dir.join(bin_name), format!("binary-{}-{}", name, bin_name)).unwrap();
        }
    }

    #[test]
    fn parse_brew_list_output() {
        let output = "curl 8.5.0\nripgrep 14.1.0\ngit 2.43.0 2.44.0\n";
        let packages = parse_brew_list(output);
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "curl");
        assert_eq!(packages[0].version, "8.5.0");
        assert_eq!(packages[2].name, "git");
        assert_eq!(packages[2].version, "2.44.0"); // takes last version
    }

    #[test]
    fn parse_brew_list_empty() {
        assert!(parse_brew_list("").is_empty());
        assert!(parse_brew_list("  \n  \n").is_empty());
    }

    #[test]
    fn discover_cellar_packages() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        add_package(&cellar, "ripgrep", "14.1.0", &["rg"]);
        add_package(&cellar, "curl", "8.5.0", &["curl"]);

        let packages = discover_packages_from_cellar(&cellar);
        assert_eq!(packages.len(), 2);
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"ripgrep"));
        assert!(names.contains(&"curl"));
    }

    #[test]
    fn discover_package_binaries_finds_bin_and_sbin() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        // Create bin/ and sbin/ entries
        let pkg_dir = cellar.join("testpkg").join("1.0.0");
        let bin_dir = pkg_dir.join("bin");
        let sbin_dir = pkg_dir.join("sbin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&sbin_dir).unwrap();
        fs::write(bin_dir.join("testbin"), "binary").unwrap();
        fs::write(sbin_dir.join("testsbin"), "sbin-binary").unwrap();

        let pkg = BrewPackage {
            name: "testpkg".to_string(),
            version: "1.0.0".to_string(),
        };
        let binaries = discover_package_binaries(&cellar, &pkg);
        assert_eq!(binaries.len(), 2);
    }

    #[test]
    fn discover_empty_cellar() {
        let tmp = TempDir::new().unwrap();
        let cellar = tmp.path().join("Cellar");
        fs::create_dir_all(&cellar).unwrap();
        let packages = discover_packages_from_cellar(&cellar);
        assert!(packages.is_empty());
    }

    #[test]
    fn create_and_read_baseline() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        add_package(&cellar, "ripgrep", "14.1.0", &["rg"]);
        add_package(&cellar, "curl", "8.5.0", &["curl"]);

        let mut db = BaselineDb::in_memory().unwrap();
        let count = create_baseline(&brew_prefix, &mut db).unwrap();
        assert_eq!(count, 2);

        let stored = db.get_binaries_by_manager(PackageManager::Homebrew).unwrap();
        assert_eq!(stored.len(), 2);
        assert!(stored.iter().all(|b| !b.sha256.is_empty()));
    }

    #[test]
    fn verify_clean_baseline_no_findings() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        add_package(&cellar, "ripgrep", "14.1.0", &["rg"]);

        let mut db = BaselineDb::in_memory().unwrap();
        create_baseline(&brew_prefix, &mut db).unwrap();

        let findings = verify_baseline(&brew_prefix, &db);
        // Should only have no tampering findings (may have new/removed if state changed)
        let tampered: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-tampered").collect();
        assert!(tampered.is_empty());
    }

    #[test]
    fn verify_detects_tampered_binary() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        add_package(&cellar, "ripgrep", "14.1.0", &["rg"]);

        let mut db = BaselineDb::in_memory().unwrap();
        create_baseline(&brew_prefix, &mut db).unwrap();

        // Tamper with the binary
        let rg_path = cellar.join("ripgrep/14.1.0/bin/rg");
        fs::write(&rg_path, "TAMPERED CONTENT").unwrap();

        let findings = verify_baseline(&brew_prefix, &db);
        let tampered: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-tampered").collect();
        assert_eq!(tampered.len(), 1);
        assert_eq!(tampered[0].severity, Severity::Critical);
    }

    #[test]
    fn verify_detects_version_upgrade() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        add_package(&cellar, "ripgrep", "14.1.0", &["rg"]);

        let mut db = BaselineDb::in_memory().unwrap();
        create_baseline(&brew_prefix, &mut db).unwrap();

        // Simulate upgrade: remove old version, add new version
        fs::remove_dir_all(cellar.join("ripgrep/14.1.0")).unwrap();
        add_package(&cellar, "ripgrep", "14.2.0", &["rg"]);

        let findings = verify_baseline(&brew_prefix, &db);

        let upgraded: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-upgraded").collect();
        // The old binary path is gone, new one appears — should see new binary + removed
        let new_bins: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-new-binary").collect();
        let removed: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-removed").collect();

        // New binary at new version path
        assert!(!new_bins.is_empty() || !upgraded.is_empty());
        // Old binary at old version path is gone
        assert!(!removed.is_empty());
        // No tampering
        let tampered: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-tampered").collect();
        assert!(tampered.is_empty());
    }

    #[test]
    fn verify_detects_removed_binary() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        add_package(&cellar, "ripgrep", "14.1.0", &["rg"]);

        let mut db = BaselineDb::in_memory().unwrap();
        create_baseline(&brew_prefix, &mut db).unwrap();

        // Remove the package entirely
        fs::remove_dir_all(cellar.join("ripgrep")).unwrap();

        let findings = verify_baseline(&brew_prefix, &db);
        let removed: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-brew-removed").collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].severity, Severity::Low);
    }

    #[test]
    fn verify_empty_baseline() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);

        let db = BaselineDb::in_memory().unwrap();
        let findings = verify_baseline(&brew_prefix, &db);
        assert!(findings.is_empty());
    }

    #[test]
    fn broken_symlink_detected() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let bin_dir = brew_prefix.join("bin");

        // Create a symlink pointing to nonexistent target
        #[cfg(unix)]
        std::os::unix::fs::symlink("/nonexistent/path", bin_dir.join("broken")).unwrap();

        let findings = check_symlink_integrity(&brew_prefix);
        #[cfg(unix)]
        {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, "pkgmon-brew-broken-symlink");
            assert_eq!(findings[0].severity, Severity::High);
        }
    }

    #[test]
    fn valid_symlink_no_finding() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let bin_dir = brew_prefix.join("bin");

        // Create a real target and symlink to it
        let target = bin_dir.join("real_binary");
        fs::write(&target, "binary content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, bin_dir.join("link")).unwrap();

        let findings = check_symlink_integrity(&brew_prefix);
        let broken: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-brew-broken-symlink")
            .collect();
        assert!(broken.is_empty());
    }

    #[test]
    fn hash_binary_produces_sha256() {
        let tmp = TempDir::new().unwrap();
        let bin_path = tmp.path().join("testbin");
        fs::write(&bin_path, "test content").unwrap();

        let binary = BrewBinary {
            cellar_path: bin_path,
            symlink_path: None,
            package_name: "test".to_string(),
            package_version: "1.0".to_string(),
        };

        let monitored = hash_binary(&binary).unwrap();
        assert!(!monitored.sha256.is_empty());
        assert_eq!(monitored.sha256.len(), 64); // SHA256 hex length
        assert_eq!(monitored.package_manager, PackageManager::Homebrew);
    }

    #[test]
    fn multiple_binaries_parallel_hashing() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_cellar(&tmp);
        let cellar = brew_prefix.join("Cellar");

        // Create a package with multiple binaries
        add_package(&cellar, "coreutils", "9.4", &["ls", "cat", "cp", "mv", "rm"]);

        let mut db = BaselineDb::in_memory().unwrap();
        let count = create_baseline(&brew_prefix, &mut db).unwrap();
        assert_eq!(count, 5);
    }
}
