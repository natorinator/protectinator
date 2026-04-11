//! Homebrew tap audit and reputation scoring
//!
//! Audits Homebrew tap configuration for security issues:
//! - Third-party tap detection
//! - Tap git repository integrity
//! - Stale/unmaintained tap detection
//! - GitHub-based reputation scoring

use crate::scanner::PkgMonCheck;
use crate::types::{PackageManager, PkgMonContext};
use protectinator_core::{Finding, FindingSource, Severity};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Official Homebrew tap prefixes that don't need auditing
const OFFICIAL_TAPS: &[&str] = &[
    "homebrew/core",
    "homebrew/cask",
    "homebrew/bundle",
    "homebrew/services",
    "homebrew/cask-fonts",
    "homebrew/cask-versions",
    "homebrew/cask-drivers",
    "homebrew/command-not-found",
];

/// Days without fetch before a tap is considered stale
const STALE_FETCH_DAYS: u64 = 180;

/// Days without fetch before brew itself is considered outdated
const BREW_OUTDATED_DAYS: u64 = 90;

/// A discovered Homebrew tap
#[derive(Debug, Clone)]
pub struct BrewTap {
    /// Full tap name (e.g., "charmbracelet/tap")
    pub name: String,
    /// Owner (e.g., "charmbracelet")
    pub owner: String,
    /// Repo name (e.g., "homebrew-tap")
    pub repo: String,
    /// Path on disk
    pub path: PathBuf,
    /// Whether this is an official Homebrew tap
    pub is_official: bool,
}

/// Discover all installed taps by scanning the Taps directory
pub fn discover_taps(brew_prefix: &Path) -> Vec<BrewTap> {
    let taps_dir = find_taps_dir(brew_prefix);
    let taps_dir = match taps_dir {
        Some(d) => d,
        None => return Vec::new(),
    };

    let mut taps = Vec::new();

    let owners = match std::fs::read_dir(&taps_dir) {
        Ok(e) => e,
        Err(_) => return taps,
    };

    for owner_entry in owners.flatten() {
        if !owner_entry.path().is_dir() {
            continue;
        }
        let owner = owner_entry.file_name().to_string_lossy().to_string();

        let repos = match std::fs::read_dir(owner_entry.path()) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for repo_entry in repos.flatten() {
            if !repo_entry.path().is_dir() {
                continue;
            }
            let repo = repo_entry.file_name().to_string_lossy().to_string();

            // Tap name convention: owner/short-name (strip "homebrew-" prefix)
            let short_name = repo
                .strip_prefix("homebrew-")
                .unwrap_or(&repo)
                .to_string();
            let tap_name = format!("{}/{}", owner, short_name);

            let is_official = OFFICIAL_TAPS
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&tap_name));

            taps.push(BrewTap {
                name: tap_name,
                owner: owner.clone(),
                repo,
                path: repo_entry.path(),
                is_official,
            });
        }
    }

    taps
}

/// Find the Taps directory relative to brew prefix
fn find_taps_dir(brew_prefix: &Path) -> Option<PathBuf> {
    // Standard: <prefix>/Homebrew/Library/Taps (Linuxbrew)
    let linuxbrew = brew_prefix.join("Homebrew/Library/Taps");
    if linuxbrew.is_dir() {
        return Some(linuxbrew);
    }

    // macOS: <prefix>/Library/Taps
    let macos = brew_prefix.join("Library/Taps");
    if macos.is_dir() {
        return Some(macos);
    }

    None
}

/// Check git integrity of a tap directory
fn check_tap_git_integrity(tap: &BrewTap) -> Vec<Finding> {
    let mut findings = Vec::new();
    let git_dir = tap.path.join(".git");

    if !git_dir.exists() {
        findings.push(
            Finding::new(
                "pkgmon-brew-tap-no-git",
                format!("Homebrew tap missing .git: {}", tap.name),
                format!(
                    "Tap '{}' at {} has no .git directory. This tap may have been \
                     installed without git or the repository may be corrupted.",
                    tap.name,
                    tap.path.display()
                ),
                Severity::High,
                FindingSource::PackageMonitor {
                    package_manager: "homebrew".to_string(),
                    check_category: "tap_audit".to_string(),
                },
            )
            .with_resource(tap.path.to_string_lossy()),
        );
        return findings;
    }

    // Check HEAD exists
    let head_file = git_dir.join("HEAD");
    if !head_file.exists() {
        findings.push(
            Finding::new(
                "pkgmon-brew-tap-corrupt-git",
                format!("Homebrew tap corrupt .git: {}", tap.name),
                format!(
                    "Tap '{}' has a .git directory but no HEAD file. \
                     The git repository may be corrupted.",
                    tap.name
                ),
                Severity::High,
                FindingSource::PackageMonitor {
                    package_manager: "homebrew".to_string(),
                    check_category: "tap_audit".to_string(),
                },
            )
            .with_resource(tap.path.to_string_lossy()),
        );
    }

    findings
}

/// Check if a tap's FETCH_HEAD indicates staleness
fn check_tap_staleness(tap: &BrewTap) -> Option<Finding> {
    let fetch_head = tap.path.join(".git/FETCH_HEAD");
    let mtime = file_age_days(&fetch_head)?;

    if mtime > STALE_FETCH_DAYS {
        Some(
            Finding::new(
                "pkgmon-brew-tap-stale",
                format!("Stale Homebrew tap: {} ({} days)", tap.name, mtime),
                format!(
                    "Tap '{}' hasn't been fetched in {} days (threshold: {}). \
                     This tap may be abandoned or unmaintained. Consider removing it \
                     with 'brew untap {}'.",
                    tap.name, mtime, STALE_FETCH_DAYS, tap.name
                ),
                Severity::Medium,
                FindingSource::PackageMonitor {
                    package_manager: "homebrew".to_string(),
                    check_category: "tap_audit".to_string(),
                },
            )
            .with_resource(tap.path.to_string_lossy())
            .with_metadata("days_since_fetch", serde_json::json!(mtime))
            .with_remediation(format!("brew untap {}", tap.name)),
        )
    } else {
        None
    }
}

/// Get file age in days from its modification time
fn file_age_days(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let now = SystemTime::now();
    let age = now.duration_since(modified).ok()?;
    Some(age.as_secs() / 86400)
}

/// Check if Homebrew itself is outdated
fn check_brew_outdated(brew_prefix: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check FETCH_HEAD of the main Homebrew repo
    let fetch_paths = [
        brew_prefix.join("Homebrew/.git/FETCH_HEAD"),
        brew_prefix.join(".git/FETCH_HEAD"),
    ];

    for fetch_head in &fetch_paths {
        if let Some(days) = file_age_days(fetch_head) {
            if days > BREW_OUTDATED_DAYS {
                findings.push(
                    Finding::new(
                        "pkgmon-brew-outdated",
                        format!("Homebrew outdated ({} days since update)", days),
                        format!(
                            "Homebrew hasn't been updated in {} days (threshold: {}). \
                             Outdated Homebrew may have known security issues. \
                             Run 'brew update' to fetch the latest formulae and security fixes.",
                            days, BREW_OUTDATED_DAYS
                        ),
                        Severity::Low,
                        FindingSource::PackageMonitor {
                            package_manager: "homebrew".to_string(),
                            check_category: "tap_audit".to_string(),
                        },
                    )
                    .with_metadata("days_since_update", serde_json::json!(days))
                    .with_remediation("brew update"),
                );
            }
            break; // Found the FETCH_HEAD, no need to check other paths
        }
    }

    findings
}

/// Homebrew tap audit check
pub struct BrewTapAudit;

impl PkgMonCheck for BrewTapAudit {
    fn name(&self) -> &str {
        "brew-tap-audit"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Homebrew
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let brew_prefix = match crate::types::brew_prefix(&ctx.config.root) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let taps = discover_taps(&brew_prefix);
        let mut findings = Vec::new();

        info!("Homebrew tap audit: found {} taps", taps.len());

        for tap in &taps {
            if tap.is_official {
                debug!("Skipping official tap: {}", tap.name);
                continue;
            }

            // Flag third-party tap
            findings.push(
                Finding::new(
                    "pkgmon-brew-thirdparty-tap",
                    format!("Third-party Homebrew tap: {}", tap.name),
                    format!(
                        "Tap '{}' is not an official Homebrew tap. Third-party taps \
                         can distribute arbitrary formulae. Verify you trust the source: \
                         https://github.com/{}/homebrew-{}",
                        tap.name, tap.owner,
                        tap.repo.strip_prefix("homebrew-").unwrap_or(&tap.repo)
                    ),
                    Severity::Medium,
                    FindingSource::PackageMonitor {
                        package_manager: "homebrew".to_string(),
                        check_category: "tap_audit".to_string(),
                    },
                )
                .with_resource(tap.path.to_string_lossy())
                .with_metadata("tap_owner", serde_json::json!(tap.owner))
                .with_metadata("tap_repo", serde_json::json!(tap.repo)),
            );

            // Check git integrity
            findings.extend(check_tap_git_integrity(tap));

            // Check staleness
            if let Some(finding) = check_tap_staleness(tap) {
                findings.push(finding);
            }
        }

        // Check if brew itself is outdated
        findings.extend(check_brew_outdated(&brew_prefix));

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_brew_with_taps(tmp: &TempDir) -> PathBuf {
        let brew_prefix = tmp.path().join("opt/homebrew");
        let taps_dir = brew_prefix.join("Library/Taps");
        fs::create_dir_all(&taps_dir).unwrap();
        // Create brew binary for detection
        let bin_dir = brew_prefix.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("brew"), "").unwrap();
        brew_prefix
    }

    fn add_tap(brew_prefix: &Path, owner: &str, repo: &str, with_git: bool) {
        let taps_dir = find_taps_dir(brew_prefix).unwrap();
        let tap_dir = taps_dir.join(owner).join(repo);
        fs::create_dir_all(&tap_dir).unwrap();
        if with_git {
            let git_dir = tap_dir.join(".git");
            fs::create_dir_all(&git_dir).unwrap();
            fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
            fs::write(git_dir.join("FETCH_HEAD"), "abc123\tbranch 'main'\n").unwrap();
        }
    }

    #[test]
    fn discover_taps_finds_all() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        add_tap(&brew_prefix, "homebrew", "homebrew-core", true);
        add_tap(&brew_prefix, "charmbracelet", "homebrew-tap", true);
        add_tap(&brew_prefix, "erewhon", "homebrew-tap", true);

        let taps = discover_taps(&brew_prefix);
        assert_eq!(taps.len(), 3);
    }

    #[test]
    fn official_taps_detected() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        add_tap(&brew_prefix, "homebrew", "homebrew-core", true);
        add_tap(&brew_prefix, "homebrew", "homebrew-cask", true);

        let taps = discover_taps(&brew_prefix);
        assert!(taps.iter().all(|t| t.is_official));
    }

    #[test]
    fn thirdparty_tap_flagged() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        add_tap(&brew_prefix, "homebrew", "homebrew-core", true);
        add_tap(&brew_prefix, "evilcorp", "homebrew-malware", true);

        let config = crate::types::PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let check = BrewTapAudit;
        let findings = check.check(&ctx);

        let thirdparty: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-brew-thirdparty-tap")
            .collect();
        assert_eq!(thirdparty.len(), 1);
        assert!(thirdparty[0].title.contains("evilcorp"));
        assert_eq!(thirdparty[0].severity, Severity::Medium);
    }

    #[test]
    fn official_tap_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        add_tap(&brew_prefix, "homebrew", "homebrew-core", true);
        add_tap(&brew_prefix, "homebrew", "homebrew-cask", true);

        let config = crate::types::PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let check = BrewTapAudit;
        let findings = check.check(&ctx);

        let thirdparty: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-brew-thirdparty-tap")
            .collect();
        assert!(thirdparty.is_empty());
    }

    #[test]
    fn missing_git_flagged() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        add_tap(&brew_prefix, "sketchy", "homebrew-tools", false);

        let config = crate::types::PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = BrewTapAudit.check(&ctx);

        let no_git: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-brew-tap-no-git")
            .collect();
        assert_eq!(no_git.len(), 1);
        assert_eq!(no_git[0].severity, Severity::High);
    }

    #[test]
    fn corrupt_git_flagged() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        // Create tap with .git but no HEAD
        let taps_dir = find_taps_dir(&brew_prefix).unwrap();
        let tap_dir = taps_dir.join("broken").join("homebrew-thing");
        let git_dir = tap_dir.join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        // Don't create HEAD file

        let config = crate::types::PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = BrewTapAudit.check(&ctx);

        let corrupt: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-brew-tap-corrupt-git")
            .collect();
        assert_eq!(corrupt.len(), 1);
        assert_eq!(corrupt[0].severity, Severity::High);
    }

    #[test]
    fn no_taps_dir_graceful() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = tmp.path().join("opt/homebrew");
        fs::create_dir_all(brew_prefix.join("bin")).unwrap();
        fs::write(brew_prefix.join("bin/brew"), "").unwrap();
        // Don't create Taps dir

        let taps = discover_taps(&brew_prefix);
        assert!(taps.is_empty());
    }

    #[test]
    fn tap_name_strips_homebrew_prefix() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);

        add_tap(&brew_prefix, "charmbracelet", "homebrew-tap", true);

        let taps = discover_taps(&brew_prefix);
        let charm = taps.iter().find(|t| t.owner == "charmbracelet").unwrap();
        assert_eq!(charm.name, "charmbracelet/tap");
        assert_eq!(charm.repo, "homebrew-tap");
    }

    #[test]
    fn file_age_days_recent() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("recent");
        fs::write(&path, "test").unwrap();
        let age = file_age_days(&path);
        assert_eq!(age, Some(0));
    }

    #[test]
    fn file_age_days_missing() {
        let age = file_age_days(Path::new("/nonexistent/path"));
        assert!(age.is_none());
    }

    #[test]
    fn linuxbrew_taps_dir() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = tmp.path().join("linuxbrew");
        let taps_dir = brew_prefix.join("Homebrew/Library/Taps");
        fs::create_dir_all(&taps_dir).unwrap();

        let found = find_taps_dir(&brew_prefix);
        assert_eq!(found, Some(taps_dir));
    }
}
