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
use std::time::SystemTime;
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

// --- Tap Reputation Scoring ---

/// Reputation score for a Homebrew tap
#[derive(Debug, Clone, serde::Serialize)]
pub struct TapReputation {
    pub stars: u64,
    pub forks: u64,
    pub age_days: u64,
    pub last_push_days: u64,
    pub archived: bool,
    pub score: u32,
}

/// Query GitHub API for tap repository metadata and compute a reputation score
pub fn score_tap(tap: &BrewTap) -> Result<TapReputation, String> {
    // Map tap to GitHub repo: owner/homebrew-<short_name>
    let github_repo = format!("{}/{}", tap.owner, tap.repo);
    let url = format!("https://api.github.com/repos/{}", github_repo);

    debug!("Querying GitHub API for tap reputation: {}", url);

    let response = ureq::get(&url)
        .set("User-Agent", "protectinator")
        .set("Accept", "application/vnd.github.v3+json")
        .call()
        .map_err(|e| format!("GitHub API request failed for {}: {}", github_repo, e))?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("Failed to parse GitHub API response: {}", e))?;

    let stars = body["stargazers_count"].as_u64().unwrap_or(0);
    let forks = body["forks_count"].as_u64().unwrap_or(0);
    let archived = body["archived"].as_bool().unwrap_or(false);

    let now = chrono::Utc::now();

    let age_days = body["created_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| (now - dt.with_timezone(&chrono::Utc)).num_days().max(0) as u64)
        .unwrap_or(0);

    let last_push_days = body["pushed_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| (now - dt.with_timezone(&chrono::Utc)).num_days().max(0) as u64)
        .unwrap_or(999);

    let score = compute_reputation_score(stars, forks, age_days, last_push_days, archived);

    Ok(TapReputation {
        stars,
        forks,
        age_days,
        last_push_days,
        archived,
        score,
    })
}

/// Compute a 0-100 reputation score
fn compute_reputation_score(
    stars: u64,
    forks: u64,
    age_days: u64,
    last_push_days: u64,
    archived: bool,
) -> u32 {
    let mut score: i32 = 0;

    // Age: max 30 points at 2+ years
    let age_score = ((age_days as f64 / 730.0) * 30.0).min(30.0) as i32;
    score += age_score;

    // Stars: max 25 points at 100+
    let star_score = ((stars as f64 / 100.0) * 25.0).min(25.0) as i32;
    score += star_score;

    // Activity: max 25 points if pushed < 90 days
    let activity_score = if last_push_days < 30 {
        25
    } else if last_push_days < 90 {
        20
    } else if last_push_days < 180 {
        10
    } else if last_push_days < 365 {
        5
    } else {
        0
    };
    score += activity_score;

    // Forks: max 20 points at 20+
    let fork_score = ((forks as f64 / 20.0) * 20.0).min(20.0) as i32;
    score += fork_score;

    // Deductions
    if archived {
        score -= 50;
    }
    if last_push_days > 365 {
        score -= 30;
    }

    score.clamp(0, 100) as u32
}

/// Cache key for tap reputation in baseline DB metadata
fn reputation_cache_key(tap: &BrewTap) -> String {
    format!("tap_reputation:{}", tap.name)
}

/// Get cached reputation score, returning None if stale (>24h)
pub fn get_cached_reputation(
    db: &crate::baseline::BaselineDb,
    tap: &BrewTap,
) -> Option<TapReputation> {
    let key = reputation_cache_key(tap);
    let cached = db.get_metadata(&key).ok()??;
    let parsed: serde_json::Value = serde_json::from_str(&cached).ok()?;

    // Check cache freshness (24h)
    let cached_at = parsed["cached_at"].as_str()?;
    let cached_time = chrono::DateTime::parse_from_rfc3339(cached_at).ok()?;
    let age = chrono::Utc::now() - cached_time.with_timezone(&chrono::Utc);
    if age.num_hours() > 24 {
        return None;
    }

    Some(TapReputation {
        stars: parsed["stars"].as_u64()?,
        forks: parsed["forks"].as_u64()?,
        age_days: parsed["age_days"].as_u64()?,
        last_push_days: parsed["last_push_days"].as_u64()?,
        archived: parsed["archived"].as_bool()?,
        score: parsed["score"].as_u64()? as u32,
    })
}

/// Cache a reputation score
pub fn cache_reputation(
    db: &crate::baseline::BaselineDb,
    tap: &BrewTap,
    rep: &TapReputation,
) {
    let key = reputation_cache_key(tap);
    let value = serde_json::json!({
        "stars": rep.stars,
        "forks": rep.forks,
        "age_days": rep.age_days,
        "last_push_days": rep.last_push_days,
        "archived": rep.archived,
        "score": rep.score,
        "cached_at": chrono::Utc::now().to_rfc3339(),
    });
    if let Err(e) = db.set_metadata(&key, &value.to_string()) {
        warn!("Failed to cache tap reputation for {}: {}", tap.name, e);
    }
}

/// Homebrew tap reputation check
pub struct BrewTapReputationCheck;

impl PkgMonCheck for BrewTapReputationCheck {
    fn name(&self) -> &str {
        "brew-tap-reputation"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Homebrew
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        if !ctx.config.online {
            debug!("Skipping tap reputation check (offline mode)");
            return Vec::new();
        }

        let brew_prefix = match crate::types::brew_prefix(&ctx.config.root) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let taps = discover_taps(&brew_prefix);
        let third_party: Vec<_> = taps.iter().filter(|t| !t.is_official).collect();

        if third_party.is_empty() {
            return Vec::new();
        }

        // Open baseline DB for caching
        let db = crate::baseline::BaselineDb::open(&ctx.config.baseline_path()).ok();

        let mut findings = Vec::new();

        for tap in third_party {
            // Try cache first
            let reputation = if let Some(ref db) = db {
                get_cached_reputation(db, tap).or_else(|| {
                    match score_tap(tap) {
                        Ok(rep) => {
                            cache_reputation(db, tap, &rep);
                            Some(rep)
                        }
                        Err(e) => {
                            warn!("Failed to score tap {}: {}", tap.name, e);
                            None
                        }
                    }
                })
            } else {
                score_tap(tap).ok()
            };

            let Some(rep) = reputation else { continue };

            let (severity, label) = if rep.score < 20 {
                (Severity::High, "very low")
            } else if rep.score < 50 {
                (Severity::Medium, "low")
            } else {
                (Severity::Info, "acceptable")
            };

            findings.push(
                Finding::new(
                    "pkgmon-brew-tap-reputation",
                    format!("Homebrew tap reputation: {} (score: {}/100)", tap.name, rep.score),
                    format!(
                        "Tap '{}' has {} reputation (score: {}/100). \
                         Stars: {}, Forks: {}, Age: {} days, Last push: {} days ago{}.",
                        tap.name, label, rep.score,
                        rep.stars, rep.forks, rep.age_days, rep.last_push_days,
                        if rep.archived { ", ARCHIVED" } else { "" }
                    ),
                    severity,
                    FindingSource::PackageMonitor {
                        package_manager: "homebrew".to_string(),
                        check_category: "tap_reputation".to_string(),
                    },
                )
                .with_resource(tap.path.to_string_lossy())
                .with_metadata("score", serde_json::json!(rep.score))
                .with_metadata("stars", serde_json::json!(rep.stars))
                .with_metadata("forks", serde_json::json!(rep.forks))
                .with_metadata("age_days", serde_json::json!(rep.age_days))
                .with_metadata("last_push_days", serde_json::json!(rep.last_push_days))
                .with_metadata("archived", serde_json::json!(rep.archived)),
            );
        }

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

    // --- Reputation scoring tests ---

    #[test]
    fn score_high_reputation() {
        // Popular, active, old repo
        let score = compute_reputation_score(500, 50, 1000, 10, false);
        assert!(score >= 80, "score was {}", score);
    }

    #[test]
    fn score_low_reputation() {
        // No stars, no forks, new, no recent push
        let score = compute_reputation_score(0, 0, 30, 400, false);
        assert!(score < 20, "score was {}", score);
    }

    #[test]
    fn score_archived_penalty() {
        // Decent repo but archived
        let score_normal = compute_reputation_score(100, 20, 800, 50, false);
        let score_archived = compute_reputation_score(100, 20, 800, 50, true);
        assert!(score_archived < score_normal);
        assert!(score_archived <= 50, "archived score was {}", score_archived);
    }

    #[test]
    fn score_inactive_penalty() {
        // Good stats but no activity in >1 year
        let score = compute_reputation_score(50, 10, 1000, 500, false);
        // Should get age + star + fork points but lose activity and get inactivity penalty
        assert!(score < 60, "score was {}", score);
    }

    #[test]
    fn score_clamped_to_100() {
        let score = compute_reputation_score(10000, 10000, 10000, 1, false);
        assert_eq!(score, 100);
    }

    #[test]
    fn score_clamped_to_0() {
        let score = compute_reputation_score(0, 0, 0, 999, true);
        assert_eq!(score, 0);
    }

    #[test]
    fn cache_roundtrip() {
        let db = crate::baseline::BaselineDb::in_memory().unwrap();
        let tap = BrewTap {
            name: "test/tap".to_string(),
            owner: "test".to_string(),
            repo: "homebrew-tap".to_string(),
            path: PathBuf::from("/tmp/tap"),
            is_official: false,
        };
        let rep = TapReputation {
            stars: 42,
            forks: 5,
            age_days: 365,
            last_push_days: 10,
            archived: false,
            score: 75,
        };

        cache_reputation(&db, &tap, &rep);
        let cached = get_cached_reputation(&db, &tap).unwrap();
        assert_eq!(cached.score, 75);
        assert_eq!(cached.stars, 42);
    }

    #[test]
    fn reputation_check_offline_skips() {
        let tmp = TempDir::new().unwrap();
        let brew_prefix = setup_brew_with_taps(&tmp);
        add_tap(&brew_prefix, "someone", "homebrew-thing", true);

        let config = crate::types::PkgMonConfig {
            root: tmp.path().to_path_buf(),
            online: false,
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = BrewTapReputationCheck.check(&ctx);
        assert!(findings.is_empty());
    }
}
