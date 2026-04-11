//! Core types for package manager binary integrity monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Supported package managers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    /// apt/dpkg on Debian/Ubuntu
    Apt,
    /// Homebrew on macOS/Linux
    Homebrew,
    /// Flatpak (future use)
    Flatpak,
}

impl fmt::Display for PackageManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageManager::Apt => write!(f, "apt"),
            PackageManager::Homebrew => write!(f, "homebrew"),
            PackageManager::Flatpak => write!(f, "flatpak"),
        }
    }
}

impl FromStr for PackageManager {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "apt" | "dpkg" => Ok(PackageManager::Apt),
            "homebrew" | "brew" => Ok(PackageManager::Homebrew),
            "flatpak" => Ok(PackageManager::Flatpak),
            other => Err(format!("unknown package manager: {}", other)),
        }
    }
}

/// A binary tracked by the package monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredBinary {
    /// Absolute path to the binary
    pub path: PathBuf,

    /// SHA256 hash of the binary contents
    pub sha256: String,

    /// MD5 hash (for dpkg compatibility, apt only)
    pub md5: Option<String>,

    /// Package that owns this binary
    pub package_name: String,

    /// Version of the package when baseline was taken
    pub package_version: String,

    /// Which package manager installed it
    pub package_manager: PackageManager,

    /// If this is a symlink, where it points
    pub symlink_target: Option<PathBuf>,

    /// File size in bytes
    pub size: u64,

    /// When this binary was last verified
    pub last_verified: DateTime<Utc>,
}

/// A baseline snapshot for a package's binaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Which package manager
    pub package_manager: PackageManager,

    /// Package name
    pub package_name: String,

    /// Package version at baseline time
    pub package_version: String,

    /// All tracked binaries for this package
    pub binaries: Vec<MonitoredBinary>,

    /// When the baseline was created
    pub created_at: DateTime<Utc>,

    /// When the baseline was last updated
    pub updated_at: DateTime<Utc>,
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct PkgMonConfig {
    /// Root path for scanning (default: /)
    pub root: PathBuf,

    /// Filter to specific package manager (None = all detected)
    pub manager_filter: Option<PackageManager>,

    /// Whether to auto-update baseline on version changes
    pub update_baseline: bool,

    /// Path for baseline database storage
    pub baseline_db_path: Option<PathBuf>,
}

impl Default for PkgMonConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            manager_filter: None,
            update_baseline: false,
            baseline_db_path: None,
        }
    }
}

impl PkgMonConfig {
    /// Default baseline database path
    pub fn default_baseline_path() -> PathBuf {
        let data_dir = dirs_or_default();
        data_dir.join("pkgmon_baseline.db")
    }

    /// Get the baseline database path, using default if not set
    pub fn baseline_path(&self) -> PathBuf {
        self.baseline_db_path
            .clone()
            .unwrap_or_else(Self::default_baseline_path)
    }

    /// Whether a specific package manager should be scanned
    pub fn should_scan(&self, manager: PackageManager) -> bool {
        self.manager_filter.map_or(true, |f| f == manager)
    }
}

/// Shared context for package monitor checks
pub struct PkgMonContext {
    /// Scanner configuration
    pub config: PkgMonConfig,

    /// Detected available package managers
    pub detected_managers: Vec<PackageManager>,
}

impl PkgMonContext {
    pub fn new(config: PkgMonConfig) -> Self {
        let detected_managers = detect_package_managers(&config.root);
        Self {
            config,
            detected_managers,
        }
    }

    /// Check if a package manager is available on this system
    pub fn has_manager(&self, manager: PackageManager) -> bool {
        self.detected_managers.contains(&manager)
    }
}

/// Detect which package managers are available on the system
pub fn detect_package_managers(root: &Path) -> Vec<PackageManager> {
    let mut managers = Vec::new();

    // apt/dpkg: check for dpkg database
    if root.join("var/lib/dpkg/status").exists() {
        managers.push(PackageManager::Apt);
    }

    // Homebrew: check common installation paths
    if brew_prefix(root).is_some() {
        managers.push(PackageManager::Homebrew);
    }

    // Flatpak: check for flatpak binary
    if root.join("usr/bin/flatpak").exists()
        || root.join("var/lib/flatpak").exists()
    {
        managers.push(PackageManager::Flatpak);
    }

    managers
}

/// Find the Homebrew prefix on this system
pub fn brew_prefix(root: &Path) -> Option<PathBuf> {
    // macOS ARM
    let arm_prefix = root.join("opt/homebrew");
    if arm_prefix.join("bin/brew").exists() {
        return Some(arm_prefix);
    }

    // macOS Intel / Linux default
    let intel_prefix = root.join("usr/local");
    if intel_prefix.join("bin/brew").exists() {
        return Some(intel_prefix);
    }

    // Linuxbrew
    let linuxbrew_prefix = root.join("home/linuxbrew/.linuxbrew");
    if linuxbrew_prefix.join("bin/brew").exists() {
        return Some(linuxbrew_prefix);
    }

    None
}

/// Get the protectinator data directory, falling back to a reasonable default
fn dirs_or_default() -> PathBuf {
    if let Some(data_dir) = dirs_data_local() {
        data_dir.join("protectinator")
    } else {
        PathBuf::from("/var/lib/protectinator")
    }
}

/// Get XDG_DATA_HOME or ~/.local/share
fn dirs_data_local() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_display_roundtrip() {
        for pm in [PackageManager::Apt, PackageManager::Homebrew, PackageManager::Flatpak] {
            let s = pm.to_string();
            let parsed: PackageManager = s.parse().unwrap();
            assert_eq!(pm, parsed);
        }
    }

    #[test]
    fn package_manager_from_str_aliases() {
        assert_eq!("dpkg".parse::<PackageManager>().unwrap(), PackageManager::Apt);
        assert_eq!("brew".parse::<PackageManager>().unwrap(), PackageManager::Homebrew);
        assert_eq!("APT".parse::<PackageManager>().unwrap(), PackageManager::Apt);
    }

    #[test]
    fn package_manager_from_str_invalid() {
        assert!("unknown".parse::<PackageManager>().is_err());
    }

    #[test]
    fn config_default_scans_all() {
        let config = PkgMonConfig::default();
        assert!(config.should_scan(PackageManager::Apt));
        assert!(config.should_scan(PackageManager::Homebrew));
    }

    #[test]
    fn config_filter_scans_only_selected() {
        let config = PkgMonConfig {
            manager_filter: Some(PackageManager::Apt),
            ..Default::default()
        };
        assert!(config.should_scan(PackageManager::Apt));
        assert!(!config.should_scan(PackageManager::Homebrew));
    }

    #[test]
    fn detect_no_managers_on_empty_root() {
        let tmp = tempfile::tempdir().unwrap();
        let managers = detect_package_managers(tmp.path());
        assert!(managers.is_empty());
    }

    #[test]
    fn detect_apt_with_dpkg_status() {
        let tmp = tempfile::tempdir().unwrap();
        let dpkg_dir = tmp.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg_dir).unwrap();
        std::fs::write(dpkg_dir.join("status"), "").unwrap();
        let managers = detect_package_managers(tmp.path());
        assert!(managers.contains(&PackageManager::Apt));
    }

    #[test]
    fn detect_homebrew_arm_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let brew_bin = tmp.path().join("opt/homebrew/bin");
        std::fs::create_dir_all(&brew_bin).unwrap();
        std::fs::write(brew_bin.join("brew"), "").unwrap();
        let prefix = brew_prefix(tmp.path());
        assert_eq!(prefix, Some(tmp.path().join("opt/homebrew")));
    }

    #[test]
    fn detect_homebrew_linuxbrew_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let brew_bin = tmp.path().join("home/linuxbrew/.linuxbrew/bin");
        std::fs::create_dir_all(&brew_bin).unwrap();
        std::fs::write(brew_bin.join("brew"), "").unwrap();
        let prefix = brew_prefix(tmp.path());
        assert_eq!(prefix, Some(tmp.path().join("home/linuxbrew/.linuxbrew")));
    }

    #[test]
    fn monitored_binary_serialization() {
        let binary = MonitoredBinary {
            path: PathBuf::from("/usr/bin/test"),
            sha256: "abc123".to_string(),
            md5: Some("def456".to_string()),
            package_name: "coreutils".to_string(),
            package_version: "8.32-4".to_string(),
            package_manager: PackageManager::Apt,
            symlink_target: None,
            size: 1024,
            last_verified: Utc::now(),
        };
        let json = serde_json::to_string(&binary).unwrap();
        let roundtrip: MonitoredBinary = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.path, binary.path);
        assert_eq!(roundtrip.sha256, binary.sha256);
        assert_eq!(roundtrip.package_manager, binary.package_manager);
    }

    #[test]
    fn baseline_entry_serialization() {
        let entry = BaselineEntry {
            package_manager: PackageManager::Homebrew,
            package_name: "ripgrep".to_string(),
            package_version: "14.0.0".to_string(),
            binaries: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let roundtrip: BaselineEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.package_name, entry.package_name);
        assert_eq!(roundtrip.package_manager, entry.package_manager);
    }
}
