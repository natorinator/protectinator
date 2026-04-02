//! Penalty box profile persistence and wrapper script generation

use crate::restrictions::{NetworkPolicy, SandboxRestrictions};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A persisted penalty box profile for a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyBoxProfile {
    /// Package name
    pub package: String,
    /// Binary paths being sandboxed
    pub binaries: Vec<PathBuf>,
    /// Sandbox restrictions
    pub restrictions: SandboxRestrictions,
    /// CVEs that triggered this penalty box
    pub cves: Vec<String>,
    /// Human-readable reason
    pub reason: String,
    /// When the penalty box was created
    pub created_at: DateTime<Utc>,
    /// Package version that will auto-lift this penalty box (if known)
    pub auto_lift_version: Option<String>,
    /// Whether this profile is currently active
    pub active: bool,
}

impl PenaltyBoxProfile {
    /// Create a new active penalty box profile.
    pub fn new(
        package: String,
        binaries: Vec<PathBuf>,
        restrictions: SandboxRestrictions,
        cves: Vec<String>,
        reason: String,
    ) -> Self {
        Self {
            package,
            binaries,
            restrictions,
            cves,
            reason,
            created_at: Utc::now(),
            auto_lift_version: None,
            active: true,
        }
    }

    /// Set the version that will auto-lift this penalty box.
    pub fn with_auto_lift(mut self, version: String) -> Self {
        self.auto_lift_version = Some(version);
        self
    }

    /// Generate the gaol sandbox command for a specific binary.
    ///
    /// Returns a list of arguments starting with "gaol".
    pub fn gaol_command(&self, binary: &Path) -> Vec<String> {
        let mut args = vec!["gaol".to_string(), "sandbox".to_string()];

        for path in &self.restrictions.read_paths {
            args.push("--read".to_string());
            args.push(path.display().to_string());
        }
        for path in &self.restrictions.write_paths {
            args.push("--write".to_string());
            args.push(path.display().to_string());
        }

        match &self.restrictions.network {
            NetworkPolicy::AllowAll => {
                args.push("--allow-network".to_string());
            }
            _ => {} // blocked by default
        }

        args.push("--".to_string());
        args.push(binary.display().to_string());
        args
    }

    /// Generate a shell wrapper script that runs the binary through gaol sandbox.
    pub fn generate_wrapper_script(&self, binary: &Path) -> String {
        let cmd = self.gaol_command(binary);
        let mut script = String::from("#!/bin/sh\n");
        script.push_str(&format!(
            "# Penalty Box wrapper for {} ({})\n",
            self.package,
            self.cves.join(", ")
        ));
        script.push_str(&format!("# Reason: {}\n", self.reason));
        script.push_str(&format!(
            "# Created: {}\n",
            self.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if let Some(ref lift_ver) = self.auto_lift_version {
            script.push_str(&format!(
                "# Auto-lifts when package upgrades to: {}\n",
                lift_ver
            ));
        }
        script.push_str(&format!(
            "exec {} \"$@\"\n",
            cmd.iter()
                .map(|a| shell_escape(a))
                .collect::<Vec<_>>()
                .join(" ")
        ));
        script
    }
}

/// Simple shell escaping for arguments
fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') || s.contains('\\') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

/// Directory where penalty box profiles are stored
pub fn profiles_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home).join(".config/protectinator/penalty-box"))
}

/// Save a profile to disk as TOML.
pub fn save_profile(profile: &PenaltyBoxProfile) -> Result<PathBuf, String> {
    save_profile_to(&profiles_dir()?, profile)
}

/// Save a profile to a specific directory.
pub fn save_profile_to(dir: &Path, profile: &PenaltyBoxProfile) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create penalty-box dir: {}", e))?;

    let path = dir.join(format!("{}.toml", profile.package));
    let content = toml::to_string_pretty(profile)
        .map_err(|e| format!("Failed to serialize profile: {}", e))?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write profile: {}", e))?;
    Ok(path)
}

/// Load a profile from disk.
pub fn load_profile(package: &str) -> Result<Option<PenaltyBoxProfile>, String> {
    load_profile_from(&profiles_dir()?, package)
}

/// Load a profile from a specific directory.
pub fn load_profile_from(dir: &Path, package: &str) -> Result<Option<PenaltyBoxProfile>, String> {
    let path = dir.join(format!("{}.toml", package));
    if !path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read profile: {}", e))?;
    let profile: PenaltyBoxProfile =
        toml::from_str(&content).map_err(|e| format!("Failed to parse profile: {}", e))?;
    Ok(Some(profile))
}

/// List all penalty box profiles.
pub fn list_profiles() -> Result<Vec<PenaltyBoxProfile>, String> {
    list_profiles_in(&profiles_dir()?)
}

/// List all penalty box profiles in a specific directory.
pub fn list_profiles_in(dir: &Path) -> Result<Vec<PenaltyBoxProfile>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut profiles = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("Failed to read dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "toml") {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
            if let Ok(profile) = toml::from_str::<PenaltyBoxProfile>(&content) {
                profiles.push(profile);
            }
        }
    }
    Ok(profiles)
}

/// Remove a penalty box profile.
pub fn remove_profile(package: &str) -> Result<bool, String> {
    remove_profile_from(&profiles_dir()?, package)
}

/// Remove a penalty box profile from a specific directory.
pub fn remove_profile_from(dir: &Path, package: &str) -> Result<bool, String> {
    let path = dir.join(format!("{}.toml", package));
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("Failed to remove: {}", e))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restrictions::SandboxRestrictions;
    use std::path::PathBuf;

    fn make_test_profile() -> PenaltyBoxProfile {
        PenaltyBoxProfile::new(
            "curl".to_string(),
            vec![PathBuf::from("/usr/bin/curl")],
            SandboxRestrictions::default_restrict(),
            vec!["CVE-2024-1234".to_string()],
            "Test penalty box".to_string(),
        )
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_path = dir.path().join("profiles");

        let profile = make_test_profile();
        let path = save_profile_to(&profiles_path, &profile).unwrap();
        assert!(path.exists());

        let loaded = load_profile_from(&profiles_path, "curl").unwrap().unwrap();
        assert_eq!(loaded.package, "curl");
        assert_eq!(loaded.cves, vec!["CVE-2024-1234"]);
        assert!(loaded.active);
        assert_eq!(loaded.binaries, vec![PathBuf::from("/usr/bin/curl")]);
    }

    #[test]
    fn test_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_path = dir.path().join("profiles");

        let loaded = load_profile_from(&profiles_path, "nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_list_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_path = dir.path().join("profiles");

        let p1 = make_test_profile();
        save_profile_to(&profiles_path, &p1).unwrap();

        let mut p2 = make_test_profile();
        p2.package = "wget".to_string();
        save_profile_to(&profiles_path, &p2).unwrap();

        let profiles = list_profiles_in(&profiles_path).unwrap();
        assert_eq!(profiles.len(), 2);
        let names: Vec<&str> = profiles.iter().map(|p| p.package.as_str()).collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"wget"));
    }

    #[test]
    fn test_remove_profile() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_path = dir.path().join("profiles");

        let profile = make_test_profile();
        save_profile_to(&profiles_path, &profile).unwrap();

        assert!(remove_profile_from(&profiles_path, "curl").unwrap());
        assert!(!remove_profile_from(&profiles_path, "curl").unwrap()); // already removed
        assert!(load_profile_from(&profiles_path, "curl").unwrap().is_none());
    }

    #[test]
    fn test_gaol_command_restrict() {
        let profile = make_test_profile();
        let cmd = profile.gaol_command(Path::new("/usr/bin/curl"));

        assert_eq!(cmd[0], "gaol");
        assert_eq!(cmd[1], "sandbox");

        // Should have --read flags for each read path
        let read_count = cmd.iter().filter(|a| *a == "--read").count();
        assert_eq!(read_count, profile.restrictions.read_paths.len());

        // Should have --write flags for each write path
        let write_count = cmd.iter().filter(|a| *a == "--write").count();
        assert_eq!(write_count, profile.restrictions.write_paths.len());

        // Should NOT have --allow-network (blocked by default)
        assert!(!cmd.contains(&"--allow-network".to_string()));

        // Should end with -- /usr/bin/curl
        assert_eq!(cmd[cmd.len() - 2], "--");
        assert_eq!(cmd[cmd.len() - 1], "/usr/bin/curl");
    }

    #[test]
    fn test_gaol_command_with_network() {
        let mut profile = make_test_profile();
        profile.restrictions.network = NetworkPolicy::AllowAll;
        let cmd = profile.gaol_command(Path::new("/usr/bin/curl"));
        assert!(cmd.contains(&"--allow-network".to_string()));
    }

    #[test]
    fn test_generate_wrapper_script() {
        let profile = make_test_profile();
        let script = profile.generate_wrapper_script(Path::new("/usr/bin/curl"));

        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("Penalty Box wrapper for curl"));
        assert!(script.contains("CVE-2024-1234"));
        assert!(script.contains("exec gaol sandbox"));
        assert!(script.contains("/usr/bin/curl"));
        assert!(script.ends_with("\"$@\"\n"));
    }

    #[test]
    fn test_generate_wrapper_script_with_auto_lift() {
        let profile = make_test_profile().with_auto_lift("8.5.0-1".to_string());
        let script = profile.generate_wrapper_script(Path::new("/usr/bin/curl"));
        assert!(script.contains("Auto-lifts when package upgrades to: 8.5.0-1"));
    }

    #[test]
    fn test_with_auto_lift() {
        let profile = make_test_profile().with_auto_lift("2.0.0".to_string());
        assert_eq!(profile.auto_lift_version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("simple"), "simple");
        assert_eq!(shell_escape("/usr/bin/curl"), "/usr/bin/curl");
        assert_eq!(shell_escape("has space"), "'has space'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_profile_toml_roundtrip() {
        let profile = make_test_profile().with_auto_lift("9.0.0".to_string());
        let toml_str = toml::to_string_pretty(&profile).unwrap();
        let parsed: PenaltyBoxProfile = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.package, profile.package);
        assert_eq!(parsed.cves, profile.cves);
        assert_eq!(parsed.auto_lift_version, profile.auto_lift_version);
        assert_eq!(parsed.active, profile.active);
    }
}
