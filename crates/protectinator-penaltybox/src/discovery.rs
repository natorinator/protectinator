//! Package binary discovery via dpkg

use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

/// Information about a binary belonging to a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageBinary {
    /// Absolute path to the binary
    pub path: PathBuf,
    /// Package that owns this binary
    pub package: String,
    /// Whether the binary has the SUID bit set
    pub is_suid: bool,
}

/// Discovers binaries belonging to system packages
pub struct PackageDiscovery;

impl PackageDiscovery {
    /// List all executable binaries installed by a package.
    ///
    /// Uses `dpkg -L <package>` and filters to bin/sbin/lib paths,
    /// checking that files are actually executable.
    pub fn find_binaries(package: &str) -> Result<Vec<PackageBinary>, String> {
        let output = Command::new("dpkg")
            .args(["-L", package])
            .output()
            .map_err(|e| format!("Failed to run dpkg -L: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "dpkg -L {} failed: {}",
                package,
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut binaries = Vec::new();

        for line in stdout.lines() {
            let path = line.trim();
            if path.is_empty() {
                continue;
            }

            // Filter to executable directories
            if !is_bin_path(path) {
                continue;
            }

            let pb = PathBuf::from(path);

            // Must be a file and executable
            let meta = match std::fs::metadata(&pb) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if !meta.is_file() {
                continue;
            }

            let mode = meta.permissions().mode();
            let is_executable = mode & 0o111 != 0;
            if !is_executable {
                continue;
            }

            let is_suid = mode & 0o4000 != 0;

            binaries.push(PackageBinary {
                path: pb,
                package: package.to_string(),
                is_suid,
            });
        }

        Ok(binaries)
    }

    /// Find which package owns a binary path.
    ///
    /// Uses `dpkg -S <path>` and parses the output.
    pub fn find_package_for_binary(binary_path: &str) -> Result<String, String> {
        let output = Command::new("dpkg")
            .args(["-S", binary_path])
            .output()
            .map_err(|e| format!("Failed to run dpkg -S: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "dpkg -S {} failed: {}",
                binary_path,
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output format: "package-name: /path/to/binary"
        // May also be "package-name, other-package: /path" for diversions
        if let Some(colon_idx) = stdout.find(':') {
            let packages = stdout[..colon_idx].trim();
            // Take the first package if multiple
            let package = packages.split(',').next().unwrap_or("").trim();
            if !package.is_empty() {
                return Ok(package.to_string());
            }
        }

        Err(format!("Could not parse dpkg -S output: {}", stdout.trim()))
    }

    /// Get the installed version of a package.
    ///
    /// Uses `dpkg -s <package>` and parses the Version field.
    pub fn get_package_version(package: &str) -> Result<String, String> {
        let output = Command::new("dpkg")
            .args(["-s", package])
            .output()
            .map_err(|e| format!("Failed to run dpkg -s: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "dpkg -s {} failed: {}",
                package,
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(version) = line.strip_prefix("Version: ") {
                return Ok(version.trim().to_string());
            }
        }

        Err(format!("No Version field found for package {}", package))
    }

    /// Check if gaol is available on the system.
    pub fn gaol_available() -> bool {
        Command::new("gaol")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Check if a path is in a standard binary/library directory
fn is_bin_path(path: &str) -> bool {
    path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/lib/")
            && path.contains("/bin/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bin_path() {
        assert!(is_bin_path("/usr/bin/curl"));
        assert!(is_bin_path("/usr/sbin/sshd"));
        assert!(is_bin_path("/bin/ls"));
        assert!(is_bin_path("/sbin/iptables"));
        assert!(!is_bin_path("/usr/share/doc/curl/README"));
        assert!(!is_bin_path("/etc/curl/curlrc"));
        assert!(!is_bin_path("/var/lib/something"));
    }

    #[test]
    #[ignore] // Requires dpkg
    fn test_find_binaries_coreutils() {
        let binaries = PackageDiscovery::find_binaries("coreutils").unwrap();
        assert!(!binaries.is_empty(), "coreutils should have binaries");
        // Should contain /usr/bin/ls or /bin/ls
        let has_ls = binaries.iter().any(|b| {
            b.path.file_name().map_or(false, |n| n == "ls")
        });
        assert!(has_ls, "coreutils should include ls");
    }

    #[test]
    #[ignore] // Requires dpkg
    fn test_find_package_for_binary() {
        let pkg = PackageDiscovery::find_package_for_binary("/usr/bin/ls").unwrap();
        assert_eq!(pkg, "coreutils");
    }

    #[test]
    #[ignore] // Requires dpkg
    fn test_get_package_version() {
        let version = PackageDiscovery::get_package_version("coreutils").unwrap();
        assert!(!version.is_empty(), "coreutils should have a version");
    }

    #[test]
    fn test_find_binaries_nonexistent_package() {
        let result = PackageDiscovery::find_binaries("this-package-does-not-exist-12345");
        assert!(result.is_err());
    }
}
