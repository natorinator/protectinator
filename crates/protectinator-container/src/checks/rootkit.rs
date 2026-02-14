//! Rootkit indicator checks
//!
//! Scans the container filesystem for known rootkit file signatures,
//! suspicious SUID binaries, and modified system files.

use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};

/// Known rootkit file paths and directories
const ROOTKIT_INDICATORS: &[(&str, &str, Severity)] = &[
    // Known rootkit files
    ("/usr/lib/libproc.a", "Possible Linux Rootkit (libproc.a)", Severity::Critical),
    ("/dev/.udev/.initramfs", "Suspicious hidden file in /dev", Severity::High),
    ("/etc/ld.so.hash", "Possible rootkit library (ld.so.hash)", Severity::High),
    // Knark rootkit
    ("/proc/knark", "Knark rootkit indicator", Severity::Critical),
    ("/dev/.pizda", "Knark rootkit indicator", Severity::Critical),
    ("/dev/.mondst", "Knark rootkit indicator", Severity::Critical),
    // Suckit rootkit
    ("/sbin/initsk12", "Suckit rootkit indicator", Severity::Critical),
    ("/dev/sdhu0/tehdrakg", "Suckit rootkit indicator", Severity::Critical),
    // T0rn rootkit
    ("/dev/.lib", "T0rn rootkit indicator (hidden lib)", Severity::Critical),
    ("/dev/.lib/lib", "T0rn rootkit indicator", Severity::Critical),
    // Adore rootkit
    ("/etc/.adore", "Adore rootkit indicator", Severity::Critical),
    ("/usr/lib/red.tar", "Adore rootkit indicator", Severity::Critical),
    // General suspicious
    ("/usr/bin/.sshd", "Hidden sshd binary", Severity::Critical),
    ("/usr/sbin/.sshd", "Hidden sshd binary", Severity::Critical),
    ("/tmp/.scsi", "Suspicious hidden file in /tmp", Severity::High),
    ("/tmp/.font-unix", "Suspicious hidden file in /tmp", Severity::Medium),
];

/// Directories to check for hidden files that shouldn't have them
const SYSTEM_DIRS_NO_HIDDEN: &[&str] = &[
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/sbin",
    "/bin",
];

/// Check for rootkit indicators in the container filesystem
pub struct RootkitCheck;

impl ContainerCheck for RootkitCheck {
    fn id(&self) -> &str {
        "container-rootkit"
    }

    fn name(&self) -> &str {
        "Rootkit Indicator Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_known_rootkit_files(fs, &mut findings);
        check_ld_preload(fs, &mut findings);
        check_hidden_files_in_system_dirs(fs, &mut findings);

        findings
    }
}

/// Check for known rootkit file signatures
fn check_known_rootkit_files(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for (path, description, severity) in ROOTKIT_INDICATORS {
        if fs.exists(path) {
            findings.push(
                Finding::new(
                    format!("container-rootkit-{}", path.replace('/', "-").trim_matches('-')),
                    format!("Rootkit indicator found: {}", path),
                    description.to_string(),
                    *severity,
                    FindingSource::AgentDetection {
                        agent_type: "rootkit".to_string(),
                        category: "filesystem".to_string(),
                    },
                )
                .with_resource(path.to_string())
                .with_remediation(
                    "Investigate this file immediately. If confirmed as a rootkit, \
                     the container should be destroyed and rebuilt from a known-good image.",
                ),
            );
        }
    }
}

/// Check /etc/ld.so.preload for suspicious entries
fn check_ld_preload(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let content = match fs.read_to_string("/etc/ld.so.preload") {
        Ok(c) => c,
        Err(_) => return, // File doesn't exist — that's fine
    };

    let entries: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if entries.is_empty() {
        return;
    }

    // Any entry in ld.so.preload is suspicious in a container
    for entry in &entries {
        let severity = if entry.contains("/tmp/") || entry.contains("/dev/") {
            Severity::Critical
        } else {
            Severity::High
        };

        findings.push(
            Finding::new(
                "container-rootkit-ldpreload",
                format!("Suspicious ld.so.preload entry: {}", entry),
                "The /etc/ld.so.preload file is used to preload shared libraries into every process. \
                 This is commonly abused by rootkits to intercept system calls.",
                severity,
                FindingSource::AgentDetection {
                    agent_type: "rootkit".to_string(),
                    category: "ld_preload".to_string(),
                },
            )
            .with_resource(format!("/etc/ld.so.preload: {}", entry))
            .with_remediation("Remove the suspicious entry from /etc/ld.so.preload and investigate the referenced library")
            .with_reference("https://attack.mitre.org/techniques/T1574/006/"),
        );
    }
}

/// Check for hidden files in system directories
fn check_hidden_files_in_system_dirs(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for dir in SYSTEM_DIRS_NO_HIDDEN {
        let entries = match fs.read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Hidden files start with a dot
            if !name_str.starts_with('.') {
                continue;
            }

            // Skip common legitimate hidden files
            let legitimate_hidden = [
                ".", "..", ".gitkeep",
                // Standard system files
                ".pwd.lock",               // shadow-utils — password file lock
                ".updated",                // systemd — tracks last update timestamp
                ".resolv.conf.systemd-resolved.bak", // systemd-resolved backup
                ".java",                   // Java system preferences
                ".mono",                   // Mono framework config
                ".directory",              // KDE directory settings
                ".hidden",                 // GNOME hidden files list
            ];
            if legitimate_hidden.contains(&name_str.as_ref()) {
                continue;
            }

            let inner_path = format!("{}/{}", dir, name_str);

            findings.push(
                Finding::new(
                    format!("container-rootkit-hidden-{}", dir.replace('/', "-").trim_matches('-')),
                    format!("Hidden file in system directory: {}", inner_path),
                    format!(
                        "Found hidden file '{}' in system directory '{}'. \
                         Hidden files in system directories can indicate rootkit activity.",
                        name_str, dir
                    ),
                    Severity::Medium,
                    FindingSource::AgentDetection {
                        agent_type: "rootkit".to_string(),
                        category: "hidden_files".to_string(),
                    },
                )
                .with_resource(inner_path),
            );
        }
    }
}
