//! Persistence mechanism checks for containers
//!
//! Scans for persistence mechanisms inside the container filesystem,
//! similar to the host-level persistence scan but operating on the
//! container's root filesystem.

use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};

/// Cron directories to check
const CRON_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
];

/// Well-known cron entries shipped by standard Debian/Ubuntu packages.
/// These are expected and should be reported as Info, not Low/High.
const STANDARD_CRON_ENTRIES: &[(&str, &str)] = &[
    ("apt-compat", "apt — periodic package list refresh"),
    ("dpkg", "dpkg — database backup"),
    ("logrotate", "logrotate — log file rotation"),
    ("man-db", "man-db — manual page index rebuild"),
    ("e2scrub_all", "e2fsprogs — ext4 filesystem scrub scheduling"),
    ("popularity-contest", "popcon — package usage survey"),
    ("passwd", "shadow-utils — password expiry check"),
    ("exim4-base", "exim4 — mail queue maintenance"),
    ("sysstat", "sysstat — system activity data collector"),
    ("mlocate", "mlocate — file database update"),
    ("plocate", "plocate — file database update"),
    ("bsdmainutils", "bsdmainutils — calendar reminders"),
    ("google-chrome-stable", "Chrome — repository key rotation"),
    ("cracklib-runtime", "cracklib — dictionary refresh"),
    (".placeholder", "placeholder file"),
];

/// Systemd unit directories to check
const SYSTEMD_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/usr/local/lib/systemd/system",
];

/// Shell profile files to check
const SHELL_PROFILES: &[&str] = &[
    "/etc/profile",
    "/etc/profile.d",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zshrc",
    "/etc/zsh/zshrc",
];

/// Init script directories
const INIT_DIRS: &[&str] = &["/etc/init.d", "/etc/rc.local"];

/// Check for persistence mechanisms in a container
pub struct PersistenceCheck;

impl ContainerCheck for PersistenceCheck {
    fn id(&self) -> &str {
        "container-persistence"
    }

    fn name(&self) -> &str {
        "Container Persistence Mechanism Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_cron_dirs(fs, &mut findings);
        check_systemd_units(fs, &mut findings);
        check_shell_profiles(fs, &mut findings);
        check_init_scripts(fs, &mut findings);
        check_ssh_authorized_keys(fs, &mut findings);
        check_at_jobs(fs, &mut findings);

        findings
    }
}

/// Check cron directories for entries
fn check_cron_dirs(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for dir in CRON_DIRS {
        let entries = match fs.read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip placeholder and hidden files
            if name_str == ".placeholder" || name_str == ".gitkeep" {
                continue;
            }

            let inner_path = format!("{}/{}", dir, name_str);

            // Check if this is a well-known cron entry from a standard package
            let is_standard = STANDARD_CRON_ENTRIES
                .iter()
                .any(|(known_name, _)| *known_name == name_str.as_ref());
            let standard_desc = STANDARD_CRON_ENTRIES
                .iter()
                .find(|(known_name, _)| *known_name == name_str.as_ref())
                .map(|(_, desc)| *desc);

            // Read content to check for suspicious patterns
            let content = fs.read_to_string(&inner_path).ok();
            let (dangerous, mild) = content
                .as_deref()
                .map(assess_cron_risk)
                .unwrap_or_default();

            let (severity, title, description) = if !dangerous.is_empty() {
                // Truly dangerous patterns (reverse shells, network downloads) — always flag
                let all_reasons: Vec<_> = dangerous.iter().chain(mild.iter()).cloned().collect();
                (
                    Severity::High,
                    format!("Suspicious cron job: {}", inner_path),
                    format!(
                        "Cron entry '{}' contains dangerous patterns: {}. Investigate immediately.",
                        name_str,
                        all_reasons.join(", ")
                    ),
                )
            } else if is_standard {
                // Known standard cron entry — mild patterns like `eval` are expected
                let desc = standard_desc.unwrap_or("standard package");
                (
                    Severity::Info,
                    format!("Standard cron job: {} ({})", name_str, desc),
                    format!(
                        "Cron entry '{}' from standard package ({}).",
                        name_str, desc
                    ),
                )
            } else if !mild.is_empty() {
                // Non-standard entry with mild suspicious patterns
                (
                    Severity::Medium,
                    format!("Cron job with notable patterns: {}", inner_path),
                    format!(
                        "Non-standard cron entry '{}' contains: {}. Review to ensure legitimacy.",
                        name_str,
                        mild.join(", ")
                    ),
                )
            } else if content.is_some() {
                // Non-standard, but content looks clean
                (
                    Severity::Low,
                    format!("Custom cron job: {}", inner_path),
                    format!(
                        "Non-standard cron entry '{}' found. Content appears clean but should be reviewed.",
                        name_str
                    ),
                )
            } else {
                (
                    Severity::Low,
                    format!("Cron job found: {}", inner_path),
                    format!("Cron entry '{}' found. Unable to read content for analysis.", name_str),
                )
            };

            let mut finding = Finding::new(
                "container-persistence-cron",
                title,
                description,
                severity,
                FindingSource::Persistence {
                    persistence_type: "cron".to_string(),
                    location: inner_path.clone(),
                },
            )
            .with_resource(inner_path)
            .with_reference("https://attack.mitre.org/techniques/T1053/003/");

            if severity == Severity::High {
                finding = finding.with_remediation(
                    "Inspect the cron entry for malicious commands. Remove if not legitimate.",
                );
            } else if severity == Severity::Low {
                finding = finding.with_remediation(
                    "Verify this custom cron job is expected and its commands are safe.",
                );
            }

            findings.push(finding);
        }
    }
}

/// Assess the risk of a cron entry's content.
/// Returns (dangerous, mild) where dangerous patterns are always flagged
/// and mild patterns are only flagged for non-standard entries.
fn assess_cron_risk(content: &str) -> (Vec<String>, Vec<String>) {
    // Dangerous: clear indicators of malicious activity
    let dangerous_patterns: &[(&str, &str)] = &[
        ("bash -i", "interactive bash — potential reverse shell"),
        ("/dev/tcp/", "bash network redirection — potential reverse shell"),
        ("nc -e", "netcat with exec — reverse shell"),
        ("ncat -e", "ncat with exec — reverse shell"),
        ("bash -c 'sh -i", "shell reverse connection"),
        ("chmod +s", "adding SUID bit"),
        ("/dev/shm/", "execution from shared memory"),
        ("base64 -d | sh", "decoded shell execution"),
        ("base64 -d | bash", "decoded shell execution"),
    ];

    // Mild: could be legitimate but worth noting in non-standard entries
    let mild_patterns: &[(&str, &str)] = &[
        ("curl ", "downloads from internet (curl)"),
        ("wget ", "downloads from internet (wget)"),
        ("base64 -d", "base64 decoding"),
        ("eval ", "dynamic code execution"),
        ("python -c", "inline Python execution"),
        ("python3 -c", "inline Python execution"),
        ("perl -e", "inline Perl execution"),
        ("ruby -e", "inline Ruby execution"),
        ("0.0.0.0", "binding to all interfaces"),
    ];

    let mut dangerous = Vec::new();
    let mut mild = Vec::new();

    for (pattern, reason) in dangerous_patterns {
        if content.contains(pattern) {
            dangerous.push(reason.to_string());
        }
    }
    for (pattern, reason) in mild_patterns {
        if content.contains(pattern) {
            mild.push(reason.to_string());
        }
    }

    (dangerous, mild)
}

/// Check for custom systemd units
fn check_systemd_units(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for dir in SYSTEMD_DIRS {
        let entries = match fs.read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only look at service and timer units
            if !name_str.ends_with(".service") && !name_str.ends_with(".timer") {
                continue;
            }

            let inner_path = format!("{}/{}", dir, name_str);

            // Check if it's a symlink (enabled) or a custom unit
            let path = entry.path();
            let is_symlink = path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);

            if is_symlink {
                continue;
            }

            // Read and analyze content
            let content = fs.read_to_string(&inner_path).ok();
            let suspicious = content.as_deref().map(assess_systemd_risk);

            let (severity, title, description) = if let Some(ref details) = suspicious {
                if !details.is_empty() {
                    (
                        Severity::High,
                        format!("Suspicious systemd unit: {}", name_str),
                        format!(
                            "Systemd unit '{}' contains suspicious patterns: {}",
                            name_str,
                            details.join(", ")
                        ),
                    )
                } else {
                    (
                        Severity::Info,
                        format!("Systemd unit: {}", name_str),
                        format!("Systemd unit '{}'. Content appears normal.", name_str),
                    )
                }
            } else {
                (
                    Severity::Info,
                    format!("Systemd unit: {}", name_str),
                    format!("Custom systemd unit '{}' found in container.", name_str),
                )
            };

            let mut finding = Finding::new(
                "container-persistence-systemd",
                title,
                description,
                severity,
                FindingSource::Persistence {
                    persistence_type: "systemd".to_string(),
                    location: inner_path.clone(),
                },
            )
            .with_resource(inner_path)
            .with_reference("https://attack.mitre.org/techniques/T1543/002/");

            if severity == Severity::High {
                finding = finding.with_remediation(
                    "Inspect the systemd unit for malicious ExecStart commands. Disable with: systemctl disable <unit>",
                );
            }

            findings.push(finding);
        }
    }
}

/// Assess risk of systemd unit content; returns list of suspicious pattern descriptions.
fn assess_systemd_risk(content: &str) -> Vec<String> {
    let suspicious: &[(&str, &str)] = &[
        ("curl ", "downloads from internet"),
        ("wget ", "downloads from internet"),
        ("bash -i", "interactive shell"),
        ("/dev/tcp/", "bash network redirection"),
        ("base64 -d", "base64 decoding"),
        ("nc -e", "netcat with exec"),
        ("ncat -e", "ncat with exec"),
        ("/tmp/", "executes from /tmp"),
        ("/dev/shm", "executes from shared memory"),
        ("chmod +s", "adds SUID bit"),
        ("LD_PRELOAD", "library preloading"),
    ];

    let mut reasons = Vec::new();
    for (pattern, reason) in suspicious {
        if content.contains(pattern) {
            reasons.push(reason.to_string());
        }
    }
    reasons
}

/// Check shell profile files for modifications
fn check_shell_profiles(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for profile in SHELL_PROFILES {
        // For directories (like /etc/profile.d), check entries
        if profile.ends_with(".d") {
            let entries = match fs.read_dir(profile) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let name_str = entry.file_name().to_string_lossy().to_string();
                let inner_path = format!("{}/{}", profile, name_str);

                if let Ok(content) = fs.read_to_string(&inner_path) {
                    if has_suspicious_shell_content(&content) {
                        findings.push(
                            Finding::new(
                                "container-persistence-shellprofile",
                                format!("Suspicious shell profile: {}", inner_path),
                                "Shell profile contains potentially suspicious commands.",
                                Severity::High,
                                FindingSource::Persistence {
                                    persistence_type: "shell_profile".to_string(),
                                    location: inner_path.clone(),
                                },
                            )
                            .with_resource(inner_path)
                            .with_reference("https://attack.mitre.org/techniques/T1546/004/"),
                        );
                    }
                }
            }
        } else if let Ok(content) = fs.read_to_string(profile) {
            if has_suspicious_shell_content(&content) {
                findings.push(
                    Finding::new(
                        "container-persistence-shellprofile",
                        format!("Suspicious shell profile: {}", profile),
                        "Shell profile contains potentially suspicious commands.",
                        Severity::High,
                        FindingSource::Persistence {
                            persistence_type: "shell_profile".to_string(),
                            location: profile.to_string(),
                        },
                    )
                    .with_resource(profile.to_string())
                    .with_reference("https://attack.mitre.org/techniques/T1546/004/"),
                );
            }
        }
    }
}

/// Check if shell content has suspicious patterns
fn has_suspicious_shell_content(content: &str) -> bool {
    let suspicious = [
        "curl ",
        "wget ",
        "/dev/tcp/",
        "base64 -d",
        "eval $(echo",
        "python -c",
        "bash -i >&",
        "nc -e",
        "ncat -e",
    ];

    suspicious.iter().any(|p| content.contains(p))
}

/// Check init scripts
fn check_init_scripts(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for path in INIT_DIRS {
        if *path == "/etc/rc.local" {
            if let Ok(content) = fs.read_to_string(path) {
                // rc.local with actual commands (not just exit 0) is noteworthy
                let has_commands = content
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#') && l.trim() != "exit 0")
                    .count()
                    > 0;

                if has_commands {
                    findings.push(
                        Finding::new(
                            "container-persistence-rclocal",
                            "rc.local with commands",
                            "The /etc/rc.local file contains commands that execute at boot.",
                            Severity::Medium,
                            FindingSource::Persistence {
                                persistence_type: "init_script".to_string(),
                                location: path.to_string(),
                            },
                        )
                        .with_resource(path.to_string())
                        .with_reference("https://attack.mitre.org/techniques/T1037/004/"),
                    );
                }
            }
        } else {
            // /etc/init.d — just list entries
            let entries = match fs.read_dir(path) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let name_str = entry.file_name().to_string_lossy().to_string();
                let inner_path = format!("{}/{}", path, name_str);

                findings.push(
                    Finding::new(
                        "container-persistence-initd",
                        format!("Init script: {}", name_str),
                        format!("Init script '{}' found in container.", name_str),
                        Severity::Info,
                        FindingSource::Persistence {
                            persistence_type: "init_script".to_string(),
                            location: inner_path.clone(),
                        },
                    )
                    .with_resource(inner_path),
                );
            }
        }
    }
}

/// Check for SSH authorized_keys files
fn check_ssh_authorized_keys(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    // Check /root/.ssh/authorized_keys
    if fs.exists("/root/.ssh/authorized_keys") {
        if let Ok(content) = fs.read_to_string("/root/.ssh/authorized_keys") {
            let key_count = content.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count();
            if key_count > 0 {
                findings.push(
                    Finding::new(
                        "container-persistence-sshkeys",
                        format!("Root SSH authorized_keys: {} key(s)", key_count),
                        "SSH authorized_keys found for root in container. Verify these keys are expected.",
                        Severity::Medium,
                        FindingSource::Persistence {
                            persistence_type: "ssh_authorized_keys".to_string(),
                            location: "/root/.ssh/authorized_keys".to_string(),
                        },
                    )
                    .with_resource("/root/.ssh/authorized_keys")
                    .with_reference("https://attack.mitre.org/techniques/T1098/004/"),
                );
            }
        }
    }

    // Check home directories for other users
    if let Ok(entries) = fs.read_dir("/home") {
        for entry in entries.flatten() {
            let user = entry.file_name().to_string_lossy().to_string();
            let auth_keys = format!("/home/{}/.ssh/authorized_keys", user);
            if fs.exists(&auth_keys) {
                if let Ok(content) = fs.read_to_string(&auth_keys) {
                    let key_count = content.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count();
                    if key_count > 0 {
                        findings.push(
                            Finding::new(
                                "container-persistence-sshkeys",
                                format!("SSH authorized_keys for {}: {} key(s)", user, key_count),
                                format!("SSH authorized_keys found for user '{}' in container.", user),
                                Severity::Low,
                                FindingSource::Persistence {
                                    persistence_type: "ssh_authorized_keys".to_string(),
                                    location: auth_keys.clone(),
                                },
                            )
                            .with_resource(auth_keys),
                        );
                    }
                }
            }
        }
    }
}

/// Check for at jobs
fn check_at_jobs(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let at_dir = "/var/spool/at";
    if let Ok(entries) = fs.read_dir(at_dir) {
        for entry in entries.flatten() {
            let name_str = entry.file_name().to_string_lossy().to_string();
            if name_str.starts_with('.') {
                continue;
            }
            let inner_path = format!("{}/{}", at_dir, name_str);

            findings.push(
                Finding::new(
                    "container-persistence-at",
                    format!("At job found: {}", name_str),
                    "Scheduled at job found in container.",
                    Severity::Low,
                    FindingSource::Persistence {
                        persistence_type: "at_job".to_string(),
                        location: inner_path.clone(),
                    },
                )
                .with_resource(inner_path)
                .with_reference("https://attack.mitre.org/techniques/T1053/001/"),
            );
        }
    }
}
