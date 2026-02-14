//! Container-specific hardening checks
//!
//! Checks SSH configuration, user accounts, file permissions,
//! and other hardening issues inside the container.

use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};

/// Check container hardening
pub struct HardeningCheck;

impl ContainerCheck for HardeningCheck {
    fn id(&self) -> &str {
        "container-hardening"
    }

    fn name(&self) -> &str {
        "Container Hardening Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_user_accounts(fs, &mut findings);
        check_ssh_config(fs, &mut findings);
        check_sensitive_dir_permissions(fs, &mut findings);

        findings
    }
}

/// Check user accounts for security issues
fn check_user_accounts(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    // Parse /etc/passwd
    let passwd = match fs.read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return,
    };

    // Check for accounts with UID 0 besides root
    let uid0_accounts: Vec<&str> = passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 && fields[2] == "0" && fields[0] != "root" {
                Some(fields[0])
            } else {
                None
            }
        })
        .collect();

    if !uid0_accounts.is_empty() {
        findings.push(
            Finding::new(
                "container-hardening-uid0",
                format!("Non-root accounts with UID 0: {}", uid0_accounts.join(", ")),
                "Accounts with UID 0 have full root privileges. Only the root account should have UID 0.",
                Severity::Critical,
                FindingSource::Hardening {
                    check_id: "container-hardening-uid0".to_string(),
                    category: "accounts".to_string(),
                },
            )
            .with_remediation("Remove or change the UID of non-root accounts with UID 0")
            .with_reference("https://www.cisecurity.org/benchmark/distribution_independent_linux"),
        );
    }

    // Check for accounts with login shells that might not need them
    let service_accounts_with_shells: Vec<String> = passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7 {
                let user = fields[0];
                let uid: u32 = fields[2].parse().unwrap_or(0);
                let shell = fields[6];

                // System accounts (UID < 1000, except root) with login shells
                if uid > 0
                    && uid < 1000
                    && !shell.contains("nologin")
                    && !shell.contains("false")
                    && !shell.is_empty()
                {
                    Some(format!("{} (shell: {})", user, shell))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    if !service_accounts_with_shells.is_empty() {
        findings.push(
            Finding::new(
                "container-hardening-service-shells",
                format!(
                    "{} service account(s) with login shells",
                    service_accounts_with_shells.len()
                ),
                format!(
                    "Service accounts should use /usr/sbin/nologin or /bin/false: {}",
                    service_accounts_with_shells.join(", ")
                ),
                Severity::Low,
                FindingSource::Hardening {
                    check_id: "container-hardening-service-shells".to_string(),
                    category: "accounts".to_string(),
                },
            )
            .with_remediation("Set service account shells to /usr/sbin/nologin"),
        );
    }

    // Check /etc/shadow for empty passwords
    if let Ok(shadow) = fs.read_to_string("/etc/shadow") {
        let empty_passwords: Vec<&str> = shadow
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 2 {
                    let user = fields[0];
                    let hash = fields[1];
                    // Empty password field or "*" or "!" means locked, but "" means no password
                    if hash.is_empty() {
                        Some(user)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        if !empty_passwords.is_empty() {
            findings.push(
                Finding::new(
                    "container-hardening-empty-password",
                    format!("Account(s) with empty passwords: {}", empty_passwords.join(", ")),
                    "Accounts with empty passwords can be accessed without authentication.",
                    Severity::Critical,
                    FindingSource::Hardening {
                        check_id: "container-hardening-empty-password".to_string(),
                        category: "accounts".to_string(),
                    },
                )
                .with_remediation("Set a password or lock the account using 'passwd -l <user>'"),
            );
        }
    }
}

/// Check SSH server configuration inside the container
fn check_ssh_config(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let sshd_config = match fs.read_to_string("/etc/ssh/sshd_config") {
        Ok(c) => c,
        Err(_) => return, // No SSH server config
    };

    // Check PermitRootLogin
    let permits_root = sshd_config
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| {
            let l = l.trim().to_lowercase();
            l.starts_with("permitrootlogin") && (l.contains("yes") || l.contains("without-password") || l.contains("prohibit-password"))
        });

    // If PermitRootLogin is not explicitly set, the default depends on the distro
    // but it's worth flagging
    let root_login_not_disabled = !sshd_config
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| {
            let l = l.trim().to_lowercase();
            l.starts_with("permitrootlogin") && l.contains("no")
        });

    if permits_root || root_login_not_disabled {
        findings.push(
            Finding::new(
                "container-hardening-ssh-root",
                "SSH permits root login",
                "The SSH server configuration does not explicitly disable root login. \
                 Root SSH access should be disabled in favor of sudo.",
                Severity::Medium,
                FindingSource::Hardening {
                    check_id: "container-hardening-ssh-root".to_string(),
                    category: "ssh".to_string(),
                },
            )
            .with_resource("/etc/ssh/sshd_config")
            .with_remediation("Set 'PermitRootLogin no' in /etc/ssh/sshd_config"),
        );
    }

    // Check PasswordAuthentication
    let allows_password = !sshd_config
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| {
            let l = l.trim().to_lowercase();
            l.starts_with("passwordauthentication") && l.contains("no")
        });

    if allows_password {
        findings.push(
            Finding::new(
                "container-hardening-ssh-password",
                "SSH allows password authentication",
                "Password authentication is not disabled. Key-based authentication is more secure.",
                Severity::Low,
                FindingSource::Hardening {
                    check_id: "container-hardening-ssh-password".to_string(),
                    category: "ssh".to_string(),
                },
            )
            .with_resource("/etc/ssh/sshd_config")
            .with_remediation("Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"),
        );
    }
}

/// Check permissions on sensitive directories
fn check_sensitive_dir_permissions(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let dirs_to_check = [
        ("/tmp", 0o1777, "sticky bit"),
        ("/var/tmp", 0o1777, "sticky bit"),
    ];

    for (dir, _expected_mode, description) in &dirs_to_check {
        if let Ok(metadata) = fs.metadata(dir) {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o7777;

            // Check if world-writable without sticky bit
            if mode & 0o0002 != 0 && mode & 0o1000 == 0 {
                findings.push(
                    Finding::new(
                        format!("container-hardening-perms-{}", dir.replace('/', "-").trim_matches('-')),
                        format!("{} is world-writable without {}", dir, description),
                        format!(
                            "Directory {} has mode {:04o} — world-writable without the sticky bit. \
                             This allows any user to delete other users' files.",
                            dir, mode
                        ),
                        Severity::High,
                        FindingSource::Hardening {
                            check_id: format!("container-hardening-perms-{}", dir.replace('/', "")),
                            category: "filesystem".to_string(),
                        },
                    )
                    .with_resource(dir.to_string())
                    .with_remediation(format!("Run 'chmod {} {}' inside the container", format!("{:04o}", _expected_mode), dir)),
                );
            }
        }
    }
}
