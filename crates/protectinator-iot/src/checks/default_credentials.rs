//! Default credential detection for Raspberry Pi and IoT devices
//!
//! Checks for the default `pi` user, weak password hashes, empty passwords,
//! NOPASSWD sudo entries, and other common IoT default accounts.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use tracing::debug;

/// Common IoT default usernames beyond the Raspberry Pi `pi` user
const IOT_DEFAULT_USERS: &[&str] = &["admin", "user", "ubuntu"];

/// Default credential detection for Pi devices
pub struct DefaultCredentialsCheck;

impl IotCheck for DefaultCredentialsCheck {
    fn id(&self) -> &str {
        "iot-default-credentials"
    }

    fn name(&self) -> &str {
        "Default Credentials Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_passwd(fs, &mut findings);
        check_shadow(fs, &mut findings);
        check_sudoers(fs, &mut findings);

        findings
    }
}

fn source() -> FindingSource {
    FindingSource::Hardening {
        check_id: "default-credentials".to_string(),
        category: "authentication".to_string(),
    }
}

/// Check /etc/passwd for default and common IoT users
fn check_passwd(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let passwd = match fs.read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => {
            debug!("Cannot read /etc/passwd, skipping default credential check");
            return;
        }
    };

    // Check for the default pi user
    let has_pi = passwd.lines().any(|line| {
        line.split(':').next().map(|u| u == "pi").unwrap_or(false)
    });

    if has_pi {
        findings.push(
            Finding::new(
                "iot-default-credentials",
                "Default 'pi' user exists",
                "The default Raspberry Pi user 'pi' is present on this device. \
                 This is a well-known target for automated attacks.",
                Severity::Medium,
                source(),
            )
            .with_resource("/etc/passwd")
            .with_remediation("Remove or rename the default pi user: sudo deluser pi")
            .with_reference("https://www.raspberrypi.com/news/a-]security-update-for-raspbian/"),
        );
    }

    // Check for other common IoT default users
    for default_user in IOT_DEFAULT_USERS {
        let exists = passwd.lines().any(|line| {
            line.split(':').next().map(|u| u == *default_user).unwrap_or(false)
        });

        if exists {
            findings.push(
                Finding::new(
                    "iot-default-credentials",
                    format!("Common IoT default user '{}' exists", default_user),
                    format!(
                        "The user '{}' is a commonly used default account on IoT devices. \
                         Ensure it has a strong, unique password or remove it if unused.",
                        default_user
                    ),
                    Severity::Low,
                    source(),
                )
                .with_resource("/etc/passwd")
                .with_remediation(format!(
                    "Set a strong password or remove the user: sudo deluser {}",
                    default_user
                )),
            );
        }
    }

    // Check for root user with a non-locked password (handled in shadow check below)
}

/// Check /etc/shadow for weak hashes, empty passwords, and root password status
fn check_shadow(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let shadow = match fs.read_to_string("/etc/shadow") {
        Ok(c) => c,
        Err(e) => {
            debug!("Cannot read /etc/shadow (may require root): {}", e);
            return;
        }
    };

    for line in shadow.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 2 {
            continue;
        }

        let user = fields[0];
        let hash = fields[1];

        // Check for any user with empty password hash (not locked)
        // Empty string means no password required to log in
        // "!" or "*" means locked account, "!!" means password not yet set (also locked)
        if hash.is_empty() {
            findings.push(
                Finding::new(
                    "iot-default-credentials",
                    format!("User '{}' has empty password", user),
                    format!(
                        "User '{}' has an empty password hash in /etc/shadow, allowing \
                         login without any password. This is a critical security risk.",
                        user
                    ),
                    Severity::Critical,
                    source(),
                )
                .with_resource("/etc/shadow")
                .with_remediation(format!(
                    "Set a password or lock the account: passwd {} or passwd -l {}",
                    user, user
                ))
                .with_metadata("user", serde_json::Value::String(user.to_string())),
            );
            continue;
        }

        // Locked accounts are fine
        if hash == "!" || hash == "*" || hash == "!!" {
            // For root specifically, having a non-locked password is fine but check hash type
            continue;
        }

        // Check for root with an actual password (non-locked)
        if user == "root" && !hash.starts_with('!') && !hash.starts_with('*') && hash.contains('$')
        {
            findings.push(
                Finding::new(
                    "iot-default-credentials",
                    "Root user has a password set",
                    "The root account has a direct password. On IoT devices, consider \
                     disabling root password login and using sudo instead.",
                    Severity::Low,
                    source(),
                )
                .with_resource("/etc/shadow")
                .with_remediation("Lock root password and use sudo: sudo passwd -l root"),
            );
        }

        // Check hash strength for pi user specifically
        if user == "pi" {
            check_hash_strength(user, hash, findings);
        }

        // Check hash strength for all users with actual hashes
        if hash.starts_with("$1$") {
            findings.push(
                Finding::new(
                    "iot-default-credentials",
                    format!("Weak MD5 password hash for user '{}'", user),
                    format!(
                        "User '{}' has an MD5-based password hash ($1$). MD5 is \
                         cryptographically weak and susceptible to brute-force attacks.",
                        user
                    ),
                    Severity::High,
                    source(),
                )
                .with_resource("/etc/shadow")
                .with_remediation(format!(
                    "Change the password to upgrade the hash: passwd {}",
                    user
                ))
                .with_metadata("hash_type", serde_json::Value::String("md5".to_string()))
                .with_metadata("user", serde_json::Value::String(user.to_string())),
            );
        } else if hash.starts_with("$5$") {
            findings.push(
                Finding::new(
                    "iot-default-credentials",
                    format!("SHA-256 password hash for user '{}'", user),
                    format!(
                        "User '{}' has a SHA-256 password hash ($5$). Consider upgrading \
                         to SHA-512 ($6$) for better security.",
                        user
                    ),
                    Severity::Medium,
                    source(),
                )
                .with_resource("/etc/shadow")
                .with_remediation(format!(
                    "Change the password to upgrade to SHA-512: passwd {}",
                    user
                ))
                .with_metadata("hash_type", serde_json::Value::String("sha256".to_string()))
                .with_metadata("user", serde_json::Value::String(user.to_string())),
            );
        }
    }
}

/// Check hash strength specifically for the pi user
fn check_hash_strength(user: &str, hash: &str, findings: &mut Vec<Finding>) {
    // We cannot check for the exact default "raspberry" password because
    // the hash is salted, but we note it as informational
    if hash.contains('$') && user == "pi" {
        findings.push(
            Finding::new(
                "iot-default-credentials",
                "Pi user has a password set — verify it is not the default",
                "The default Raspberry Pi password is 'raspberry'. While we cannot \
                 verify the exact password from the hash (it is salted), ensure the \
                 password has been changed from the default.",
                Severity::Info,
                source(),
            )
            .with_resource("/etc/shadow")
            .with_remediation("Change the pi password: passwd pi"),
        );
    }
}

/// Check /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries
fn check_sudoers(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    // Collect all sudoers content: main file plus drop-in directory
    let mut sudoers_files: Vec<(String, String)> = Vec::new();

    if let Ok(content) = fs.read_to_string("/etc/sudoers") {
        sudoers_files.push(("/etc/sudoers".to_string(), content));
    }

    if let Ok(entries) = fs.read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip hidden files and README
            if name_str.starts_with('.') || name_str == "README" {
                continue;
            }

            let path = format!("/etc/sudoers.d/{}", name_str);
            if let Ok(content) = fs.read_to_string(&path) {
                sudoers_files.push((path, content));
            }
        }
    }

    for (path, content) in &sudoers_files {
        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if !trimmed.contains("NOPASSWD") {
                continue;
            }

            // Check for the most dangerous patterns first
            let upper = trimmed.to_uppercase();

            if upper.contains("ALL") && upper.contains("ALL=(ALL)") && upper.contains("NOPASSWD")
            {
                // Check for unrestricted access for everyone
                if trimmed.starts_with("ALL ") {
                    findings.push(
                        Finding::new(
                            "iot-default-credentials",
                            "Unrestricted NOPASSWD sudo for ALL users",
                            format!(
                                "Sudoers entry '{}' in '{}' grants unrestricted passwordless \
                                 sudo to all users. This is critically dangerous.",
                                trimmed, path
                            ),
                            Severity::Critical,
                            source(),
                        )
                        .with_resource(path.clone())
                        .with_remediation("Remove this sudoers entry immediately")
                        .with_reference("https://attack.mitre.org/techniques/T1548/003/"),
                    );
                    continue;
                }

                // Check for default pi user with full NOPASSWD
                if trimmed.starts_with("pi ") {
                    findings.push(
                        Finding::new(
                            "iot-default-credentials",
                            "Default pi user has unrestricted NOPASSWD sudo",
                            format!(
                                "Sudoers entry '{}' in '{}' gives the default pi user \
                                 full passwordless sudo access. This is a common IoT \
                                 attack vector.",
                                trimmed, path
                            ),
                            Severity::High,
                            source(),
                        )
                        .with_resource(path.clone())
                        .with_remediation(
                            "Remove NOPASSWD for the pi user or remove the pi user entirely",
                        )
                        .with_reference("https://attack.mitre.org/techniques/T1548/003/"),
                    );
                    continue;
                }
            }

            // Generic NOPASSWD entry
            findings.push(
                Finding::new(
                    "iot-default-credentials",
                    "NOPASSWD sudo configured",
                    format!(
                        "Sudoers entry '{}' in '{}' allows passwordless sudo. \
                         Passwordless sudo weakens authentication security.",
                        trimmed, path
                    ),
                    Severity::Medium,
                    source(),
                )
                .with_resource(path.clone())
                .with_remediation(
                    "Remove NOPASSWD from sudoers entries unless absolutely necessary",
                )
                .with_reference("https://attack.mitre.org/techniques/T1548/003/"),
            );
        }
    }
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
    fn test_detects_default_pi_user() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();

        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             pi:x:1000:1000:,,,:/home/pi:/bin/bash\n\
             nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        let pi_finding = findings
            .iter()
            .find(|f| f.title.contains("Default 'pi' user"));
        assert!(pi_finding.is_some(), "Should detect default pi user");
        assert_eq!(pi_finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_detects_empty_password() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();

        fs::write(etc.join("passwd"), "backdoor:x:1001:1001::/home/backdoor:/bin/bash\n").unwrap();

        // Empty password hash field (between first and second colon pair)
        fs::write(
            etc.join("shadow"),
            "root:!:19000:0:99999:7:::\n\
             backdoor::19000:0:99999:7:::\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        let empty_pw = findings
            .iter()
            .find(|f| f.title.contains("empty password"));
        assert!(empty_pw.is_some(), "Should detect empty password");
        assert_eq!(empty_pw.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_detects_weak_md5_hash() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();

        fs::write(etc.join("passwd"), "weakuser:x:1001:1001::/home/weakuser:/bin/bash\n").unwrap();

        fs::write(
            etc.join("shadow"),
            "weakuser:$1$salt$hash123456789abcdef:19000:0:99999:7:::\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        let md5_finding = findings
            .iter()
            .find(|f| f.title.contains("Weak MD5 password hash"));
        assert!(md5_finding.is_some(), "Should detect MD5 hash");
        assert_eq!(md5_finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detects_nopasswd_sudo() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(etc.join("sudoers.d")).unwrap();

        fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();

        fs::write(
            etc.join("sudoers"),
            "# /etc/sudoers\n\
             root ALL=(ALL:ALL) ALL\n\
             %sudo ALL=(ALL:ALL) ALL\n",
        )
        .unwrap();

        fs::write(
            etc.join("sudoers.d/010_pi-nopasswd"),
            "pi ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        let nopasswd_finding = findings
            .iter()
            .find(|f| f.title.contains("pi user has unrestricted NOPASSWD"));
        assert!(
            nopasswd_finding.is_some(),
            "Should detect pi NOPASSWD sudo"
        );
        assert_eq!(nopasswd_finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detects_critical_all_nopasswd() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();

        fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();

        fs::write(
            etc.join("sudoers"),
            "ALL ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        let critical_finding = findings
            .iter()
            .find(|f| f.title.contains("ALL users"));
        assert!(
            critical_finding.is_some(),
            "Should detect ALL users NOPASSWD"
        );
        assert_eq!(critical_finding.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_detects_common_iot_users() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();

        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             admin:x:1001:1001::/home/admin:/bin/bash\n\
             ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        let admin_finding = findings
            .iter()
            .find(|f| f.title.contains("'admin'"));
        assert!(admin_finding.is_some(), "Should detect admin user");

        let ubuntu_finding = findings
            .iter()
            .find(|f| f.title.contains("'ubuntu'"));
        assert!(ubuntu_finding.is_some(), "Should detect ubuntu user");
    }

    #[test]
    fn test_locked_accounts_no_findings() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let etc = root.join("etc");
        fs::create_dir_all(&etc).unwrap();

        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        )
        .unwrap();

        fs::write(
            etc.join("shadow"),
            "root:!:19000:0:99999:7:::\n\
             daemon:*:19000:0:99999:7:::\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = DefaultCredentialsCheck;
        let findings = check.run(&cfs);

        // Locked accounts should not produce empty password or hash findings
        let empty_pw_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("empty password"))
            .collect();
        assert!(
            empty_pw_findings.is_empty(),
            "Locked accounts should not trigger findings"
        );
    }
}
