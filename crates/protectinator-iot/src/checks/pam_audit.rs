//! PAM module audit
//!
//! Scans PAM configuration for backdoor modules, non-standard modules,
//! and unowned shared libraries in the PAM security directories.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use tracing::debug;

/// Standard PAM modules that are expected on a normal system
const STANDARD_PAM_MODULES: &[&str] = &[
    "pam_unix.so",
    "pam_deny.so",
    "pam_permit.so",
    "pam_env.so",
    "pam_mail.so",
    "pam_limits.so",
    "pam_loginuid.so",
    "pam_systemd.so",
    "pam_nologin.so",
    "pam_motd.so",
    "pam_lastlog.so",
    "pam_access.so",
    "pam_securetty.so",
    "pam_shells.so",
    "pam_keyinit.so",
    "pam_selinux.so",
    "pam_namespace.so",
    "pam_xauth.so",
    "pam_umask.so",
    "pam_cap.so",
    "pam_wheel.so",
    "pam_warn.so",
    "pam_tally2.so",
    "pam_faillock.so",
    "pam_pwquality.so",
    "pam_cracklib.so",
    "pam_succeed_if.so",
    "pam_rootok.so",
    "pam_timestamp.so",
    "pam_group.so",
    "pam_mkhomedir.so",
    "pam_gnome_keyring.so",
    "pam_fprintd.so",
    "pam_sss.so",
    "pam_ldap.so",
    "pam_krb5.so",
];

/// Suspicious temp/writable paths for module loading
const SUSPICIOUS_MODULE_PATHS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

/// PAM security library directories on ARM systems
const PAM_LIB_DIRS: &[&str] = &[
    "/lib/aarch64-linux-gnu/security",
    "/lib/arm-linux-gnueabihf/security",
    "/usr/lib/aarch64-linux-gnu/security",
    "/usr/lib/arm-linux-gnueabihf/security",
    // Also check x86_64 for non-Pi IoT devices
    "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security",
];

fn make_source() -> FindingSource {
    FindingSource::Hardening {
        check_id: "pam-audit".to_string(),
        category: "authentication".to_string(),
    }
}

/// PAM module audit check
pub struct PamAuditCheck;

impl IotCheck for PamAuditCheck {
    fn id(&self) -> &str {
        "iot-pam-audit"
    }

    fn name(&self) -> &str {
        "PAM Module Audit"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_pam_configs(fs, &mut findings);
        check_unowned_pam_libraries(fs, &mut findings);

        findings
    }
}

/// Parse PAM config files and check for suspicious modules
fn check_pam_configs(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let pam_dir = "/etc/pam.d";
    let entries = match fs.read_dir(pam_dir) {
        Ok(e) => e,
        Err(_) => {
            debug!("Cannot read /etc/pam.d, skipping PAM config audit");
            return;
        }
    };

    let standard_modules: HashSet<&str> = STANDARD_PAM_MODULES.iter().copied().collect();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let file_path = format!("{}/{}", pam_dir, name_str);

        let content = match fs.read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle @include directives (Debian-style)
            if line.starts_with("@include") {
                continue;
            }

            // Parse PAM line: <type> <control> <module> [args...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let pam_type = parts[0];
            let _control = parts[1];
            let module_field = parts[2];
            let args: Vec<&str> = if parts.len() > 3 {
                parts[3..].to_vec()
            } else {
                Vec::new()
            };

            // Extract module name (may be a full path or just module name)
            let module_name = module_field
                .rsplit('/')
                .next()
                .unwrap_or(module_field);

            // Check: pam_exec.so with expose_authtok
            if module_name == "pam_exec.so" {
                let has_expose_authtok = args.iter().any(|a| *a == "expose_authtok");
                if has_expose_authtok {
                    findings.push(
                        Finding::new(
                            "iot-pam-audit",
                            format!(
                                "PAM exec with password exposure in {}:{}",
                                name_str,
                                line_num + 1
                            ),
                            format!(
                                "pam_exec.so with expose_authtok in '{}' line {}. This passes \
                                 the user's password to the executed script via stdin, which \
                                 is a common backdoor technique for credential harvesting.",
                                file_path,
                                line_num + 1
                            ),
                            Severity::Critical,
                            make_source(),
                        )
                        .with_resource(file_path.clone())
                        .with_remediation(
                            "Remove expose_authtok from the pam_exec.so line, or remove the \
                             entire line if the script is not legitimate.",
                        )
                        .with_reference("https://attack.mitre.org/techniques/T1556/"),
                    );
                } else {
                    findings.push(
                        Finding::new(
                            "iot-pam-audit",
                            format!(
                                "PAM exec module in {} line {}",
                                name_str,
                                line_num + 1
                            ),
                            format!(
                                "pam_exec.so found in '{}' line {}. This module executes \
                                 arbitrary scripts during authentication, which can be used \
                                 for persistence or credential theft.",
                                file_path,
                                line_num + 1
                            ),
                            Severity::High,
                            make_source(),
                        )
                        .with_resource(file_path.clone())
                        .with_remediation(
                            "Verify the executed script is legitimate and necessary. \
                             Remove the pam_exec.so line if not required.",
                        ),
                    );
                }
                continue;
            }

            // Check: pam_permit.so in auth stack
            if module_name == "pam_permit.so" && pam_type == "auth" {
                findings.push(
                    Finding::new(
                        "iot-pam-audit",
                        format!(
                            "Unconditional auth permit in {} line {}",
                            name_str,
                            line_num + 1
                        ),
                        format!(
                            "pam_permit.so in the auth stack of '{}' line {}. This module \
                             unconditionally permits authentication, effectively disabling \
                             password checks for this service.",
                            file_path,
                            line_num + 1
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(file_path.clone())
                    .with_remediation(
                        "Replace pam_permit.so with pam_unix.so or pam_deny.so in the \
                         auth stack unless this is intentional (e.g., for a local-only service).",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1556/"),
                );
                continue;
            }

            // Check: modules loaded from suspicious paths
            if SUSPICIOUS_MODULE_PATHS
                .iter()
                .any(|p| module_field.starts_with(p))
            {
                findings.push(
                    Finding::new(
                        "iot-pam-audit",
                        format!(
                            "PAM module from suspicious path in {} line {}",
                            name_str,
                            line_num + 1
                        ),
                        format!(
                            "PAM module loaded from suspicious path '{}' in '{}' line {}. \
                             Loading PAM modules from writable directories like /tmp or /dev/shm \
                             is a strong indicator of a PAM backdoor.",
                            module_field,
                            file_path,
                            line_num + 1
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(file_path.clone())
                    .with_remediation(
                        "Remove this PAM module entry immediately and investigate \
                         the referenced shared library file.",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1556/"),
                );
                continue;
            }

            // Check: pam_python.so or pam_script.so
            if module_name == "pam_python.so" || module_name == "pam_script.so" {
                findings.push(
                    Finding::new(
                        "iot-pam-audit",
                        format!(
                            "Scripting PAM module in {} line {}",
                            name_str,
                            line_num + 1
                        ),
                        format!(
                            "'{}' found in '{}' line {}. Scripting PAM modules allow arbitrary \
                             code execution during authentication and are commonly used for \
                             PAM backdoors.",
                            module_name,
                            file_path,
                            line_num + 1
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(file_path.clone())
                    .with_remediation(
                        "Remove this PAM module unless it is specifically required. \
                         Verify the associated scripts are legitimate.",
                    ),
                );
                continue;
            }

            // Check: unknown modules not in whitelist
            if !standard_modules.contains(module_name) {
                findings.push(
                    Finding::new(
                        "iot-pam-audit",
                        format!(
                            "Unknown PAM module '{}' in {} line {}",
                            module_name,
                            name_str,
                            line_num + 1
                        ),
                        format!(
                            "Non-standard PAM module '{}' found in '{}' line {}. This module \
                             is not in the standard PAM module whitelist and should be verified.",
                            module_name,
                            file_path,
                            line_num + 1
                        ),
                        Severity::Medium,
                        make_source(),
                    )
                    .with_resource(file_path.clone())
                    .with_remediation(format!(
                        "Verify that '{}' is a legitimate PAM module installed by a known package. \
                         Check with: dpkg -S {}",
                        module_name, module_name
                    )),
                );
            }
        }
    }
}

/// Check for .so files in PAM library directories not owned by dpkg
fn check_unowned_pam_libraries(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    // Build set of all files owned by dpkg
    let dpkg_owned = collect_dpkg_owned_files(fs);

    for pam_dir in PAM_LIB_DIRS {
        let entries = match fs.read_dir(pam_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();

            if !name_str.ends_with(".so") {
                continue;
            }

            let lib_path = format!("{}/{}", pam_dir, name_str);

            if !dpkg_owned.contains(&lib_path) {
                findings.push(
                    Finding::new(
                        "iot-pam-audit",
                        format!("Unowned PAM library: {}", lib_path),
                        format!(
                            "PAM shared library '{}' is not owned by any dpkg package. \
                             Unowned PAM modules may have been manually installed as part \
                             of a PAM backdoor or rootkit.",
                            lib_path
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(lib_path)
                    .with_remediation(
                        "Investigate this shared library. Check its creation time, contents, \
                         and whether it was intentionally installed. Remove if suspicious.",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1556/"),
                );
            }
        }
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
    fn test_detects_pam_exec_with_expose_authtok() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let pam_dir = root.join("etc/pam.d");
        fs::create_dir_all(&pam_dir).unwrap();

        fs::write(
            pam_dir.join("sshd"),
            "auth required pam_exec.so expose_authtok /tmp/steal_creds.sh\n\
             auth required pam_unix.so\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = PamAuditCheck;
        let findings = check.run(&cfs);

        let exec_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("password exposure"))
            .collect();
        assert_eq!(exec_findings.len(), 1);
        assert_eq!(exec_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detects_pam_permit_in_auth() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let pam_dir = root.join("etc/pam.d");
        fs::create_dir_all(&pam_dir).unwrap();

        fs::write(
            pam_dir.join("sudo"),
            "auth sufficient pam_permit.so\n\
             auth required pam_unix.so\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = PamAuditCheck;
        let findings = check.run(&cfs);

        let permit_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Unconditional auth permit"))
            .collect();
        assert_eq!(permit_findings.len(), 1);
        assert_eq!(permit_findings[0].severity, Severity::High);
    }

    #[test]
    fn test_detects_module_from_tmp() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let pam_dir = root.join("etc/pam.d");
        fs::create_dir_all(&pam_dir).unwrap();

        fs::write(
            pam_dir.join("login"),
            "auth required /tmp/evil_pam.so\n\
             auth required pam_unix.so\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = PamAuditCheck;
        let findings = check.run(&cfs);

        let tmp_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("suspicious path"))
            .collect();
        assert_eq!(tmp_findings.len(), 1);
        assert_eq!(tmp_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_clean_pam_config_no_critical_findings() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let pam_dir = root.join("etc/pam.d");
        fs::create_dir_all(&pam_dir).unwrap();

        fs::write(
            pam_dir.join("common-auth"),
            "# Standard Debian PAM config\n\
             auth    required    pam_unix.so nullok\n\
             auth    required    pam_deny.so\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = PamAuditCheck;
        let findings = check.run(&cfs);

        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .collect();
        assert!(
            critical.is_empty(),
            "Standard PAM config should not produce critical/high findings, got: {:?}",
            critical.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detects_unknown_module() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let pam_dir = root.join("etc/pam.d");
        fs::create_dir_all(&pam_dir).unwrap();

        fs::write(
            pam_dir.join("common-auth"),
            "auth required pam_custom_backdoor.so\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = PamAuditCheck;
        let findings = check.run(&cfs);

        let unknown_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Unknown PAM module"))
            .collect();
        assert_eq!(unknown_findings.len(), 1);
        assert_eq!(unknown_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_detects_unowned_pam_library() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create PAM lib dir with an unowned .so
        let pam_lib = root.join("lib/aarch64-linux-gnu/security");
        fs::create_dir_all(&pam_lib).unwrap();
        fs::write(pam_lib.join("pam_evil.so"), b"fake shared library").unwrap();

        // Create empty dpkg info dir (no packages own this file)
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        // Need pam.d dir too (even if empty)
        let pam_dir = root.join("etc/pam.d");
        fs::create_dir_all(&pam_dir).unwrap();

        let cfs = setup_container(&tmp);
        let check = PamAuditCheck;
        let findings = check.run(&cfs);

        let unowned: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Unowned PAM library"))
            .collect();
        assert_eq!(unowned.len(), 1);
        assert_eq!(unowned[0].severity, Severity::High);
    }
}
