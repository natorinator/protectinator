//! Boot partition integrity check
//!
//! Analyzes Raspberry Pi boot partitions for tampered configuration,
//! suspicious kernel parameters, and unexpected files that could indicate
//! boot-level persistence or rootkit activity.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use tracing::debug;

/// Boot directories to check (Bookworm+ uses /boot/firmware/, older uses /boot/)
const BOOT_DIRS: &[&str] = &["/boot/firmware", "/boot"];

/// Standard init binaries (cmdline.txt init= parameter)
const STANDARD_INIT_BINARIES: &[&str] = &[
    "/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
    "/init",
];

fn make_source() -> FindingSource {
    FindingSource::Hardening {
        check_id: "boot-integrity".to_string(),
        category: "boot_partition".to_string(),
    }
}

/// Boot partition integrity check for Raspberry Pi
pub struct BootIntegrityCheck;

impl IotCheck for BootIntegrityCheck {
    fn id(&self) -> &str {
        "iot-boot-integrity"
    }

    fn name(&self) -> &str {
        "Boot Partition Integrity Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find the active boot directory
        let boot_dir = BOOT_DIRS.iter().find(|d| fs.exists(d));
        let Some(&boot_dir) = boot_dir else {
            debug!("No boot directory found, skipping boot integrity check");
            return findings;
        };

        debug!("Checking boot directory: {}", boot_dir);

        check_config_txt(fs, boot_dir, &mut findings);
        check_cmdline_txt(fs, boot_dir, &mut findings);
        check_unexpected_files(fs, boot_dir, &mut findings);

        findings
    }
}

/// Parse and check config.txt for suspicious entries
fn check_config_txt(fs: &ContainerFs, boot_dir: &str, findings: &mut Vec<Finding>) {
    let config_path = format!("{}/config.txt", boot_dir);
    let content = match fs.read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Check kernel= directive
        if let Some(kernel_value) = line.strip_prefix("kernel=") {
            let kernel_value = kernel_value.trim();
            // Standard kernels: kernel.img, kernel7.img, kernel7l.img, kernel8.img, kernel_2712.img
            let is_standard = kernel_value.starts_with("kernel")
                && (kernel_value.ends_with(".img") || kernel_value.ends_with(".img.bak"));

            if !is_standard {
                findings.push(
                    Finding::new(
                        "iot-boot-integrity",
                        format!("Non-standard kernel in config.txt: {}", kernel_value),
                        format!(
                            "config.txt specifies kernel='{}' which does not match standard \
                             Raspberry Pi kernel naming (kernel*.img). This could indicate a \
                             rootkit or backdoored kernel.",
                            kernel_value
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(config_path.clone())
                    .with_remediation(
                        "Verify the kernel binary is legitimate. Compare against a known-good \
                         Raspberry Pi OS image. Restore with: sudo apt install --reinstall raspberrypi-kernel",
                    )
                    .with_reference("https://www.raspberrypi.com/documentation/computers/config_txt.html"),
                );
            }
        }

        // Check initramfs directive
        if line.starts_with("initramfs ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let initramfs_file = parts[1];
                // Standard initramfs names
                let is_standard = initramfs_file.starts_with("initrd")
                    || initramfs_file.starts_with("initramfs");

                if !is_standard {
                    findings.push(
                        Finding::new(
                            "iot-boot-integrity",
                            format!("Unexpected initramfs in config.txt: {}", initramfs_file),
                            format!(
                                "config.txt specifies an initramfs file '{}' that does not match \
                                 standard naming conventions. A malicious initramfs could execute \
                                 code before the real init system starts.",
                                initramfs_file
                            ),
                            Severity::High,
                            make_source(),
                        )
                        .with_resource(config_path.clone())
                        .with_remediation(
                            "Verify the initramfs image is legitimate. Remove the initramfs line \
                             from config.txt if it was not intentionally added.",
                        ),
                    );
                }
            }
        }

        // Note dtoverlay entries (informational, delegated to device_tree check)
        if let Some(overlay_value) = line.strip_prefix("dtoverlay=") {
            let overlay_name = overlay_value.split(',').next().unwrap_or(overlay_value).trim();
            debug!("Noted dtoverlay: {} (delegated to device_tree check)", overlay_name);
        }
    }
}

/// Parse and check cmdline.txt for suspicious parameters
fn check_cmdline_txt(fs: &ContainerFs, boot_dir: &str, findings: &mut Vec<Finding>) {
    let cmdline_path = format!("{}/cmdline.txt", boot_dir);
    let content = match fs.read_to_string(&cmdline_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // cmdline.txt is a single line of space-separated parameters
    let params: Vec<&str> = content.trim().split_whitespace().collect();

    for param in &params {
        // Check init= parameter
        if let Some(init_value) = param.strip_prefix("init=") {
            if !STANDARD_INIT_BINARIES.contains(&init_value) {
                findings.push(
                    Finding::new(
                        "iot-boot-integrity",
                        format!("Non-standard init binary: {}", init_value),
                        format!(
                            "cmdline.txt specifies init='{}' which is not a standard init binary. \
                             Standard init binaries are: {}. A non-standard init could be a \
                             backdoor executing before the real init system.",
                            init_value,
                            STANDARD_INIT_BINARIES.join(", ")
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(cmdline_path.clone())
                    .with_remediation(
                        "Remove or correct the init= parameter in cmdline.txt. \
                         Standard value: init=/lib/systemd/systemd",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1542/"),
                );
            }
        }

        // Check for suspicious stall parameters
        if let Some(delay_value) = param.strip_prefix("rootdelay=") {
            if let Ok(delay) = delay_value.parse::<u32>() {
                if delay >= 60 {
                    findings.push(
                        Finding::new(
                            "iot-boot-integrity",
                            format!("Suspicious rootdelay={} in cmdline.txt", delay),
                            format!(
                                "cmdline.txt specifies rootdelay={} which causes a long boot \
                                 stall. Very high values (>60s) could be used to delay boot while \
                                 a malicious process runs, or to cause denial of service.",
                                delay
                            ),
                            Severity::Medium,
                            make_source(),
                        )
                        .with_resource(cmdline_path.clone())
                        .with_remediation(
                            "Remove or reduce the rootdelay parameter in cmdline.txt unless \
                             specifically required for your hardware setup.",
                        ),
                    );
                }
            }
        }

        // Check for suspicious rootwait parameters with extremely high timeouts
        if let Some(wait_value) = param.strip_prefix("rootwait=") {
            if let Ok(wait) = wait_value.parse::<u32>() {
                if wait >= 300 {
                    findings.push(
                        Finding::new(
                            "iot-boot-integrity",
                            format!("Suspicious rootwait={} in cmdline.txt", wait),
                            format!(
                                "cmdline.txt specifies rootwait={} which is unusually long. \
                                 This could be used to stall boot for malicious purposes.",
                                wait
                            ),
                            Severity::Medium,
                            make_source(),
                        )
                        .with_resource(cmdline_path.clone()),
                    );
                }
            }
        }
    }
}

/// Check for unexpected files in the boot directory
fn check_unexpected_files(fs: &ContainerFs, boot_dir: &str, findings: &mut Vec<Finding>) {
    let entries = match fs.read_dir(boot_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();

        // Check if it matches any expected pattern
        if is_expected_boot_file(&name_str) {
            continue;
        }

        let file_path = format!("{}/{}", boot_dir, name_str);

        // Check if it's an executable file (higher severity)
        let is_executable = name_str.ends_with(".sh")
            || name_str.ends_with(".py")
            || name_str.ends_with(".pl")
            || is_elf_file(fs, &file_path);

        let severity = if is_executable {
            Severity::High
        } else {
            Severity::Medium
        };

        let description = if is_executable {
            format!(
                "Executable file '{}' found in boot partition. Executable files in \
                 the boot directory are highly suspicious and could indicate boot-level \
                 persistence or a rootkit payload.",
                name_str
            )
        } else {
            format!(
                "Unexpected file '{}' found in boot partition. This file does not match \
                 standard Raspberry Pi boot files and should be investigated.",
                name_str
            )
        };

        findings.push(
            Finding::new(
                "iot-boot-integrity",
                format!("Unexpected boot file: {}", name_str),
                description,
                severity,
                make_source(),
            )
            .with_resource(file_path)
            .with_remediation(
                "Investigate this file and remove it if not intentionally placed. \
                 Compare against a known-good Raspberry Pi OS boot partition.",
            ),
        );
    }
}

/// Check if a filename matches expected boot file patterns
fn is_expected_boot_file(name: &str) -> bool {
    // Exact matches
    if matches!(
        name,
        "bootcode.bin"
            | "config.txt"
            | "cmdline.txt"
            | "LICENCE.broadcom"
            | "COPYING.linux"
            | "issue.txt"
            | "overlays"
            | "LICENSE.oracle"
    ) {
        return true;
    }

    // Prefix-based patterns
    if name.starts_with("kernel") && (name.ends_with(".img") || name.ends_with(".img.bak")) {
        return true;
    }
    if name.starts_with("start") && name.ends_with(".elf") {
        return true;
    }
    if name.starts_with("fixup") && name.ends_with(".dat") {
        return true;
    }
    if name.starts_with("bcm2") && name.ends_with(".dtb") {
        return true;
    }

    // General DTB files
    if name.ends_with(".dtb") {
        return true;
    }

    // Initramfs and vmlinuz (standard Linux boot files)
    if name.starts_with("initrd") || name.starts_with("initramfs") {
        return true;
    }
    if name.starts_with("vmlinuz") || name.starts_with("System.map") {
        return true;
    }

    false
}

/// Check if a file appears to be an ELF binary (by reading magic bytes)
fn is_elf_file(fs: &ContainerFs, path: &str) -> bool {
    // Read first 4 bytes and check for ELF magic: 0x7f 'E' 'L' 'F'
    let host_path = fs.resolve(path);
    let Ok(data) = std::fs::read(&host_path) else {
        return false;
    };
    data.len() >= 4 && data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
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
    fn test_clean_boot_no_findings() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let boot = root.join("boot/firmware");
        fs::create_dir_all(&boot).unwrap();

        // Write standard files
        fs::write(boot.join("config.txt"), "# Standard config\n").unwrap();
        fs::write(boot.join("cmdline.txt"), "console=serial0,115200 root=PARTUUID=abc dwc_otg.lpm_enable=0 rootfstype=ext4 rootwait\n").unwrap();
        fs::write(boot.join("kernel8.img"), b"fake kernel").unwrap();
        fs::write(boot.join("start4.elf"), b"fake start").unwrap();
        fs::write(boot.join("fixup4.dat"), b"fake fixup").unwrap();
        fs::write(boot.join("bcm2711-rpi-4-b.dtb"), b"dtb").unwrap();
        fs::write(boot.join("bootcode.bin"), b"bootcode").unwrap();

        let cfs = setup_container(&tmp);
        let check = BootIntegrityCheck;
        let findings = check.run(&cfs);

        assert!(findings.is_empty(), "Clean boot should produce no findings, got: {:?}", findings.iter().map(|f| &f.title).collect::<Vec<_>>());
    }

    #[test]
    fn test_malicious_kernel_detected() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let boot = root.join("boot/firmware");
        fs::create_dir_all(&boot).unwrap();

        // config.txt pointing to non-standard kernel
        fs::write(
            boot.join("config.txt"),
            "kernel=backdoor.bin\n",
        )
        .unwrap();
        fs::write(boot.join("cmdline.txt"), "root=/dev/mmcblk0p2\n").unwrap();

        let cfs = setup_container(&tmp);
        let check = BootIntegrityCheck;
        let findings = check.run(&cfs);

        let kernel_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Non-standard kernel"))
            .collect();
        assert_eq!(kernel_findings.len(), 1);
        assert_eq!(kernel_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_malicious_init_detected() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let boot = root.join("boot");
        fs::create_dir_all(&boot).unwrap();

        fs::write(boot.join("config.txt"), "# Normal config\n").unwrap();
        fs::write(
            boot.join("cmdline.txt"),
            "root=/dev/mmcblk0p2 init=/tmp/evil rootwait\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = BootIntegrityCheck;
        let findings = check.run(&cfs);

        let init_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Non-standard init"))
            .collect();
        assert_eq!(init_findings.len(), 1);
        assert_eq!(init_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_unexpected_script_in_boot() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let boot = root.join("boot/firmware");
        fs::create_dir_all(&boot).unwrap();

        fs::write(boot.join("config.txt"), "# Normal\n").unwrap();
        fs::write(boot.join("cmdline.txt"), "root=/dev/mmcblk0p2\n").unwrap();
        fs::write(boot.join("payload.sh"), "#!/bin/bash\nwhoami\n").unwrap();

        let cfs = setup_container(&tmp);
        let check = BootIntegrityCheck;
        let findings = check.run(&cfs);

        let script_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("payload.sh"))
            .collect();
        assert_eq!(script_findings.len(), 1);
        assert_eq!(script_findings[0].severity, Severity::High);
    }

    #[test]
    fn test_suspicious_rootdelay() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let boot = root.join("boot/firmware");
        fs::create_dir_all(&boot).unwrap();

        fs::write(boot.join("config.txt"), "# Normal\n").unwrap();
        fs::write(
            boot.join("cmdline.txt"),
            "root=/dev/mmcblk0p2 rootdelay=999 rootwait\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = BootIntegrityCheck;
        let findings = check.run(&cfs);

        let delay_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("rootdelay"))
            .collect();
        assert_eq!(delay_findings.len(), 1);
        assert_eq!(delay_findings[0].severity, Severity::Medium);
    }
}
