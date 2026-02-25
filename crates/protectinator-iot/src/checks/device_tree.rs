//! Device Tree overlay validation
//!
//! Parses config.txt dtoverlay= lines against a standard Pi overlay whitelist
//! and checks that .dtbo files in the overlays directory are package-owned.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use tracing::debug;

pub struct DeviceTreeCheck;

/// Standard Raspberry Pi device tree overlays shipped with the firmware package
const STANDARD_OVERLAYS: &[&str] = &[
    "disable-bt",
    "disable-wifi",
    "dwc2",
    "gpio-fan",
    "gpio-ir",
    "gpio-ir-tx",
    "gpio-key",
    "gpio-led",
    "gpio-poweroff",
    "gpio-shutdown",
    "hifiberry-dac",
    "hifiberry-dacplus",
    "hifiberry-dacplusadc",
    "hifiberry-digi",
    "i2c-rtc",
    "i2c-sensor",
    "i2s-gpio28-31",
    "imx219",
    "imx477",
    "iqaudio-dac",
    "iqaudio-dacplus",
    "miniuart-bt",
    "mmc",
    "pi3-disable-bt",
    "pi3-miniuart-bt",
    "pps-gpio",
    "pwm",
    "pwm-2chan",
    "spi0-1cs",
    "spi0-2cs",
    "spi1-1cs",
    "spi1-2cs",
    "spi1-3cs",
    "uart0",
    "uart1",
    "uart2",
    "uart3",
    "uart4",
    "uart5",
    "vc4-fkms-v3d",
    "vc4-kms-v3d",
    "vc4-kms-v3d-pi4",
    "vc4-kms-v3d-pi5",
    "w1-gpio",
    "w1-gpio-pullup",
    "wittypi",
];

impl IotCheck for DeviceTreeCheck {
    fn id(&self) -> &str {
        "iot-device-tree"
    }

    fn name(&self) -> &str {
        "Device Tree Overlay Validation"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        let boot_dirs = ["/boot/firmware", "/boot"];
        for boot_dir in &boot_dirs {
            let config_path = format!("{}/config.txt", boot_dir);
            if let Ok(content) = fs.read_to_string(&config_path) {
                check_dtoverlays(&content, boot_dir, fs, &mut findings);
            }
        }

        findings
    }
}

fn check_dtoverlays(
    config_content: &str,
    boot_dir: &str,
    fs: &ContainerFs,
    findings: &mut Vec<Finding>,
) {
    let standard: HashSet<&str> = STANDARD_OVERLAYS.iter().copied().collect();
    let overlays_dir = format!("{}/overlays", boot_dir);

    for line in config_content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // dtoverlay=name or dtoverlay=name,param=value,...
        if let Some(rest) = line.strip_prefix("dtoverlay=") {
            let overlay_name = rest.split(',').next().unwrap_or(rest).trim();
            if overlay_name.is_empty() {
                continue;
            }

            debug!("Found dtoverlay: {}", overlay_name);

            if !standard.contains(overlay_name) {
                // Check if the .dtbo file exists
                let dtbo_path = format!("{}/{}.dtbo", overlays_dir, overlay_name);
                let exists = fs.exists(&dtbo_path);

                let severity = if !exists {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let desc = if exists {
                    format!(
                        "Non-standard device tree overlay '{}' is configured in config.txt. \
                         Verify this overlay is expected for your hardware configuration.",
                        overlay_name
                    )
                } else {
                    format!(
                        "Device tree overlay '{}' is configured in config.txt but the \
                         corresponding .dtbo file was not found at {}.",
                        overlay_name, dtbo_path
                    )
                };

                findings.push(
                    Finding::new(
                        "iot-device-tree-nonstandard",
                        format!("Non-standard device tree overlay: {}", overlay_name),
                        desc,
                        severity,
                        FindingSource::Hardening {
                            check_id: "device-tree".to_string(),
                            category: "boot_config".to_string(),
                        },
                    )
                    .with_resource(format!("{}/config.txt", boot_dir)),
                );
            }
        }
    }

    // Check for .dtbo files in overlays/ not owned by dpkg
    if let Ok(entries) = fs.read_dir(&overlays_dir) {
        // Build dpkg ownership set
        let owned_files = build_dpkg_file_set(fs);

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("dtbo") {
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let overlay_path = format!("{}/{}", overlays_dir, file_name);

                // Check if owned by dpkg
                if !owned_files.is_empty() && !owned_files.contains(&overlay_path) {
                    findings.push(
                        Finding::new(
                            "iot-device-tree-unowned",
                            format!("Unowned device tree overlay: {}", file_name),
                            format!(
                                "Device tree overlay file '{}' is not owned by any installed \
                                 package. This could indicate a manually added or malicious overlay.",
                                overlay_path
                            ),
                            Severity::Medium,
                            FindingSource::Hardening {
                                check_id: "device-tree".to_string(),
                                category: "boot_config".to_string(),
                            },
                        )
                        .with_resource(overlay_path)
                        .with_remediation(
                            "Verify this overlay is expected. Remove if not needed.",
                        ),
                    );
                }
            }
        }
    }
}

/// Build a set of file paths owned by dpkg packages
fn build_dpkg_file_set(fs: &ContainerFs) -> HashSet<String> {
    let mut owned = HashSet::new();
    let dpkg_info_dir = fs.resolve("/var/lib/dpkg/info");

    if let Ok(entries) = std::fs::read_dir(&dpkg_info_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("list") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        let line = line.trim();
                        if !line.is_empty() {
                            owned.insert(line.to_string());
                        }
                    }
                }
            }
        }
    }

    owned
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_boot_dir(tmp: &TempDir) -> ContainerFs {
        let boot = tmp.path().join("boot").join("firmware");
        std::fs::create_dir_all(boot.join("overlays")).unwrap();
        ContainerFs::new(tmp.path())
    }

    #[test]
    fn test_standard_overlay_no_finding() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_boot_dir(&tmp);

        let config = "dtoverlay=vc4-kms-v3d\ndtoverlay=disable-bt\n";
        std::fs::write(
            tmp.path().join("boot/firmware/config.txt"),
            config,
        )
        .unwrap();

        let check = DeviceTreeCheck;
        let findings = check.run(&fs);
        assert!(findings.is_empty(), "Standard overlays should not flag");
    }

    #[test]
    fn test_nonstandard_overlay_flags() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_boot_dir(&tmp);

        // Create a non-standard overlay entry
        let config = "dtoverlay=my-custom-evil-overlay\n";
        std::fs::write(
            tmp.path().join("boot/firmware/config.txt"),
            config,
        )
        .unwrap();

        let check = DeviceTreeCheck;
        let findings = check.run(&fs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("my-custom-evil-overlay"));
    }

    #[test]
    fn test_comments_and_empty_lines_skipped() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_boot_dir(&tmp);

        let config = "# dtoverlay=evil\n\ndtoverlay=vc4-kms-v3d\n";
        std::fs::write(
            tmp.path().join("boot/firmware/config.txt"),
            config,
        )
        .unwrap();

        let check = DeviceTreeCheck;
        let findings = check.run(&fs);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_overlay_with_params() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_boot_dir(&tmp);

        let config = "dtoverlay=gpio-fan,gpiopin=14,temp=55000\n";
        std::fs::write(
            tmp.path().join("boot/firmware/config.txt"),
            config,
        )
        .unwrap();

        let check = DeviceTreeCheck;
        let findings = check.run(&fs);
        assert!(findings.is_empty(), "gpio-fan is standard");
    }
}
