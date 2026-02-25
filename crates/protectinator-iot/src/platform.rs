//! Platform detection for Raspberry Pi and IoT devices
//!
//! Detects device type, Pi model, and architecture by examining
//! device tree, boot files, and system information.

use crate::types::{IotDeviceType, PiModel};
use protectinator_container::filesystem::ContainerFs;
use tracing::debug;

/// Detect the device type from the filesystem
pub fn detect_device(fs: &ContainerFs) -> IotDeviceType {
    // Try Pi-specific detection first
    if let Some(model) = detect_pi_model(fs) {
        return IotDeviceType::RaspberryPi(model);
    }

    // Check for generic ARM
    if is_arm_device(fs) {
        return IotDeviceType::GenericARM;
    }

    IotDeviceType::GenericLinux
}

/// Detect Raspberry Pi model from device tree or boot files
fn detect_pi_model(fs: &ContainerFs) -> Option<PiModel> {
    // Method 1: /proc/device-tree/model (local mode only)
    if let Ok(model_str) = fs.read_to_string("/proc/device-tree/model") {
        let model_str = model_str.trim_end_matches('\0').trim();
        debug!("Device tree model: {}", model_str);
        return Some(parse_pi_model(model_str));
    }

    // Method 2: /etc/rpi-issue (works on mounted filesystems)
    if fs.exists("/etc/rpi-issue") {
        debug!("Found /etc/rpi-issue — this is a Raspberry Pi OS image");
        // Try to get model from /sys/firmware/devicetree/base/model
        if let Ok(model_str) = fs.read_to_string("/sys/firmware/devicetree/base/model") {
            let model_str = model_str.trim_end_matches('\0').trim();
            return Some(parse_pi_model(model_str));
        }
        // Can't determine specific model from a mounted card without device tree
        return Some(PiModel::Unknown("detected from /etc/rpi-issue".to_string()));
    }

    // Method 3: Check boot partition for Pi-specific files
    let boot_dirs = ["/boot/firmware", "/boot"];
    for boot_dir in &boot_dirs {
        let config_path = format!("{}/config.txt", boot_dir);
        if fs.exists(&config_path) {
            // config.txt is Pi-specific
            let kernel_path = format!("{}/kernel8.img", boot_dir);
            let kernel7_path = format!("{}/kernel7.img", boot_dir);
            let kernel7l_path = format!("{}/kernel7l.img", boot_dir);

            if fs.exists(&kernel_path) || fs.exists(&kernel7_path) || fs.exists(&kernel7l_path) {
                debug!("Found Pi boot files in {}", boot_dir);
                return Some(PiModel::Unknown(
                    "detected from boot partition".to_string(),
                ));
            }
        }
    }

    None
}

/// Parse a device-tree model string into a PiModel
fn parse_pi_model(model: &str) -> PiModel {
    let lower = model.to_lowercase();

    if lower.contains("pi 5") || lower.contains("pi5") {
        PiModel::Pi5
    } else if lower.contains("pi 400") {
        PiModel::Pi400
    } else if lower.contains("compute module 4") || lower.contains("cm4") {
        PiModel::PiCM4
    } else if lower.contains("pi 4") || lower.contains("pi4") {
        PiModel::Pi4
    } else if lower.contains("pi 3") || lower.contains("pi3") {
        PiModel::Pi3
    } else if lower.contains("pi 2") || lower.contains("pi2") {
        PiModel::Pi2
    } else if lower.contains("zero 2") {
        PiModel::PiZero2
    } else if lower.contains("zero w") {
        PiModel::PiZeroW
    } else if lower.contains("zero") {
        PiModel::PiZero
    } else if lower.contains("pi 1") || lower.contains("model b") || lower.contains("model a") {
        PiModel::Pi1
    } else {
        PiModel::Unknown(model.to_string())
    }
}

/// Check if this is an ARM device (from /proc/cpuinfo or lib paths)
fn is_arm_device(fs: &ContainerFs) -> bool {
    // Check /proc/cpuinfo for ARM (local mode)
    if let Ok(cpuinfo) = fs.read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("ARM") || cpuinfo.contains("aarch64") {
            return true;
        }
    }

    // Check for ARM library paths (works on mounted filesystems)
    fs.exists("/usr/lib/arm-linux-gnueabihf")
        || fs.exists("/usr/lib/aarch64-linux-gnu")
        || fs.exists("/lib/arm-linux-gnueabihf")
        || fs.exists("/lib/aarch64-linux-gnu")
}

/// Get the architecture string for display
pub fn detect_architecture(fs: &ContainerFs) -> String {
    // Try /proc/cpuinfo (local)
    if let Ok(cpuinfo) = fs.read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") || line.starts_with("Hardware") {
                if let Some((_, value)) = line.split_once(':') {
                    return value.trim().to_string();
                }
            }
        }
    }

    // Infer from lib paths (mounted)
    if fs.exists("/usr/lib/aarch64-linux-gnu") || fs.exists("/lib/aarch64-linux-gnu") {
        return "aarch64".to_string();
    }
    if fs.exists("/usr/lib/arm-linux-gnueabihf") || fs.exists("/lib/arm-linux-gnueabihf") {
        return "armhf".to_string();
    }

    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pi_model_pi4() {
        assert!(matches!(
            parse_pi_model("Raspberry Pi 4 Model B Rev 1.4"),
            PiModel::Pi4
        ));
    }

    #[test]
    fn test_parse_pi_model_pi5() {
        assert!(matches!(
            parse_pi_model("Raspberry Pi 5 Model B Rev 1.0"),
            PiModel::Pi5
        ));
    }

    #[test]
    fn test_parse_pi_model_zero2() {
        assert!(matches!(
            parse_pi_model("Raspberry Pi Zero 2 W Rev 1.0"),
            PiModel::PiZero2
        ));
    }

    #[test]
    fn test_parse_pi_model_zero_w() {
        assert!(matches!(
            parse_pi_model("Raspberry Pi Zero W Rev 1.1"),
            PiModel::PiZeroW
        ));
    }

    #[test]
    fn test_parse_pi_model_pi400() {
        assert!(matches!(
            parse_pi_model("Raspberry Pi 400 Rev 1.0"),
            PiModel::Pi400
        ));
    }

    #[test]
    fn test_parse_pi_model_unknown() {
        assert!(matches!(
            parse_pi_model("Some Other Board"),
            PiModel::Unknown(_)
        ));
    }
}
