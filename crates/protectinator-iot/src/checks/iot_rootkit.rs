//! IoT-specific rootkit and malware signature check
//!
//! Extends the generic rootkit check with signatures for IoT-targeted
//! malware families (Mirai, Hajime, Gafgyt, etc.), suspicious /dev entries,
//! and unowned ARM libraries.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use tracing::debug;

/// Mirai botnet indicator files
const MIRAI_INDICATORS: &[&str] = &[
    "/tmp/.nippon",
    "/tmp/.xm",
    "/dev/.human",
    "/tmp/mirai.arm",
    "/tmp/mirai.arm7",
    "/tmp/mirai.mips",
    "/tmp/mirai.x86",
    "/var/run/.mira",
    "/tmp/.loaded",
    "/tmp/.anime",
];

/// Hajime botnet indicator files
const HAJIME_INDICATORS: &[&str] = &[
    "/tmp/.hajime",
    "/tmp/atk",
    "/tmp/atk.arm",
    "/tmp/atk.mips",
    "/var/run/.hajime",
];

/// Other IoT malware indicator files
const OTHER_IOT_MALWARE: &[(&str, &str)] = &[
    ("/tmp/.gafgyt", "Gafgyt/Bashlite botnet"),
    ("/tmp/.bashlite", "Bashlite botnet"),
    ("/tmp/.tsunami", "Tsunami/Kaiten IRC bot"),
    ("/tmp/.kaiten", "Kaiten IRC bot"),
    ("/tmp/.zollard", "Zollard worm"),
    ("/var/tmp/.bot", "Generic IoT bot"),
    ("/tmp/.dvrHelper", "DVR exploitation tool"),
    ("/tmp/.ttp", "IoT trojan payload"),
    ("/tmp/.satori", "Satori botnet"),
    ("/tmp/.owari", "Owari/Mirai variant"),
    ("/tmp/.yakuza", "Yakuza/Mirai variant"),
    ("/tmp/.jno", "JenX botnet"),
    ("/tmp/.rab", "Remaiten botnet"),
];

/// Standard /dev entries (prefixes and exact names)
const STANDARD_DEV_EXACT: &[&str] = &[
    "null",
    "zero",
    "random",
    "urandom",
    "ptmx",
    "console",
    "full",
    "fd",
    "stdin",
    "stdout",
    "stderr",
    "shm",
    "mqueue",
    "hugepages",
    "log",
    "disk",
    "bus",
    "char",
    "block",
    "net",
    "cpu",
    "mapper",
    "mem",
    "kmsg",
    "port",
    "input",
    "snd",
    "dri",
    "pts",
    "watchdog",
    "hwrng",
    "vcio",
    "vchiq",
    "cuse",
    "fuse",
    "btrfs-control",
    "autofs",
    "rtc0",
    "rtc",
    "ppp",
    "tun",
    "vhost-net",
    "vhost-vsock",
    "kvm",
    "vsock",
    "snapshot",
    "uhid",
    "uinput",
    "userfaultfd",
    "gpiomem",
];

/// Standard /dev entry prefixes
const STANDARD_DEV_PREFIXES: &[&str] = &[
    "tty",
    "pts",
    "vcs",
    "loop",
    "ram",
    "video",
    "fb",
    "i2c-",
    "spi",
    "gpio",
    "serial",
    "ttyAMA",
    "ttyS",
    "ttyUSB",
    "mmcblk",
    "sd",
    "dm-",
    "nvme",
    "sg",
    "sr",
    "md",
    "drm",
    "hidraw",
    "media",
    "v4l",
    "vhci",
    "zram",
    "iio:device",
    "watchdog",
    "ptp",
    "cec",
    "mei",
    "dma_heap",
    "usb",
];

/// ARM library directories to check for unowned shared libraries
const ARM_LIB_DIRS: &[&str] = &[
    "/usr/lib/arm-linux-gnueabihf",
    "/usr/lib/aarch64-linux-gnu",
];

fn make_source(category: &str) -> FindingSource {
    FindingSource::AgentDetection {
        agent_type: "iot_malware".to_string(),
        category: category.to_string(),
    }
}

/// IoT rootkit and malware signature check
pub struct IotRootkitCheck;

impl IotCheck for IotRootkitCheck {
    fn id(&self) -> &str {
        "iot-rootkit-signatures"
    }

    fn name(&self) -> &str {
        "IoT Rootkit & Malware Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_mirai_indicators(fs, &mut findings);
        check_hajime_indicators(fs, &mut findings);
        check_other_iot_malware(fs, &mut findings);
        check_suspicious_dev_entries(fs, &mut findings);
        check_unowned_arm_libraries(fs, &mut findings);

        findings
    }
}

/// Check for Mirai botnet indicator files
fn check_mirai_indicators(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for path in MIRAI_INDICATORS {
        if fs.exists(path) {
            findings.push(
                Finding::new(
                    "iot-rootkit-signatures",
                    format!("Mirai botnet indicator: {}", path),
                    format!(
                        "Known Mirai botnet indicator file found at '{}'. Mirai is an IoT \
                         botnet that infects devices via default credentials and telnet, then \
                         uses them for DDoS attacks. Immediate investigation required.",
                        path
                    ),
                    Severity::Critical,
                    make_source("mirai"),
                )
                .with_resource(path.to_string())
                .with_remediation(
                    "Isolate this device immediately. Reflash the SD card from a known-good \
                     image. Change all default credentials before reconnecting to the network.",
                )
                .with_reference("https://attack.mitre.org/software/S0368/"),
            );
        }
    }

    // Also check for Mirai with wildcard pattern: /tmp/mirai.*
    if let Ok(entries) = fs.read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("mirai.") || name_str.starts_with("mirai_") {
                let path = format!("/tmp/{}", name_str);
                // Avoid double-reporting exact matches
                if MIRAI_INDICATORS.contains(&path.as_str()) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        "iot-rootkit-signatures",
                        format!("Mirai botnet indicator: {}", path),
                        format!(
                            "Possible Mirai botnet binary found at '{}'. Mirai distributes \
                             architecture-specific binaries named mirai.* to infected devices.",
                            path
                        ),
                        Severity::Critical,
                        make_source("mirai"),
                    )
                    .with_resource(path)
                    .with_remediation(
                        "Isolate this device immediately and reflash from a known-good image.",
                    ),
                );
            }
        }
    }
}

/// Check for Hajime botnet indicator files
fn check_hajime_indicators(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for path in HAJIME_INDICATORS {
        if fs.exists(path) {
            findings.push(
                Finding::new(
                    "iot-rootkit-signatures",
                    format!("Hajime botnet indicator: {}", path),
                    format!(
                        "Known Hajime botnet indicator file found at '{}'. Hajime is a \
                         peer-to-peer IoT botnet that spreads via brute-force attacks on \
                         telnet and SSH.",
                        path
                    ),
                    Severity::Critical,
                    make_source("hajime"),
                )
                .with_resource(path.to_string())
                .with_remediation(
                    "Isolate this device and reflash from a known-good image. \
                     Change all credentials and disable telnet.",
                )
                .with_reference("https://attack.mitre.org/software/S0400/"),
            );
        }
    }

    // Check for /tmp/atk* pattern
    if let Ok(entries) = fs.read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("atk") {
                let path = format!("/tmp/{}", name_str);
                if HAJIME_INDICATORS.contains(&path.as_str()) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        "iot-rootkit-signatures",
                        format!("Hajime attack tool indicator: {}", path),
                        format!(
                            "Possible Hajime attack tool found at '{}'. Files named atk* in \
                             /tmp are associated with the Hajime botnet's attack modules.",
                            path
                        ),
                        Severity::Critical,
                        make_source("hajime"),
                    )
                    .with_resource(path),
                );
            }
        }
    }
}

/// Check for other IoT malware indicator files
fn check_other_iot_malware(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    for (path, malware_name) in OTHER_IOT_MALWARE {
        if fs.exists(path) {
            findings.push(
                Finding::new(
                    "iot-rootkit-signatures",
                    format!("{} indicator: {}", malware_name, path),
                    format!(
                        "Known IoT malware indicator '{}' found at '{}'. This file is \
                         associated with the {} malware family.",
                        malware_name, path, malware_name
                    ),
                    Severity::Critical,
                    make_source("iot_malware"),
                )
                .with_resource(path.to_string())
                .with_remediation(
                    "Isolate this device immediately and reflash from a known-good image.",
                ),
            );
        }
    }
}

/// Check /dev for suspicious entries not in standard whitelist
fn check_suspicious_dev_entries(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let entries = match fs.read_dir("/dev") {
        Ok(e) => e,
        Err(_) => {
            debug!("Cannot read /dev, skipping suspicious device check");
            return;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();

        // Get metadata to check file type
        let host_path = entry.path();
        let meta = match host_path.symlink_metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Only flag regular files or symlinks — skip directories, device nodes,
        // sockets, and pipes (which are all normal in /dev)
        let file_type = meta.file_type();
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }

        // Check against standard whitelist
        if is_standard_dev_entry(&name_str) {
            continue;
        }

        // Hidden files in /dev are especially suspicious
        let severity = if name_str.starts_with('.') {
            Severity::High
        } else {
            Severity::Medium
        };

        findings.push(
            Finding::new(
                "iot-rootkit-signatures",
                format!("Suspicious /dev entry: {}", name_str),
                format!(
                    "Unexpected regular file or symlink '{}' found in /dev. Regular files \
                     in /dev are unusual and can be used to hide malware or rootkit components. \
                     Hidden files (starting with .) are especially suspicious.",
                    name_str
                ),
                severity,
                make_source("dev_filesystem"),
            )
            .with_resource(format!("/dev/{}", name_str))
            .with_remediation(
                "Investigate this file. Examine its contents, creation time, and whether \
                 any process is using it. Remove if not legitimate.",
            ),
        );
    }
}

/// Check if a /dev entry name matches the standard whitelist
fn is_standard_dev_entry(name: &str) -> bool {
    // Exact match
    if STANDARD_DEV_EXACT.contains(&name) {
        return true;
    }

    // Prefix match (e.g., "tty0" matches prefix "tty")
    for prefix in STANDARD_DEV_PREFIXES {
        if name.starts_with(prefix) {
            return true;
        }
    }

    // Hidden dot files that are actually standard
    if name == "." || name == ".." {
        return true;
    }

    false
}

/// Check for unowned shared libraries in ARM lib paths
fn check_unowned_arm_libraries(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let dpkg_owned = collect_dpkg_owned_files(fs);

    for lib_dir in ARM_LIB_DIRS {
        let entries = match fs.read_dir(lib_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();

            // Only check .so files (including versioned like .so.1.2.3)
            if !name_str.contains(".so") {
                continue;
            }

            let lib_path = format!("{}/{}", lib_dir, name_str);

            if !dpkg_owned.contains(&lib_path) {
                findings.push(
                    Finding::new(
                        "iot-rootkit-signatures",
                        format!("Unowned ARM library: {}", lib_path),
                        format!(
                            "Shared library '{}' is not owned by any dpkg package. \
                             Unowned libraries in ARM system directories could be rootkit \
                             components or injected shared objects used for function hooking.",
                            lib_path
                        ),
                        Severity::High,
                        make_source("rootkit_library"),
                    )
                    .with_resource(lib_path)
                    .with_remediation(
                        "Investigate this library. Check with: file <path>, ldd <path>, \
                         strings <path>. Remove if not intentionally installed.",
                    )
                    .with_reference("https://attack.mitre.org/techniques/T1574/006/"),
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
    fn test_detects_mirai_indicators() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create Mirai indicator files
        let tmp_dir = root.join("tmp");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join(".nippon"), b"mirai payload").unwrap();
        fs::write(tmp_dir.join("mirai.arm7"), b"arm binary").unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        let mirai: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Mirai"))
            .collect();
        assert_eq!(mirai.len(), 2);
        assert!(mirai.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_detects_hajime_indicators() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let tmp_dir = root.join("tmp");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join(".hajime"), b"hajime").unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        let hajime: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Hajime"))
            .collect();
        assert_eq!(hajime.len(), 1);
        assert_eq!(hajime[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detects_hidden_file_in_dev() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let dev_dir = root.join("dev");
        fs::create_dir_all(&dev_dir).unwrap();
        // Create a hidden regular file (suspicious)
        fs::write(dev_dir.join(".human"), b"hidden payload").unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        // .human is also a Mirai indicator, so we may get that too
        let dev_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Suspicious /dev entry"))
            .collect();
        assert!(!dev_findings.is_empty());
        // Hidden files in /dev should be High severity
        assert!(dev_findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_clean_system_no_malware_findings() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create standard directories but no malware
        fs::create_dir_all(root.join("tmp")).unwrap();
        fs::create_dir_all(root.join("dev")).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            critical.is_empty(),
            "Clean system should have no critical findings, got: {:?}",
            critical.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detects_unowned_arm_library() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create ARM lib directory with an unowned .so
        let arm_lib = root.join("usr/lib/aarch64-linux-gnu");
        fs::create_dir_all(&arm_lib).unwrap();
        fs::write(arm_lib.join("librootkit.so"), b"malicious library").unwrap();

        // Create dpkg info dir (empty — no packages own anything)
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        let unowned: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Unowned ARM library"))
            .collect();
        assert_eq!(unowned.len(), 1);
        assert_eq!(unowned[0].severity, Severity::High);
    }

    #[test]
    fn test_standard_dev_entries_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let dev_dir = root.join("dev");
        fs::create_dir_all(&dev_dir).unwrap();

        // Create standard /dev entries as regular files (for testing)
        // In reality these would be device nodes, but we're testing the name filter
        fs::write(dev_dir.join("null"), b"").unwrap();
        fs::write(dev_dir.join("zero"), b"").unwrap();
        fs::write(dev_dir.join("urandom"), b"").unwrap();
        // Note: tty0 matches prefix "tty"
        fs::write(dev_dir.join("tty0"), b"").unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        // Even though these are regular files (not device nodes) in our test,
        // they match the standard whitelist names so should not be flagged
        let dev_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Suspicious /dev entry"))
            .collect();
        assert!(
            dev_findings.is_empty(),
            "Standard /dev names should not be flagged, got: {:?}",
            dev_findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detects_other_iot_malware() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let tmp_dir = root.join("tmp");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join(".gafgyt"), b"gafgyt payload").unwrap();
        fs::write(tmp_dir.join(".tsunami"), b"tsunami irc bot").unwrap();

        let var_tmp = root.join("var/tmp");
        fs::create_dir_all(&var_tmp).unwrap();
        fs::write(var_tmp.join(".bot"), b"generic bot").unwrap();

        let cfs = setup_container(&tmp);
        let check = IotRootkitCheck;
        let findings = check.run(&cfs);

        let malware: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.title.contains("Gafgyt")
                    || f.title.contains("Tsunami")
                    || f.title.contains("Generic IoT bot")
            })
            .collect();
        assert_eq!(malware.len(), 3);
        assert!(malware.iter().all(|f| f.severity == Severity::Critical));
    }
}
