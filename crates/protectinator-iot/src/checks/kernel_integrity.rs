//! Kernel module integrity check
//!
//! Verifies kernel modules against dpkg package manifests, detects known
//! rootkit module names, and (when running locally) cross-references loaded
//! modules in /proc/modules against on-disk .ko files.

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use tracing::debug;
use walkdir::WalkDir;

/// Known rootkit kernel module names
const ROOTKIT_MODULE_NAMES: &[&str] = &[
    "adore",
    "knark",
    "rial",
    "heroin",
    "override",
    "synth",
    "rkit",
    "suckit",
    "modhide",
    "cleaner",
    "flkm",
    "vlogger",
    "enyelkm",
    "phalanx",
];

/// Kernel module file extensions
const MODULE_EXTENSIONS: &[&str] = &[".ko", ".ko.xz", ".ko.zst", ".ko.gz"];

/// Kernel module integrity check
pub struct KernelIntegrityCheck;

impl IotCheck for KernelIntegrityCheck {
    fn id(&self) -> &str {
        "iot-kernel-integrity"
    }

    fn name(&self) -> &str {
        "Kernel Module Integrity Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build the set of dpkg-owned files for module ownership checks
        let dpkg_owned = collect_dpkg_owned_files(fs);

        // Walk /lib/modules/ for on-disk module checks (works in mounted mode)
        check_ondisk_modules(fs, &dpkg_owned, &mut findings);

        // Local-mode additional checks via /proc
        check_proc_modules(fs, &mut findings);
        check_proc_version(fs, &mut findings);

        findings
    }
}

fn source() -> FindingSource {
    FindingSource::AgentDetection {
        agent_type: "rootkit".to_string(),
        category: "kernel_module".to_string(),
    }
}

/// Collect all file paths listed in /var/lib/dpkg/info/*.list
fn collect_dpkg_owned_files(fs: &ContainerFs) -> HashSet<String> {
    let mut owned = HashSet::new();

    let dpkg_info_dir = "/var/lib/dpkg/info";
    let entries = match fs.read_dir(dpkg_info_dir) {
        Ok(e) => e,
        Err(_) => {
            debug!("Cannot read dpkg info directory for kernel module ownership check");
            return owned;
        }
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

/// Check on-disk kernel modules under /lib/modules/
fn check_ondisk_modules(
    fs: &ContainerFs,
    dpkg_owned: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let modules_dir = fs.resolve("/lib/modules");
    if !modules_dir.exists() {
        debug!("/lib/modules does not exist, skipping on-disk kernel module check");
        return;
    }

    let root = fs.root();

    for entry in WalkDir::new(&modules_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let name_str = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();

        // Only check kernel module files
        if !MODULE_EXTENSIONS.iter().any(|ext| name_str.ends_with(ext)) {
            continue;
        }

        // Get the module base name (strip all extensions)
        let module_name = strip_module_extensions(&name_str);

        // Check for known rootkit module names
        if ROOTKIT_MODULE_NAMES
            .iter()
            .any(|rk| module_name.eq_ignore_ascii_case(rk))
        {
            let container_path = path_to_container_path(path, root);
            findings.push(
                Finding::new(
                    "iot-kernel-integrity",
                    format!("Known rootkit module found: {}", name_str),
                    format!(
                        "Kernel module '{}' at '{}' matches the name of a known Linux \
                         rootkit. This requires immediate investigation.",
                        module_name, container_path
                    ),
                    Severity::Critical,
                    source(),
                )
                .with_resource(container_path)
                .with_remediation(
                    "Investigate this module immediately. Compare checksums with known-good copies. \
                     Consider reimaging the device.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1547/006/"),
            );
            continue;
        }

        // Check if the module is owned by a dpkg package
        let container_path = path_to_container_path(path, root);
        if !dpkg_owned.contains(&container_path) {
            findings.push(
                Finding::new(
                    "iot-kernel-integrity",
                    format!("Unowned kernel module found: {}", name_str),
                    format!(
                        "Kernel module '{}' at '{}' is not owned by any dpkg package. \
                         This may be a custom module, a DKMS-built module, or a \
                         potentially malicious module.",
                        name_str, container_path
                    ),
                    Severity::High,
                    source(),
                )
                .with_resource(container_path)
                .with_remediation(
                    "Verify this module is expected. Check if it was built by DKMS \
                     or installed manually. Remove if not recognized.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1547/006/"),
            );
        }
    }

    // Check for kernel modules in non-standard locations (outside /lib/modules/)
    check_nonstandard_module_locations(fs, findings);
}

/// Check for kernel modules in non-standard locations
fn check_nonstandard_module_locations(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    // Common directories where rootkit modules might hide
    let suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/root", "/home"];

    for dir in &suspicious_dirs {
        let resolved = fs.resolve(dir);
        if !resolved.exists() {
            continue;
        }

        // Only walk one level deep to avoid excessive scanning
        for entry in WalkDir::new(&resolved)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let name_str = entry
                .path()
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if MODULE_EXTENSIONS.iter().any(|ext| name_str.ends_with(ext)) {
                let container_path = path_to_container_path(entry.path(), fs.root());
                findings.push(
                    Finding::new(
                        "iot-kernel-integrity",
                        format!(
                            "Kernel module in non-standard location: {}",
                            container_path
                        ),
                        format!(
                            "Kernel module '{}' found outside /lib/modules/ at '{}'. \
                             Kernel modules in non-standard locations are highly suspicious.",
                            name_str, container_path
                        ),
                        Severity::High,
                        source(),
                    )
                    .with_resource(container_path)
                    .with_remediation("Investigate this module. Kernel modules should only exist in /lib/modules/.")
                    .with_reference("https://attack.mitre.org/techniques/T1547/006/"),
                );
            }
        }
    }
}

/// Check /proc/modules (local mode) — cross-reference loaded modules against on-disk files
fn check_proc_modules(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let proc_modules = match fs.read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => {
            debug!("/proc/modules not readable (expected if not running locally)");
            return;
        }
    };

    // Build a set of on-disk module names from /lib/modules/
    let ondisk_modules = collect_ondisk_module_names(fs);

    for line in proc_modules.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }

        let module_name = fields[0];

        // Check for rootkit module names in loaded modules
        if ROOTKIT_MODULE_NAMES
            .iter()
            .any(|rk| module_name.eq_ignore_ascii_case(rk))
        {
            findings.push(
                Finding::new(
                    "iot-kernel-integrity",
                    format!("Known rootkit module loaded: {}", module_name),
                    format!(
                        "Loaded kernel module '{}' matches a known rootkit name. \
                         This is a critical indicator of compromise.",
                        module_name
                    ),
                    Severity::Critical,
                    source(),
                )
                .with_resource(format!("/proc/modules:{}", module_name))
                .with_remediation(
                    "Investigate immediately. This device may be compromised. \
                     Consider taking the device offline and reimaging.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1014/"),
            );
            continue;
        }

        // Check if loaded module has a corresponding .ko on disk
        // Module names in /proc/modules use underscores, on-disk names may use hyphens
        let normalized = module_name.replace('-', "_");
        let also_hyphen = module_name.replace('_', "-");

        if !ondisk_modules.contains(&normalized)
            && !ondisk_modules.contains(module_name)
            && !ondisk_modules.contains(&also_hyphen)
        {
            findings.push(
                Finding::new(
                    "iot-kernel-integrity",
                    format!("Potentially hidden kernel module: {}", module_name),
                    format!(
                        "Loaded kernel module '{}' has no corresponding .ko file on disk \
                         under /lib/modules/. This may indicate a hidden or injected module.",
                        module_name
                    ),
                    Severity::High,
                    source(),
                )
                .with_resource(format!("/proc/modules:{}", module_name))
                .with_remediation(
                    "Investigate this module. Check if it was loaded from a non-standard \
                     path or if it is attempting to hide.",
                )
                .with_reference("https://attack.mitre.org/techniques/T1014/"),
            );
        }
    }
}

/// Collect on-disk module base names (without extension) from /lib/modules/
fn collect_ondisk_module_names(fs: &ContainerFs) -> HashSet<String> {
    let mut names = HashSet::new();

    let modules_dir = fs.resolve("/lib/modules");
    if !modules_dir.exists() {
        return names;
    }

    for entry in WalkDir::new(&modules_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let name_str = entry
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if MODULE_EXTENSIONS.iter().any(|ext| name_str.ends_with(ext)) {
            let base = strip_module_extensions(&name_str);
            // Store both underscore and hyphen variants
            names.insert(base.replace('-', "_"));
            names.insert(base.replace('_', "-"));
            names.insert(base.to_string());
        }
    }

    names
}

/// Check /proc/version against installed kernel package (local mode)
fn check_proc_version(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let proc_version = match fs.read_to_string("/proc/version") {
        Ok(c) => c,
        Err(_) => {
            debug!("/proc/version not readable (expected if not running locally)");
            return;
        }
    };

    // Extract kernel version from /proc/version
    // Format: "Linux version 5.10.0-21-arm64 (debian-kernel@lists.debian.org) ..."
    let running_version = proc_version
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .to_string();

    if running_version.is_empty() {
        return;
    }

    // Try to find the installed kernel package version from dpkg status
    let dpkg_status = match fs.read_to_string("/var/lib/dpkg/status") {
        Ok(c) => c,
        Err(_) => return,
    };

    // Look for linux-image packages
    let mut installed_version: Option<String> = None;
    let mut in_kernel_package = false;

    for line in dpkg_status.lines() {
        if line.starts_with("Package: ") {
            let pkg_name = line.trim_start_matches("Package: ").trim();
            in_kernel_package = pkg_name.starts_with("linux-image-");
        }
        if in_kernel_package && line.starts_with("Version: ") {
            installed_version = Some(line.trim_start_matches("Version: ").trim().to_string());
        }
        // Reset on empty line (package boundary)
        if line.trim().is_empty() {
            if in_kernel_package && installed_version.is_some() {
                break;
            }
            in_kernel_package = false;
        }
    }

    if let Some(ref pkg_version) = installed_version {
        // Simple sanity check: the running version should appear somewhere in
        // the installed package name or version
        if !dpkg_status.contains(&running_version) {
            findings.push(
                Finding::new(
                    "iot-kernel-integrity",
                    "Running kernel may not match installed package",
                    format!(
                        "Running kernel '{}' does not appear to match any installed \
                         linux-image dpkg package (found version '{}'). The kernel may \
                         have been replaced outside the package manager.",
                        running_version, pkg_version
                    ),
                    Severity::High,
                    source(),
                )
                .with_resource("/proc/version")
                .with_metadata(
                    "running_version",
                    serde_json::Value::String(running_version),
                )
                .with_metadata(
                    "installed_version",
                    serde_json::Value::String(pkg_version.clone()),
                )
                .with_remediation(
                    "Verify the kernel is legitimate. Reinstall the kernel package if needed.",
                ),
            );
        }
    }
}

/// Strip all kernel module extensions from a filename
fn strip_module_extensions(name: &str) -> String {
    let mut result = name.to_string();
    // Strip compression extensions first
    for ext in &[".xz", ".zst", ".gz"] {
        if let Some(stripped) = result.strip_suffix(ext) {
            result = stripped.to_string();
        }
    }
    // Then strip .ko
    if let Some(stripped) = result.strip_suffix(".ko") {
        result = stripped.to_string();
    }
    result
}

/// Convert a host path back to a container-relative path
fn path_to_container_path(path: &std::path::Path, root: &std::path::Path) -> String {
    match path.strip_prefix(root) {
        Ok(relative) => format!("/{}", relative.display()),
        Err(_) => path.display().to_string(),
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
    fn test_detects_rootkit_module_on_disk() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create module directory structure
        let kernel_dir = root.join("lib/modules/5.10.0/kernel/drivers");
        fs::create_dir_all(&kernel_dir).unwrap();

        // Plant a rootkit module
        fs::write(kernel_dir.join("adore.ko"), b"fake rootkit module").unwrap();

        // Create dpkg info directory (empty — module is unowned)
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        let cfs = setup_container(&tmp);
        let check = KernelIntegrityCheck;
        let findings = check.run(&cfs);

        let rootkit = findings
            .iter()
            .find(|f| f.title.contains("Known rootkit module found: adore"));
        assert!(rootkit.is_some(), "Should detect rootkit module on disk");
        assert_eq!(rootkit.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_detects_unowned_module() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create module directory
        let kernel_dir = root.join("lib/modules/5.10.0/kernel/misc");
        fs::create_dir_all(&kernel_dir).unwrap();

        // Create a module that is NOT in any dpkg .list file
        fs::write(kernel_dir.join("custom_driver.ko"), b"custom module").unwrap();

        // Create dpkg info directory with a .list that doesn't include our module
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();
        fs::write(
            dpkg_dir.join("linux-image-5.10.0.list"),
            "/lib/modules/5.10.0/kernel/drivers/some_other.ko\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = KernelIntegrityCheck;
        let findings = check.run(&cfs);

        let unowned = findings
            .iter()
            .find(|f| f.title.contains("Unowned kernel module found: custom_driver"));
        assert!(unowned.is_some(), "Should detect unowned module");
        assert_eq!(unowned.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_owned_module_no_finding() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create module directory
        let kernel_dir = root.join("lib/modules/5.10.0/kernel/drivers");
        fs::create_dir_all(&kernel_dir).unwrap();
        fs::write(kernel_dir.join("e1000.ko"), b"network driver").unwrap();

        // Create dpkg .list that includes this module
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();
        fs::write(
            dpkg_dir.join("linux-image-5.10.0.list"),
            "/lib/modules/5.10.0/kernel/drivers/e1000.ko\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = KernelIntegrityCheck;
        let findings = check.run(&cfs);

        // Should have no unowned or rootkit findings for e1000
        let e1000_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("e1000"))
            .collect();
        assert!(
            e1000_findings.is_empty(),
            "Owned module should not produce findings"
        );
    }

    #[test]
    fn test_detects_module_in_nonstandard_location() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create /lib/modules so the main check runs
        fs::create_dir_all(root.join("lib/modules")).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        // Plant a module in /tmp
        let tmp_dir = root.join("tmp");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join("evil.ko"), b"malicious module").unwrap();

        let cfs = setup_container(&tmp);
        let check = KernelIntegrityCheck;
        let findings = check.run(&cfs);

        let nonstandard = findings
            .iter()
            .find(|f| f.title.contains("non-standard location") && f.title.contains("evil.ko"));
        assert!(
            nonstandard.is_some(),
            "Should detect module in non-standard location"
        );
        assert_eq!(nonstandard.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detects_hidden_proc_module() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create /lib/modules with only one legitimate module
        let kernel_dir = root.join("lib/modules/5.10.0/kernel");
        fs::create_dir_all(&kernel_dir).unwrap();
        fs::write(kernel_dir.join("e1000.ko"), b"legit").unwrap();

        fs::create_dir_all(root.join("var/lib/dpkg/info")).unwrap();

        // Create /proc/modules with a module that has no on-disk file
        let proc_dir = root.join("proc");
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("modules"),
            "e1000 12345 0 - Live 0xffffffff00000000\n\
             hidden_rootkit 4096 0 - Live 0xffffffff10000000\n",
        )
        .unwrap();

        let cfs = setup_container(&tmp);
        let check = KernelIntegrityCheck;
        let findings = check.run(&cfs);

        let hidden = findings
            .iter()
            .find(|f| f.title.contains("Potentially hidden kernel module: hidden_rootkit"));
        assert!(
            hidden.is_some(),
            "Should detect loaded module with no on-disk file"
        );
        assert_eq!(hidden.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_strip_module_extensions() {
        assert_eq!(strip_module_extensions("e1000.ko"), "e1000");
        assert_eq!(strip_module_extensions("btrfs.ko.xz"), "btrfs");
        assert_eq!(strip_module_extensions("zfs.ko.zst"), "zfs");
        assert_eq!(strip_module_extensions("ext4.ko.gz"), "ext4");
        assert_eq!(strip_module_extensions("noext"), "noext");
    }
}
