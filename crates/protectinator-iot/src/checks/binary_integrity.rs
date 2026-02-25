//! Binary integrity verification via dpkg md5sums
//!
//! Reads `/var/lib/dpkg/info/*.md5sums`, computes MD5 of each referenced
//! file in critical system paths, and flags mismatches indicating tampered
//! binaries.

use crate::checks::IotCheck;
use md5::{Digest, Md5};
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{FileChangeType, Finding, FindingSource, Severity};
use rayon::prelude::*;
use std::collections::HashSet;
use std::io::Read;
use tracing::debug;

/// Critical filesystem paths to verify (in order of severity)
const CRITICAL_BIN_PATHS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"];
const CRITICAL_LIB_PATHS: &[&str] = &["/usr/lib/", "/lib/"];

/// All critical paths combined for filtering
const ALL_CRITICAL_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
];

/// A file entry parsed from a dpkg md5sums file
struct Md5Entry {
    expected_hash: String,
    file_path: String,
    package_name: String,
    md5sums_file: String,
}

/// Binary integrity check via dpkg md5sums verification
pub struct BinaryIntegrityCheck;

impl IotCheck for BinaryIntegrityCheck {
    fn id(&self) -> &str {
        "iot-binary-integrity"
    }

    fn name(&self) -> &str {
        "Binary Integrity Check (dpkg md5sums)"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let dpkg_info_dir = "/var/lib/dpkg/info";

        let entries = match fs.read_dir(dpkg_info_dir) {
            Ok(e) => e,
            Err(_) => {
                debug!("Cannot read dpkg info directory, skipping binary integrity check");
                return Vec::new();
            }
        };

        // Collect all conffiles to exclude config files from verification
        let conffiles = collect_conffiles(fs, dpkg_info_dir);

        // Collect all md5sum entries for critical paths
        let mut md5_entries: Vec<Md5Entry> = Vec::new();

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.ends_with(".md5sums") {
                continue;
            }

            let package_name = name_str.trim_end_matches(".md5sums").to_string();
            // Handle architecture-qualified names like "coreutils:arm64.md5sums"
            let package_name = package_name.split(':').next().unwrap_or(&package_name).to_string();

            let md5sums_path = format!("{}/{}", dpkg_info_dir, name_str);
            let content = match fs.read_to_string(&md5sums_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Format: "<md5hex>  <filepath>" (two spaces separator)
                let Some((hash, path)) = line.split_once("  ") else {
                    continue;
                };

                let file_path = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/{}", path)
                };

                // Only check files in critical paths
                if !ALL_CRITICAL_PREFIXES.iter().any(|p| file_path.starts_with(p)) {
                    continue;
                }

                // Skip config files
                if conffiles.contains(&file_path) {
                    continue;
                }

                md5_entries.push(Md5Entry {
                    expected_hash: hash.to_string(),
                    file_path,
                    package_name: package_name.clone(),
                    md5sums_file: md5sums_path.clone(),
                });
            }
        }

        debug!(
            "Binary integrity: checking {} files across critical paths",
            md5_entries.len()
        );

        // Use rayon for parallel hash computation
        let findings: Vec<Finding> = md5_entries
            .par_iter()
            .filter_map(|entry| check_single_file(fs, entry))
            .collect();

        findings
    }
}

/// Collect all conffiles from dpkg info to exclude from verification
fn collect_conffiles(fs: &ContainerFs, dpkg_info_dir: &str) -> HashSet<String> {
    let mut conffiles = HashSet::new();

    let entries = match fs.read_dir(dpkg_info_dir) {
        Ok(e) => e,
        Err(_) => return conffiles,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.ends_with(".conffiles") {
            continue;
        }

        let path = format!("{}/{}", dpkg_info_dir, name_str);
        if let Ok(content) = fs.read_to_string(&path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    conffiles.insert(line.to_string());
                }
            }
        }
    }

    conffiles
}

/// Check a single file's MD5 hash against the expected value
fn check_single_file(fs: &ContainerFs, entry: &Md5Entry) -> Option<Finding> {
    let host_path = fs.resolve(&entry.file_path);

    // Skip files that don't exist (package removed but info remains)
    if !host_path.exists() {
        return None;
    }

    // Compute MD5 hash
    let mut file = match std::fs::File::open(&host_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut hasher = Md5::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return None,
        };
        hasher.update(&buffer[..bytes_read]);
    }

    let actual_hash = format!("{:x}", hasher.finalize());

    if actual_hash == entry.expected_hash {
        return None;
    }

    // Determine severity based on path
    let severity = if CRITICAL_BIN_PATHS
        .iter()
        .any(|p| entry.file_path.starts_with(p))
    {
        Severity::Critical
    } else if CRITICAL_LIB_PATHS
        .iter()
        .any(|p| entry.file_path.starts_with(p))
    {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(
        Finding::new(
            "iot-binary-integrity",
            format!("Tampered binary: {}", entry.file_path),
            format!(
                "File '{}' from package '{}' has unexpected MD5 hash. \
                 Expected: {}, Actual: {}. This may indicate the binary \
                 has been modified or replaced.",
                entry.file_path, entry.package_name, entry.expected_hash, actual_hash
            ),
            severity,
            FindingSource::FileIntegrity {
                baseline_path: entry.md5sums_file.clone(),
                change_type: FileChangeType::Modified,
            },
        )
        .with_resource(entry.file_path.clone())
        .with_remediation(format!(
            "Verify package: dpkg --verify {}",
            entry.package_name
        ))
        .with_metadata(
            "expected_hash",
            serde_json::Value::String(entry.expected_hash.clone()),
        )
        .with_metadata(
            "actual_hash",
            serde_json::Value::String(actual_hash),
        )
        .with_metadata(
            "package",
            serde_json::Value::String(entry.package_name.clone()),
        )
        .with_reference("https://attack.mitre.org/techniques/T1554/"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Create a ContainerFs rooted at a temp directory
    fn setup_container(tmp: &TempDir) -> ContainerFs {
        ContainerFs::new(tmp.path())
    }

    #[test]
    fn test_detects_tampered_binary() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create dpkg info directory with md5sums
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        // Create a binary to check
        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin).unwrap();
        let binary_path = usr_bin.join("testbin");
        fs::write(&binary_path, b"original content").unwrap();

        // Compute the MD5 of a *different* content to simulate tampering
        let mut hasher = Md5::new();
        hasher.update(b"expected content");
        let expected_hash = format!("{:x}", hasher.finalize());

        // Write md5sums file with wrong hash
        let md5sums_content = format!("{}  usr/bin/testbin\n", expected_hash);
        fs::write(dpkg_dir.join("testpkg.md5sums"), md5sums_content).unwrap();

        let cfs = setup_container(&tmp);
        let check = BinaryIntegrityCheck;
        let findings = check.run(&cfs);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("testbin"));
        assert!(findings[0].resource.as_ref().unwrap().contains("/usr/bin/testbin"));
    }

    #[test]
    fn test_clean_binary_no_finding() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create dpkg info directory
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        // Create binary with known content
        let usr_sbin = root.join("usr/sbin");
        fs::create_dir_all(&usr_sbin).unwrap();
        let content = b"clean binary content";
        fs::write(usr_sbin.join("goodbin"), content).unwrap();

        // Compute correct MD5
        let mut hasher = Md5::new();
        hasher.update(content);
        let correct_hash = format!("{:x}", hasher.finalize());

        let md5sums_content = format!("{}  usr/sbin/goodbin\n", correct_hash);
        fs::write(dpkg_dir.join("goodpkg.md5sums"), md5sums_content).unwrap();

        let cfs = setup_container(&tmp);
        let check = BinaryIntegrityCheck;
        let findings = check.run(&cfs);

        assert!(findings.is_empty(), "Clean binary should not produce findings");
    }

    #[test]
    fn test_skips_conffiles() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        // Create a file that's a conffile
        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin).unwrap();
        fs::write(usr_bin.join("confbin"), b"modified config").unwrap();

        // Write md5sums with wrong hash
        let md5sums_content = "0000000000000000000000000000dead  usr/bin/confbin\n";
        fs::write(dpkg_dir.join("confpkg.md5sums"), md5sums_content).unwrap();

        // Mark it as a conffile
        fs::write(dpkg_dir.join("confpkg.conffiles"), "/usr/bin/confbin\n").unwrap();

        let cfs = setup_container(&tmp);
        let check = BinaryIntegrityCheck;
        let findings = check.run(&cfs);

        assert!(findings.is_empty(), "Conffiles should be excluded from integrity checks");
    }

    #[test]
    fn test_skips_missing_files() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        // md5sums references a file that doesn't exist
        let md5sums_content = "deadbeefdeadbeefdeadbeefdeadbeef  usr/bin/nonexistent\n";
        fs::write(dpkg_dir.join("missing.md5sums"), md5sums_content).unwrap();

        let cfs = setup_container(&tmp);
        let check = BinaryIntegrityCheck;
        let findings = check.run(&cfs);

        assert!(findings.is_empty(), "Missing files should be skipped");
    }

    #[test]
    fn test_lib_path_gets_high_severity() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();

        // Create a library file
        let usr_lib = root.join("usr/lib");
        fs::create_dir_all(&usr_lib).unwrap();
        fs::write(usr_lib.join("libtest.so"), b"tampered library").unwrap();

        // Wrong hash
        let md5sums_content = "0000000000000000000000000000dead  usr/lib/libtest.so\n";
        fs::write(dpkg_dir.join("libpkg.md5sums"), md5sums_content).unwrap();

        let cfs = setup_container(&tmp);
        let check = BinaryIntegrityCheck;
        let findings = check.run(&cfs);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
