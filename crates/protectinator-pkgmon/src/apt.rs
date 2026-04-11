//! apt/dpkg binary integrity checks
//!
//! Verifies system binaries against dpkg md5sums manifests and audits
//! package source configuration for security issues.

use crate::scanner::PkgMonCheck;
use crate::types::{PackageManager, PkgMonContext};
use md5::{Digest, Md5};
use protectinator_core::{Finding, FindingSource, Severity};
use rayon::prelude::*;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use tracing::debug;

/// Critical filesystem paths — binaries here get Critical severity
const CRITICAL_BIN_PATHS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"];

/// Library paths get High severity
const CRITICAL_LIB_PATHS: &[&str] = &["/usr/lib/", "/lib/"];

/// All critical prefixes for filtering
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
}

/// apt binary integrity verification via dpkg md5sums
pub struct AptIntegrityCheck;

impl PkgMonCheck for AptIntegrityCheck {
    fn name(&self) -> &str {
        "apt-binary-integrity"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Apt
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let root = &ctx.config.root;
        let dpkg_info = root.join("var/lib/dpkg/info");

        let entries = match std::fs::read_dir(&dpkg_info) {
            Ok(e) => e,
            Err(e) => {
                debug!("Cannot read dpkg info directory: {}", e);
                return Vec::new();
            }
        };

        // Collect conffiles to exclude
        let conffiles = collect_conffiles(&dpkg_info);

        // Parse all md5sums entries for critical paths
        let mut md5_entries: Vec<Md5Entry> = Vec::new();

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.ends_with(".md5sums") {
                continue;
            }

            let package_name = name_str
                .trim_end_matches(".md5sums")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string();

            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Format: "<md5hex>  <filepath>" (two spaces)
                let Some((hash, path)) = line.split_once("  ") else {
                    continue;
                };

                let file_path = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/{}", path)
                };

                if !ALL_CRITICAL_PREFIXES.iter().any(|p| file_path.starts_with(p)) {
                    continue;
                }

                if conffiles.contains(&file_path) {
                    continue;
                }

                md5_entries.push(Md5Entry {
                    expected_hash: hash.to_string(),
                    file_path,
                    package_name: package_name.clone(),
                });
            }
        }

        debug!(
            "apt binary integrity: checking {} files in critical paths",
            md5_entries.len()
        );

        // Parallel hash verification
        md5_entries
            .par_iter()
            .filter_map(|entry| check_binary(root, entry))
            .collect()
    }
}

/// Collect conffiles to exclude from integrity checks
fn collect_conffiles(dpkg_info: &Path) -> HashSet<String> {
    let mut conffiles = HashSet::new();

    let entries = match std::fs::read_dir(dpkg_info) {
        Ok(e) => e,
        Err(_) => return conffiles,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().ends_with(".conffiles") {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
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

/// Verify a single binary's MD5 hash
fn check_binary(root: &Path, entry: &Md5Entry) -> Option<Finding> {
    let host_path = root.join(entry.file_path.trim_start_matches('/'));

    if !host_path.exists() {
        return None;
    }

    let mut file = std::fs::File::open(&host_path).ok()?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 8192];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return None,
        }
    }

    let actual_hash = format!("{:x}", hasher.finalize());

    if actual_hash == entry.expected_hash {
        return None;
    }

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
            "pkgmon-apt-integrity",
            format!("Tampered binary: {}", entry.file_path),
            format!(
                "File '{}' from package '{}' has unexpected MD5 hash. \
                 Expected: {}, Actual: {}. This may indicate the binary \
                 has been modified or replaced.",
                entry.file_path, entry.package_name, entry.expected_hash, actual_hash
            ),
            severity,
            FindingSource::PackageMonitor {
                package_manager: "apt".to_string(),
                check_category: "binary_integrity".to_string(),
            },
        )
        .with_resource(&entry.file_path)
        .with_remediation(format!(
            "Verify package: dpkg --verify {}. Reinstall if compromised: apt install --reinstall {}",
            entry.package_name, entry.package_name
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

/// apt source configuration audit
///
/// Checks /etc/apt/sources.list and /etc/apt/sources.list.d/ for:
/// - HTTP (non-HTTPS) transport
/// - Unsigned repositories (missing signed-by)
/// - Third-party PPAs
pub struct AptSourceAudit;

impl PkgMonCheck for AptSourceAudit {
    fn name(&self) -> &str {
        "apt-source-audit"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Apt
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let root = &ctx.config.root;
        let mut findings = Vec::new();

        // Collect all source lines from sources.list and sources.list.d/
        let sources_files = collect_sources_files(root);

        for (file_path, content) in &sources_files {
            for (line_num, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // DEB822 format (.sources files)
                if file_path.ends_with(".sources") {
                    findings.extend(audit_deb822_line(file_path, line, line_num + 1));
                    continue;
                }

                // Traditional one-line format
                findings.extend(audit_source_line(file_path, line, line_num + 1));
            }
        }

        // Check for unauthorized GPG keys
        findings.extend(audit_gpg_keys(root));

        findings
    }
}

/// Collect all apt source files
fn collect_sources_files(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();

    // Main sources.list
    let sources_list = root.join("etc/apt/sources.list");
    if let Ok(content) = std::fs::read_to_string(&sources_list) {
        files.push((sources_list.to_string_lossy().to_string(), content));
    }

    // sources.list.d/ directory
    let sources_dir = root.join("etc/apt/sources.list.d");
    if let Ok(entries) = std::fs::read_dir(&sources_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".list") || name_str.ends_with(".sources") {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    files.push((entry.path().to_string_lossy().to_string(), content));
                }
            }
        }
    }

    files
}

/// Official Debian/Ubuntu mirror hostname patterns
const OFFICIAL_MIRRORS: &[&str] = &[
    "deb.debian.org",
    "security.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "changelogs.ubuntu.com",
    "apt.kubernetes.io",
    "packages.microsoft.com",
    "download.docker.com",
    "packages.grafana.com",
];

/// Audit a traditional one-line apt source entry
fn audit_source_line(file_path: &str, line: &str, line_num: usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Parse: deb [options] uri suite [component...]
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return findings;
    }

    let (_deb_type, rest) = match parts[0] {
        "deb" | "deb-src" => (parts[0], &parts[1..]),
        _ => return findings,
    };

    // Find the URI (may have [options] before it)
    let uri_idx = rest.iter().position(|p| !p.starts_with('[') && !p.ends_with(']'));
    let uri = match uri_idx {
        Some(i) => rest[i],
        None => return findings,
    };

    // Check for HTTP transport
    if uri.starts_with("http://") {
        findings.push(
            Finding::new(
                "pkgmon-apt-http-source",
                format!("Insecure HTTP apt source: {}", uri),
                format!(
                    "{}:{}: Repository uses unencrypted HTTP transport. \
                     An attacker could intercept or modify packages in transit.",
                    file_path, line_num
                ),
                Severity::High,
                FindingSource::PackageMonitor {
                    package_manager: "apt".to_string(),
                    check_category: "source_audit".to_string(),
                },
            )
            .with_resource(file_path)
            .with_remediation("Change http:// to https:// in the repository URL"),
        );
    }

    // Check for missing signed-by in options
    let options_str = line;
    let has_signed_by = options_str.contains("signed-by=");
    let has_trusted_yes = options_str.contains("trusted=yes");

    if has_trusted_yes {
        findings.push(
            Finding::new(
                "pkgmon-apt-trusted-repo",
                format!("Trusted=yes bypasses signature verification: {}", uri),
                format!(
                    "{}:{}: Repository has trusted=yes which disables all GPG \
                     signature verification. Any package from this source will be \
                     installed without verification.",
                    file_path, line_num
                ),
                Severity::Critical,
                FindingSource::PackageMonitor {
                    package_manager: "apt".to_string(),
                    check_category: "source_audit".to_string(),
                },
            )
            .with_resource(file_path)
            .with_remediation("Remove trusted=yes and add proper GPG key with signed-by="),
        );
    }

    // Check for third-party sources
    if !is_official_mirror(uri) && !has_signed_by {
        findings.push(
            Finding::new(
                "pkgmon-apt-unsigned-thirdparty",
                format!("Third-party repo without signed-by: {}", uri),
                format!(
                    "{}:{}: Third-party repository does not use signed-by= option. \
                     This means any key in the global apt keyring can sign packages \
                     for this repository.",
                    file_path, line_num
                ),
                Severity::Medium,
                FindingSource::PackageMonitor {
                    package_manager: "apt".to_string(),
                    check_category: "source_audit".to_string(),
                },
            )
            .with_resource(file_path)
            .with_remediation(
                "Add [signed-by=/path/to/key.gpg] to restrict which key can sign this repo's packages",
            ),
        );
    }

    findings
}

/// Audit a DEB822 format source entry
fn audit_deb822_line(file_path: &str, line: &str, line_num: usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    // DEB822 format: "URIs: http://..."
    if line.starts_with("URIs:") || line.starts_with("URIs :") {
        let uri = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
        if uri.starts_with("http://") {
            findings.push(
                Finding::new(
                    "pkgmon-apt-http-source",
                    format!("Insecure HTTP apt source: {}", uri),
                    format!(
                        "{}:{}: Repository uses unencrypted HTTP transport.",
                        file_path, line_num
                    ),
                    Severity::High,
                    FindingSource::PackageMonitor {
                        package_manager: "apt".to_string(),
                        check_category: "source_audit".to_string(),
                    },
                )
                .with_resource(file_path)
                .with_remediation("Change http:// to https:// in the URIs field"),
            );
        }
    }

    if line.starts_with("Trusted:") && line.contains("yes") {
        findings.push(
            Finding::new(
                "pkgmon-apt-trusted-repo",
                "Trusted: yes bypasses signature verification",
                format!(
                    "{}:{}: Repository has Trusted: yes which disables GPG verification.",
                    file_path, line_num
                ),
                Severity::Critical,
                FindingSource::PackageMonitor {
                    package_manager: "apt".to_string(),
                    check_category: "source_audit".to_string(),
                },
            )
            .with_resource(file_path)
            .with_remediation("Remove Trusted: yes and add proper Signed-By field"),
        );
    }

    findings
}

/// Check if a URI points to an official mirror
fn is_official_mirror(uri: &str) -> bool {
    let uri_lower = uri.to_lowercase();
    OFFICIAL_MIRRORS.iter().any(|m| uri_lower.contains(m))
}

/// Audit GPG keys in /etc/apt/trusted.gpg.d/
fn audit_gpg_keys(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for legacy trusted.gpg (deprecated, should use trusted.gpg.d/ with signed-by)
    let legacy_keyring = root.join("etc/apt/trusted.gpg");
    if legacy_keyring.exists() {
        if let Ok(meta) = std::fs::metadata(&legacy_keyring) {
            if meta.len() > 0 {
                findings.push(
                    Finding::new(
                        "pkgmon-apt-legacy-keyring",
                        "Legacy apt keyring in use (trusted.gpg)",
                        "The legacy /etc/apt/trusted.gpg keyring is non-empty. Keys in this \
                         file can sign packages for ANY repository. Use /etc/apt/trusted.gpg.d/ \
                         with per-repo signed-by= instead.",
                        Severity::Medium,
                        FindingSource::PackageMonitor {
                            package_manager: "apt".to_string(),
                            check_category: "source_audit".to_string(),
                        },
                    )
                    .with_resource("/etc/apt/trusted.gpg")
                    .with_remediation(
                        "Migrate keys to /etc/apt/trusted.gpg.d/ and use signed-by= in sources",
                    ),
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_dpkg(tmp: &TempDir) -> PathBuf {
        let root = tmp.path().to_path_buf();
        let dpkg_dir = root.join("var/lib/dpkg/info");
        fs::create_dir_all(&dpkg_dir).unwrap();
        // Also create dpkg/status so manager is detected
        fs::write(root.join("var/lib/dpkg/status"), "").unwrap();
        root
    }

    #[test]
    fn detects_tampered_binary() {
        let tmp = TempDir::new().unwrap();
        let root = setup_dpkg(&tmp);

        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin).unwrap();
        fs::write(usr_bin.join("testbin"), b"actual content").unwrap();

        // Compute hash of different content
        let mut hasher = Md5::new();
        hasher.update(b"expected content");
        let expected = format!("{:x}", hasher.finalize());

        let dpkg_info = root.join("var/lib/dpkg/info");
        fs::write(
            dpkg_info.join("testpkg.md5sums"),
            format!("{}  usr/bin/testbin\n", expected),
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let check = AptIntegrityCheck;
        let findings = check.check(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("testbin"));
    }

    #[test]
    fn clean_binary_no_findings() {
        let tmp = TempDir::new().unwrap();
        let root = setup_dpkg(&tmp);

        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin).unwrap();
        let content = b"clean content";
        fs::write(usr_bin.join("goodbin"), content).unwrap();

        let mut hasher = Md5::new();
        hasher.update(content);
        let correct = format!("{:x}", hasher.finalize());

        let dpkg_info = root.join("var/lib/dpkg/info");
        fs::write(
            dpkg_info.join("goodpkg.md5sums"),
            format!("{}  usr/bin/goodbin\n", correct),
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptIntegrityCheck.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_conffiles() {
        let tmp = TempDir::new().unwrap();
        let root = setup_dpkg(&tmp);

        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin).unwrap();
        fs::write(usr_bin.join("confbin"), b"modified").unwrap();

        let dpkg_info = root.join("var/lib/dpkg/info");
        fs::write(
            dpkg_info.join("pkg.md5sums"),
            "deadbeefdeadbeefdeadbeefdeadbeef  usr/bin/confbin\n",
        )
        .unwrap();
        fs::write(dpkg_info.join("pkg.conffiles"), "/usr/bin/confbin\n").unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptIntegrityCheck.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_missing_files() {
        let tmp = TempDir::new().unwrap();
        let root = setup_dpkg(&tmp);

        let dpkg_info = root.join("var/lib/dpkg/info");
        fs::write(
            dpkg_info.join("missing.md5sums"),
            "deadbeefdeadbeefdeadbeefdeadbeef  usr/bin/nonexistent\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptIntegrityCheck.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn lib_path_high_severity() {
        let tmp = TempDir::new().unwrap();
        let root = setup_dpkg(&tmp);

        let usr_lib = root.join("usr/lib");
        fs::create_dir_all(&usr_lib).unwrap();
        fs::write(usr_lib.join("libtest.so"), b"tampered").unwrap();

        let dpkg_info = root.join("var/lib/dpkg/info");
        fs::write(
            dpkg_info.join("libpkg.md5sums"),
            "0000000000000000000000000000dead  usr/lib/libtest.so\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptIntegrityCheck.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn handles_arch_qualified_package_names() {
        let tmp = TempDir::new().unwrap();
        let root = setup_dpkg(&tmp);

        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin).unwrap();
        fs::write(usr_bin.join("archbin"), b"tampered").unwrap();

        let dpkg_info = root.join("var/lib/dpkg/info");
        fs::write(
            dpkg_info.join("coreutils:amd64.md5sums"),
            "0000000000000000000000000000dead  usr/bin/archbin\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptIntegrityCheck.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("coreutils"));
    }

    // Source audit tests

    fn setup_sources(tmp: &TempDir) -> PathBuf {
        let root = tmp.path().to_path_buf();
        fs::create_dir_all(root.join("etc/apt/sources.list.d")).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        fs::write(root.join("var/lib/dpkg/status"), "").unwrap();
        root
    }

    #[test]
    fn detects_http_source() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list"),
            "deb http://example.com/repo stable main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let http_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-http-source")
            .collect();
        assert_eq!(http_findings.len(), 1);
        assert_eq!(http_findings[0].severity, Severity::High);
    }

    #[test]
    fn https_source_no_finding() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list"),
            "deb [signed-by=/usr/share/keyrings/key.gpg] https://example.com/repo stable main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let http_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-http-source")
            .collect();
        assert!(http_findings.is_empty());
    }

    #[test]
    fn detects_trusted_yes() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list"),
            "deb [trusted=yes] https://sketchy.com/repo stable main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let trusted_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-trusted-repo")
            .collect();
        assert_eq!(trusted_findings.len(), 1);
        assert_eq!(trusted_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_unsigned_thirdparty() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list"),
            "deb https://thirdparty.example.com/repo stable main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let unsigned_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-unsigned-thirdparty")
            .collect();
        assert_eq!(unsigned_findings.len(), 1);
    }

    #[test]
    fn official_mirror_no_unsigned_finding() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list"),
            "deb https://deb.debian.org/debian bookworm main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let unsigned_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-unsigned-thirdparty")
            .collect();
        assert!(unsigned_findings.is_empty());
    }

    #[test]
    fn skips_comments_and_empty_lines() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list"),
            "# This is a comment\n\n# deb http://old.example.com/repo stable main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn reads_sources_list_d() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        // Don't write main sources.list, only sources.list.d/
        fs::write(
            root.join("etc/apt/sources.list.d/sketchy.list"),
            "deb http://sketchy.example.com/repo stable main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_legacy_keyring() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        let apt_dir = root.join("etc/apt");
        fs::create_dir_all(&apt_dir).unwrap();
        fs::write(apt_dir.join("trusted.gpg"), b"some key data").unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let keyring_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-legacy-keyring")
            .collect();
        assert_eq!(keyring_findings.len(), 1);
    }

    #[test]
    fn deb822_detects_http() {
        let tmp = TempDir::new().unwrap();
        let root = setup_sources(&tmp);

        fs::write(
            root.join("etc/apt/sources.list.d/example.sources"),
            "Types: deb\nURIs: http://example.com/repo\nSuites: stable\nComponents: main\n",
        )
        .unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.clone(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = AptSourceAudit.check(&ctx);

        let http_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-apt-http-source")
            .collect();
        assert_eq!(http_findings.len(), 1);
    }
}
