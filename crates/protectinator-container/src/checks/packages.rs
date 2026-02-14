//! Package freshness and vulnerability checks
//!
//! Checks container packages using multiple methods:
//! 1. Scans for security-sensitive packages with known vulnerability history
//! 2. Checks for available security updates from apt lists
//! 3. Checks dpkg health (broken packages)
//!
//! Note: This is heuristic-based — it checks for known-risky packages
//! and pending security updates rather than querying a live CVE database.

use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};

/// Installed package info parsed from dpkg/rpm databases
#[derive(Debug)]
struct InstalledPackage {
    name: String,
    version: String,
    status: String,
}

/// Security-sensitive packages that frequently have CVEs.
/// Format: (package_name_prefix, description, remediation)
const SECURITY_SENSITIVE_PACKAGES: &[(&str, &str, &str)] = &[
    // Crypto / TLS
    (
        "openssl",
        "OpenSSL has frequent security updates. Ensure this is the latest patched version.",
        "Run: apt update && apt install --only-upgrade openssl libssl3",
    ),
    (
        "libssl1.1",
        "OpenSSL 1.1 branch is nearing end-of-life. Consider migrating to OpenSSL 3.x (libssl3).",
        "Upgrade to a distro version that ships OpenSSL 3.x, or install libssl3",
    ),
    (
        "gnutls",
        "GnuTLS has had multiple CVEs. Ensure this is the latest patched version.",
        "Run: apt update && apt install --only-upgrade libgnutls30",
    ),
    // Privilege escalation targets
    (
        "sudo",
        "sudo has had privilege escalation CVEs (e.g., CVE-2023-22809, CVE-2021-3156). Keep updated.",
        "Run: apt update && apt install --only-upgrade sudo",
    ),
    (
        "polkit",
        "polkit has had privilege escalation CVEs (e.g., CVE-2021-4034 PwnKit). Keep updated.",
        "Run: apt update && apt install --only-upgrade policykit-1",
    ),
    (
        "pkexec",
        "pkexec (polkit) has had critical privilege escalation vulnerabilities.",
        "Run: apt update && apt install --only-upgrade policykit-1",
    ),
    // Network services
    (
        "openssh-server",
        "OpenSSH server is network-facing and security-critical. Keep updated.",
        "Run: apt update && apt install --only-upgrade openssh-server",
    ),
    (
        "nginx",
        "nginx is network-facing. Ensure it's patched against known HTTP vulnerabilities.",
        "Run: apt update && apt install --only-upgrade nginx",
    ),
    (
        "apache2",
        "Apache is network-facing. Ensure it's patched against known HTTP vulnerabilities.",
        "Run: apt update && apt install --only-upgrade apache2",
    ),
    // Interpreters (supply chain risk)
    (
        "python3.",
        "Python runtime — ensure it receives security patches.",
        "Run: apt update && apt install --only-upgrade python3",
    ),
    // System libraries
    (
        "libc6",
        "glibc is critical system infrastructure. Vulnerabilities here affect everything.",
        "Run: apt update && apt install --only-upgrade libc6",
    ),
    (
        "systemd",
        "systemd is PID 1 and manages services. Keep updated.",
        "Run: apt update && apt install --only-upgrade systemd",
    ),
    (
        "curl",
        "curl has had multiple buffer overflow CVEs. Keep updated.",
        "Run: apt update && apt install --only-upgrade curl libcurl4",
    ),
    (
        "libcurl",
        "libcurl has had multiple buffer overflow CVEs. Keep updated.",
        "Run: apt update && apt install --only-upgrade libcurl4",
    ),
];

/// Check for package-related security issues
pub struct PackageCheck;

impl ContainerCheck for PackageCheck {
    fn id(&self) -> &str {
        "container-packages"
    }

    fn name(&self) -> &str {
        "Package Security Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Try Debian/Ubuntu (dpkg)
        if fs.exists("/var/lib/dpkg/status") {
            let packages = parse_dpkg_status(fs);

            // Report package count as info
            let installed_count = packages
                .iter()
                .filter(|p| p.status.contains("installed"))
                .count();
            findings.push(Finding::new(
                "container-packages-count",
                format!("{} packages installed", installed_count),
                format!(
                    "{} packages installed in container. Fewer packages = smaller attack surface.",
                    installed_count
                ),
                Severity::Info,
                FindingSource::Hardening {
                    check_id: "container-packages-count".to_string(),
                    category: "packages".to_string(),
                },
            ));

            check_security_sensitive(&packages, &mut findings);
            check_pending_security_updates(fs, &mut findings);
            check_dpkg_health(fs, &packages, &mut findings);
        }

        // Try RPM-based (check for rpm database)
        if fs.exists("/var/lib/rpm") {
            findings.push(Finding::new(
                "container-packages-rpm",
                "RPM-based package database detected",
                "RPM package database found but detailed parsing is not yet implemented. \
                 Manual review recommended: run 'rpm -qa --last' inside the container.",
                Severity::Info,
                FindingSource::Hardening {
                    check_id: "container-packages-rpm".to_string(),
                    category: "packages".to_string(),
                },
            ));
        }

        // Check for no package manager
        if !fs.exists("/var/lib/dpkg/status") && !fs.exists("/var/lib/rpm") {
            findings.push(Finding::new(
                "container-packages-none",
                "No recognized package manager database found",
                "Could not find dpkg or rpm package databases. Package auditing is not possible.",
                Severity::Info,
                FindingSource::Hardening {
                    check_id: "container-packages-none".to_string(),
                    category: "packages".to_string(),
                },
            ));
        }

        findings
    }
}

/// Parse the dpkg status file to list installed packages
fn parse_dpkg_status(fs: &ContainerFs) -> Vec<InstalledPackage> {
    let content = match fs.read_to_string("/var/lib/dpkg/status") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut packages = Vec::new();
    let mut current_name = String::new();
    let mut current_version = String::new();
    let mut current_status = String::new();

    for line in content.lines() {
        if line.is_empty() {
            if !current_name.is_empty() {
                packages.push(InstalledPackage {
                    name: std::mem::take(&mut current_name),
                    version: std::mem::take(&mut current_version),
                    status: std::mem::take(&mut current_status),
                });
            }
            continue;
        }

        if let Some(name) = line.strip_prefix("Package: ") {
            current_name = name.to_string();
        } else if let Some(version) = line.strip_prefix("Version: ") {
            current_version = version.to_string();
        } else if let Some(status) = line.strip_prefix("Status: ") {
            current_status = status.to_string();
        }
    }

    // Don't forget the last entry
    if !current_name.is_empty() {
        packages.push(InstalledPackage {
            name: current_name,
            version: current_version,
            status: current_status,
        });
    }

    packages
}

/// Check installed packages against the security-sensitive list
fn check_security_sensitive(packages: &[InstalledPackage], findings: &mut Vec<Finding>) {
    for pkg in packages {
        if !pkg.status.contains("installed") {
            continue;
        }

        for (name_prefix, description, remediation) in SECURITY_SENSITIVE_PACKAGES {
            if pkg.name == *name_prefix || pkg.name.starts_with(name_prefix) {
                findings.push(
                    Finding::new(
                        format!("container-pkg-{}", pkg.name),
                        format!(
                            "Security-sensitive package: {} ({})",
                            pkg.name, pkg.version
                        ),
                        description.to_string(),
                        Severity::Info,
                        FindingSource::Hardening {
                            check_id: format!("container-pkg-{}", pkg.name),
                            category: "packages".to_string(),
                        },
                    )
                    .with_resource(format!("{}={}", pkg.name, pkg.version))
                    .with_remediation(remediation.to_string()),
                );
                break; // Only match once per package
            }
        }
    }
}

/// Check if there are pending security updates by examining apt lists
fn check_pending_security_updates(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    // Check if apt lists exist at all (indicates apt update has been run)
    let lists_dir = "/var/lib/apt/lists";
    let has_lists = fs
        .read_dir(lists_dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);

    if !has_lists {
        findings.push(
            Finding::new(
                "container-apt-no-lists",
                "apt package lists are empty — updates may not have been checked",
                "The container has no apt package list cache. This means 'apt update' has \
                 either never been run or the cache was cleaned. The container may have \
                 unpatched security vulnerabilities.",
                Severity::Medium,
                FindingSource::Hardening {
                    check_id: "container-apt-no-lists".to_string(),
                    category: "packages".to_string(),
                },
            )
            .with_remediation("Run 'apt update && apt upgrade' inside the container"),
        );
        return;
    }

    // Check for security-specific list files
    let has_security_lists = fs
        .read_dir(lists_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.contains("security") || name.contains("Security")
                })
        })
        .unwrap_or(false);

    if !has_security_lists {
        findings.push(
            Finding::new(
                "container-apt-no-security",
                "No security repository configured",
                "The container's apt sources do not appear to include a security repository. \
                 Security updates may not be available.",
                Severity::Medium,
                FindingSource::Hardening {
                    check_id: "container-apt-no-security".to_string(),
                    category: "packages".to_string(),
                },
            )
            .with_remediation(
                "Add the security repository to /etc/apt/sources.list \
                 (e.g., 'deb http://security.debian.org/debian-security bookworm-security main')",
            ),
        );
    }

    // Check apt update freshness by looking at list file modification times
    if let Ok(entries) = fs.read_dir(lists_dir) {
        let mut newest_mtime: Option<std::time::SystemTime> = None;
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    newest_mtime = Some(match newest_mtime {
                        Some(prev) => std::cmp::max(prev, mtime),
                        None => mtime,
                    });
                }
            }
        }

        if let Some(mtime) = newest_mtime {
            let age = std::time::SystemTime::now()
                .duration_since(mtime)
                .unwrap_or_default();
            let days = age.as_secs() / 86400;

            if days > 90 {
                findings.push(
                    Finding::new(
                        "container-apt-stale",
                        format!(
                            "Package lists are {} days old — security updates may be pending",
                            days
                        ),
                        format!(
                            "The apt package lists haven't been refreshed in {} days. \
                             Security patches released since then are not installed.",
                            days
                        ),
                        Severity::High,
                        FindingSource::Hardening {
                            check_id: "container-apt-stale".to_string(),
                            category: "packages".to_string(),
                        },
                    )
                    .with_remediation(
                        "Run 'apt update && apt upgrade' inside the container to apply security patches",
                    ),
                );
            } else if days > 30 {
                findings.push(
                    Finding::new(
                        "container-apt-aging",
                        format!(
                            "Package lists are {} days old — consider updating",
                            days
                        ),
                        format!(
                            "The apt package lists are {} days old. Recent security patches may not be installed.",
                            days
                        ),
                        Severity::Medium,
                        FindingSource::Hardening {
                            check_id: "container-apt-aging".to_string(),
                            category: "packages".to_string(),
                        },
                    )
                    .with_remediation(
                        "Run 'apt update && apt upgrade' inside the container",
                    ),
                );
            }
        }
    }
}

/// Check dpkg health — e.g., packages in half-installed state
fn check_dpkg_health(
    _fs: &ContainerFs,
    packages: &[InstalledPackage],
    findings: &mut Vec<Finding>,
) {
    let broken: Vec<_> = packages
        .iter()
        .filter(|p| {
            p.status.contains("half-installed")
                || p.status.contains("half-configured")
                || p.status.contains("unpacked")
        })
        .collect();

    if !broken.is_empty() {
        let names: Vec<_> = broken.iter().map(|p| p.name.as_str()).collect();
        findings.push(
            Finding::new(
                "container-dpkg-broken",
                format!("{} package(s) in broken state", broken.len()),
                format!(
                    "The following packages are not fully installed: {}. \
                     This may indicate interrupted updates or package manager issues.",
                    names.join(", ")
                ),
                Severity::Medium,
                FindingSource::Hardening {
                    check_id: "container-dpkg-broken".to_string(),
                    category: "packages".to_string(),
                },
            )
            .with_remediation(
                "Run 'dpkg --configure -a' inside the container to fix broken packages",
            ),
        );
    }
}
