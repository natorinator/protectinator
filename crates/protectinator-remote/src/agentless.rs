//! Agentless remote scanning
//!
//! Gathers system data from remote hosts via SSH commands, writes it
//! to a temp directory structured as a filesystem, then runs the
//! existing container checks against it.

use crate::ssh;
use crate::types::{RemoteHost, RemoteScanResults, ScanMode};
use protectinator_container::filesystem::ContainerFs;
use protectinator_container::ContainerScanner;
use protectinator_container::types::{Container, ContainerRuntime, ContainerState, ContainerOsInfo};
use protectinator_core::{Finding, FindingSource};
use std::path::Path;
use tempfile::TempDir;
use tracing::{debug, info, warn};

/// Run an agentless scan against a remote host
pub fn scan(
    host: &RemoteHost,
    skip_vulnerability: bool,
) -> Result<RemoteScanResults, String> {
    info!("Starting agentless scan of {}", host.display_name());

    // Test connectivity first
    ssh::test_connection(host)?;

    // Gather data from remote host
    let tmp = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    gather_remote_data(host, tmp.path())?;

    // Run container checks against the gathered data
    let fs = ContainerFs::new(tmp.path());
    let os_info = fs.detect_os();

    let container = Container {
        name: host.display_name(),
        runtime: ContainerRuntime::Nspawn, // Reuse type — doesn't matter for scanning
        root_path: tmp.path().to_path_buf(),
        state: ContainerState::Running,
        os_info: os_info.clone(),
    };

    let scanner = ContainerScanner::new()
        .skip_vulnerability(skip_vulnerability);

    let mut results = scanner.scan(&container);

    // Re-wrap findings with Remote source instead of Container
    for finding in &mut results.scan_results.findings {
        if let FindingSource::Container { inner_source, .. } = &finding.source {
            finding.source = FindingSource::Remote {
                host: host.hostname.clone(),
                scan_mode: "agentless".to_string(),
                inner_source: inner_source.clone(),
            };
        }
    }

    // Gather additional IOC data that container checks don't cover
    let ioc_findings = gather_ioc_indicators(host);
    for mut finding in ioc_findings {
        finding.source = FindingSource::Remote {
            host: host.hostname.clone(),
            scan_mode: "agentless".to_string(),
            inner_source: Box::new(finding.source.clone()),
        };
        results.scan_results.add_finding(finding);
    }

    info!(
        "Agentless scan complete: {} findings for {}",
        results.scan_results.findings.len(),
        host.display_name()
    );

    Ok(RemoteScanResults {
        host: host.clone(),
        scan_mode: ScanMode::Agentless,
        scan_results: results.scan_results,
    })
}

/// Gather system data from a remote host and write to a temp directory
fn gather_remote_data(host: &RemoteHost, tmp: &Path) -> Result<(), String> {
    info!("Gathering system data from {}", host.display_name());

    // OS release
    if let Some(content) = ssh::read_remote_file(host, "/etc/os-release") {
        write_gathered(tmp, "etc/os-release", &content);
    }

    // dpkg status (Debian/Ubuntu)
    if let Some(content) = ssh::read_remote_file(host, "/var/lib/dpkg/status") {
        debug!("Gathered dpkg status ({} bytes)", content.len());
        write_gathered(tmp, "var/lib/dpkg/status", &content);
    }

    // apk installed database (Alpine)
    if let Some(content) = ssh::read_remote_file(host, "/lib/apk/db/installed") {
        debug!("Gathered apk database ({} bytes)", content.len());
        write_gathered(tmp, "lib/apk/db/installed", &content);
    }

    // Hostname
    if let Some(content) = ssh::read_remote_file(host, "/etc/hostname") {
        write_gathered(tmp, "etc/hostname", &content);
    }

    // passwd (for hardening checks — login shells, service accounts)
    if let Some(content) = ssh::read_remote_file(host, "/etc/passwd") {
        write_gathered(tmp, "etc/passwd", &content);
    }

    // shadow (permissions check — the check just looks at existence)
    let shadow_check = ssh::ssh_exec_optional(host, "stat -c '%a' /etc/shadow 2>/dev/null");
    if !shadow_check.trim().is_empty() {
        // Create a placeholder so the check sees the file exists
        write_gathered(tmp, "etc/shadow", "# placeholder for permissions check");
    }

    // SSH config (hardening)
    if let Some(content) = ssh::read_remote_file(host, "/etc/ssh/sshd_config") {
        write_gathered(tmp, "etc/ssh/sshd_config", &content);
    }

    // Cron jobs
    gather_cron_data(host, tmp);

    // Systemd units (persistence check)
    gather_systemd_data(host, tmp);

    // Shell profiles (persistence check)
    for profile in &["/etc/profile", "/etc/bash.bashrc", "/etc/environment"] {
        if let Some(content) = ssh::read_remote_file(host, profile) {
            write_gathered(tmp, &profile[1..], &content); // strip leading /
        }
    }

    // Kernel modules (rootkit check)
    let modules = ssh::ssh_exec_optional(host, "cat /proc/modules 2>/dev/null");
    if !modules.is_empty() {
        write_gathered(tmp, "proc/modules", &modules);
    }

    // SUID binaries — gather and create marker files
    gather_suid_data(host, tmp);

    // Apt lists directory (package freshness check)
    let apt_lists = ssh::ssh_exec_optional(
        host,
        "ls -1 /var/lib/apt/lists/ 2>/dev/null | head -20",
    );
    if !apt_lists.trim().is_empty() {
        let lists_dir = tmp.join("var/lib/apt/lists");
        std::fs::create_dir_all(&lists_dir).ok();
        // Create marker files so the freshness check sees non-empty dir
        for name in apt_lists.lines().take(5) {
            let name = name.trim();
            if !name.is_empty() {
                std::fs::write(lists_dir.join(name), "").ok();
            }
        }
    }

    info!("Data gathering complete");
    Ok(())
}

/// Gather cron entries from remote host
fn gather_cron_data(host: &RemoteHost, tmp: &Path) {
    let cron_dirs = &[
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ];

    for dir in cron_dirs {
        let listing = ssh::ssh_exec_optional(
            host,
            &format!(
                "for f in {}/*; do [ -f \"$f\" ] && echo \"---FILE:$f\" && cat \"$f\"; done 2>/dev/null",
                dir
            ),
        );

        if listing.is_empty() {
            continue;
        }

        let local_dir = &dir[1..]; // strip leading /
        let target_dir = tmp.join(local_dir);
        std::fs::create_dir_all(&target_dir).ok();

        let mut current_file: Option<String> = None;
        let mut current_content = String::new();

        for line in listing.lines() {
            if let Some(path) = line.strip_prefix("---FILE:") {
                // Write previous file
                if let Some(ref fname) = current_file {
                    let basename = Path::new(fname)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    std::fs::write(target_dir.join(basename), &current_content).ok();
                }
                current_file = Some(path.to_string());
                current_content.clear();
            } else {
                current_content.push_str(line);
                current_content.push('\n');
            }
        }

        // Write last file
        if let Some(ref fname) = current_file {
            let basename = Path::new(fname)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            std::fs::write(target_dir.join(basename), &current_content).ok();
        }
    }
}

/// Gather systemd unit files
fn gather_systemd_data(host: &RemoteHost, tmp: &Path) {
    let output = ssh::ssh_exec_optional(
        host,
        "find /etc/systemd/system -name '*.service' -o -name '*.timer' 2>/dev/null | head -50",
    );

    for path in output.lines() {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        if let Some(content) = ssh::read_remote_file(host, path) {
            let local_path = &path[1..]; // strip leading /
            write_gathered(tmp, local_path, &content);
        }
    }
}

/// Gather SUID binary list and create marker files
fn gather_suid_data(host: &RemoteHost, tmp: &Path) {
    let suid_output = ssh::ssh_exec_optional(
        host,
        "find / -xdev -perm -4000 -type f 2>/dev/null | head -100",
    );

    if suid_output.is_empty() {
        return;
    }

    for line in suid_output.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        let local_path = &path[1..]; // strip leading /
        let full_path = tmp.join(local_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // Create the file and set SUID bit so the check can detect it
        std::fs::write(&full_path, "").ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&full_path, std::fs::Permissions::from_mode(0o4755)).ok();
        }
    }

    debug!("Gathered {} SUID binaries", suid_output.lines().count());
}

/// Gather IOC indicators that container checks don't cover
fn gather_ioc_indicators(host: &RemoteHost) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for suspicious hidden files in system directories
    let hidden = ssh::ssh_exec_optional(
        host,
        "find /usr/bin /usr/sbin /sbin /bin /usr/local/bin -maxdepth 1 -name '.*' -not -name '.' 2>/dev/null",
    );

    for line in hidden.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        findings.push(
            Finding::new(
                format!("remote-ioc-hidden-{}", path.replace('/', "-")),
                format!("Hidden file in system directory: {}", path),
                "Hidden files in system binary directories may indicate rootkit activity or unauthorized modifications.",
                protectinator_core::Severity::High,
                FindingSource::AgentDetection {
                    agent_type: "rootkit".to_string(),
                    category: "ioc".to_string(),
                },
            )
            .with_resource(path.to_string()),
        );
    }

    // Check for processes with deleted binaries
    let deleted = ssh::ssh_exec_optional(
        host,
        "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -20",
    );

    for line in deleted.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        findings.push(Finding::new(
            "remote-ioc-deleted-binary",
            format!("Process running from deleted binary: {}", line),
            "A running process whose binary has been deleted from disk. This can indicate malware that deletes itself after execution.",
            protectinator_core::Severity::High,
            FindingSource::AgentDetection {
                agent_type: "rootkit".to_string(),
                category: "ioc".to_string(),
            },
        ));
    }

    // Check for LD_PRELOAD in environment
    let ld_preload = ssh::ssh_exec_optional(
        host,
        "cat /etc/ld.so.preload 2>/dev/null; echo '---'; grep -r LD_PRELOAD /etc/environment /etc/profile.d/ 2>/dev/null",
    );

    for line in ld_preload.lines() {
        let line = line.trim();
        if line.is_empty() || line == "---" {
            continue;
        }
        findings.push(Finding::new(
            "remote-ioc-ld-preload",
            format!("LD_PRELOAD configured: {}", line),
            "LD_PRELOAD is being used to inject a shared library into all processes. This is a common rootkit technique.",
            protectinator_core::Severity::Critical,
            FindingSource::AgentDetection {
                agent_type: "rootkit".to_string(),
                category: "ioc".to_string(),
            },
        ));
    }

    // Check for unusual listening ports
    let listeners = ssh::ssh_exec_optional(
        host,
        "ss -tlnp 2>/dev/null | tail -n +2",
    );

    let suspicious_ports: Vec<&str> = listeners
        .lines()
        .filter(|l| {
            // Flag listeners on all interfaces (0.0.0.0 or ::) that aren't common services
            let l = l.trim();
            (l.contains("0.0.0.0:") || l.contains(":::"))
                && !l.contains(":22 ")   // SSH
                && !l.contains(":80 ")   // HTTP
                && !l.contains(":443 ")  // HTTPS
                && !l.contains(":53 ")   // DNS
                && !l.contains(":25 ")   // SMTP
        })
        .collect();

    if suspicious_ports.len() > 10 {
        findings.push(Finding::new(
            "remote-ioc-many-listeners",
            format!("{} services listening on all interfaces", suspicious_ports.len()),
            "Many services are exposed on all network interfaces. Review for unnecessary exposure.",
            protectinator_core::Severity::Medium,
            FindingSource::Hardening {
                check_id: "remote-network-exposure".to_string(),
                category: "network".to_string(),
            },
        ));
    }

    findings
}

/// Write gathered data to the temp directory, creating parent dirs as needed
fn write_gathered(tmp: &Path, relative_path: &str, content: &str) {
    let full_path = tmp.join(relative_path);
    if let Some(parent) = full_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&full_path, content).ok();
}
