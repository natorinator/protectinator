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

    // Check disk space from gathered data
    let df_data = std::fs::read_to_string(tmp.path().join("protectinator/df_root")).unwrap_or_default();
    if let Some(disk_finding) = check_disk_space(host, df_data.trim()) {
        let mut f = disk_finding;
        f.source = FindingSource::Remote {
            host: host.hostname.clone(),
            scan_mode: "agentless".to_string(),
            inner_source: Box::new(f.source.clone()),
        };
        results.scan_results.add_finding(f);
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

    // Disk space (do this first — fast command, critical info)
    let df_output = ssh::ssh_exec_optional(host, "df -P / 2>/dev/null | tail -1");
    write_gathered(tmp, "protectinator/df_root", &df_output);

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

    // Check uptime and reboot-needed
    let uptime_findings = check_uptime(host);
    for mut f in uptime_findings {
        f.source = FindingSource::Remote {
            host: host.hostname.clone(),
            scan_mode: "agentless".to_string(),
            inner_source: Box::new(f.source.clone()),
        };
        findings.push(f);
    }

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

/// Check system uptime and whether a reboot is needed
fn check_uptime(host: &RemoteHost) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Get uptime in seconds from /proc/uptime
    let uptime_str = ssh::ssh_exec_optional(host, "cat /proc/uptime 2>/dev/null");
    let uptime_secs: f64 = uptime_str
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    if uptime_secs <= 0.0 {
        return findings;
    }

    let uptime_days = (uptime_secs / 86400.0) as u64;

    // Check if reboot is needed (Debian/Ubuntu)
    let reboot_required = ssh::ssh_exec_optional(
        host,
        "test -f /var/run/reboot-required && cat /var/run/reboot-required 2>/dev/null",
    );

    // Check for packages requiring restart
    let needs_restart = ssh::ssh_exec_optional(
        host,
        "cat /var/run/reboot-required.pkgs 2>/dev/null",
    );

    let uptime_human = if uptime_days >= 365 {
        let years = uptime_days / 365;
        let remaining_days = uptime_days % 365;
        format!("{} year{}, {} days", years, if years > 1 { "s" } else { "" }, remaining_days)
    } else {
        format!("{} days", uptime_days)
    };

    if !reboot_required.trim().is_empty() {
        let mut desc = format!(
            "System has been up for {} and requires a reboot. {}",
            uptime_human,
            reboot_required.trim()
        );
        if !needs_restart.trim().is_empty() {
            let pkg_count = needs_restart.lines().count();
            desc.push_str(&format!(
                "\n\n{} package(s) requiring restart:\n{}",
                pkg_count,
                needs_restart
                    .lines()
                    .take(10)
                    .map(|l| format!("  {}", l.trim()))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }

        findings.push(
            Finding::new(
                "remote-reboot-required",
                format!("Reboot required (uptime: {})", uptime_human),
                desc,
                protectinator_core::Severity::High,
                FindingSource::Hardening {
                    check_id: "remote-uptime".to_string(),
                    category: "availability".to_string(),
                },
            )
            .with_remediation("Schedule a reboot to apply pending kernel and system updates."),
        );
    } else if uptime_days > 365 {
        findings.push(
            Finding::new(
                "remote-uptime-excessive",
                format!("System uptime: {} — consider rebooting", uptime_human),
                format!(
                    "System has been running for {} without a reboot. \
                     Kernel security patches and major system updates require a reboot to take effect. \
                     Processes may be running outdated binaries.",
                    uptime_human
                ),
                protectinator_core::Severity::Medium,
                FindingSource::Hardening {
                    check_id: "remote-uptime".to_string(),
                    category: "availability".to_string(),
                },
            )
            .with_remediation("Schedule a maintenance reboot to apply accumulated system updates."),
        );
    } else if uptime_days > 90 {
        findings.push(Finding::new(
            "remote-uptime-notice",
            format!("System uptime: {}", uptime_human),
            format!(
                "System has been running for {}. Check if any pending updates require a reboot.",
                uptime_human
            ),
            protectinator_core::Severity::Info,
            FindingSource::Hardening {
                check_id: "remote-uptime".to_string(),
                category: "availability".to_string(),
            },
        ));
    }

    findings
}

/// Check disk space and generate findings for critical/low space
fn check_disk_space(host: &RemoteHost, df_line: &str) -> Option<Finding> {
    // df -P output: Filesystem 1024-blocks Used Available Capacity Mounted
    let fields: Vec<&str> = df_line.split_whitespace().collect();
    if fields.len() < 5 {
        return None;
    }

    let capacity_str = fields[4].trim_end_matches('%');
    let usage_pct: u32 = capacity_str.parse().ok()?;
    let avail_kb: u64 = fields[3].parse().ok()?;
    let total_kb: u64 = fields[1].parse().ok()?;

    let avail_human = format_size(avail_kb * 1024);
    let total_human = format_size(total_kb * 1024);

    if usage_pct >= 99 {
        // Get top space consumers
        let top_dirs = ssh::ssh_exec_optional(
            host,
            "for d in /var/log /var/lib /var/cache /home /usr /tmp /opt /srv; do s=$(du -sx \"$d\" 2>/dev/null | cut -f1); [ -n \"$s\" ] && echo \"$s $d\"; done | sort -rn | head -5",
        );
        let mut desc = format!(
            "Root filesystem is {}% full ({} available of {}). System operations may fail.",
            usage_pct, avail_human, total_human
        );
        if !top_dirs.trim().is_empty() {
            desc.push_str("\n\nTop space consumers:");
            for line in top_dirs.lines().take(5) {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    let kb: u64 = parts[0].parse().unwrap_or(0);
                    desc.push_str(&format!("\n  {} — {}", parts[1], format_size(kb * 1024)));
                }
            }
        }

        // Check for easy wins
        let journal_size = ssh::ssh_exec_optional(
            host,
            "du -s /var/log/journal 2>/dev/null | cut -f1",
        );
        let journal_kb: u64 = journal_size.trim().parse().unwrap_or(0);
        let apt_cache = ssh::ssh_exec_optional(
            host,
            "du -s /var/cache/apt 2>/dev/null | cut -f1",
        );
        let apt_kb: u64 = apt_cache.trim().parse().unwrap_or(0);

        let mut remediation = String::new();
        if journal_kb > 100_000 {
            remediation.push_str(&format!(
                "journalctl --vacuum-size=100M (reclaim ~{}); ",
                format_size((journal_kb - 100_000) * 1024)
            ));
        }
        if apt_kb > 50_000 {
            remediation.push_str(&format!(
                "apt clean (reclaim ~{}); ",
                format_size(apt_kb * 1024)
            ));
        }
        if remediation.is_empty() {
            remediation = "Investigate disk usage with 'du -sh /*' and remove unnecessary files.".to_string();
        }

        Some(
            Finding::new(
                "remote-disk-critical",
                format!("Disk critically full: {}% ({} free)", usage_pct, avail_human),
                desc,
                protectinator_core::Severity::Critical,
                FindingSource::Hardening {
                    check_id: "remote-disk-space".to_string(),
                    category: "availability".to_string(),
                },
            )
            .with_resource(format!("/ — {} of {}", avail_human, total_human))
            .with_remediation(remediation),
        )
    } else if usage_pct >= 90 {
        Some(
            Finding::new(
                "remote-disk-warning",
                format!("Disk nearly full: {}% ({} free)", usage_pct, avail_human),
                format!(
                    "Root filesystem is {}% full with {} remaining of {}. Monitor and plan cleanup.",
                    usage_pct, avail_human, total_human
                ),
                protectinator_core::Severity::High,
                FindingSource::Hardening {
                    check_id: "remote-disk-space".to_string(),
                    category: "availability".to_string(),
                },
            )
            .with_resource(format!("/ — {} of {}", avail_human, total_human))
            .with_remediation("Investigate disk usage with 'du -sh /*' and clean up old logs, caches, and unused packages."),
        )
    } else if usage_pct >= 80 {
        Some(Finding::new(
            "remote-disk-notice",
            format!("Disk usage: {}% ({} free)", usage_pct, avail_human),
            format!(
                "Root filesystem is {}% full with {} remaining of {}.",
                usage_pct, avail_human, total_human
            ),
            protectinator_core::Severity::Medium,
            FindingSource::Hardening {
                check_id: "remote-disk-space".to_string(),
                category: "availability".to_string(),
            },
        ))
    } else {
        None
    }
}

/// Format bytes into human-readable size
fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}G", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.0}M", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.0}K", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

/// Write gathered data to the temp directory, creating parent dirs as needed
fn write_gathered(tmp: &Path, relative_path: &str, content: &str) {
    let full_path = tmp.join(relative_path);
    if let Some(parent) = full_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&full_path, content).ok();
}
