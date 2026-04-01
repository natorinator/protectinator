//! SSH-based data gathering for IoT device scanning
//!
//! Gathers system data from a remote IoT device via SSH, writes it to a temp
//! directory, then the scanner runs checks against that filesystem.

use protectinator_remote::ssh;
use protectinator_remote::RemoteHost;
use std::path::Path;
use tracing::{debug, info, warn};

/// Gather IoT device data from a remote host via SSH.
///
/// This gathers everything the remote agentless scan gathers PLUS IoT-specific
/// files needed for Pi/ARM checks (boot partition, PAM modules, device tree, etc.)
pub fn gather_iot_data(host: &RemoteHost, tmp: &Path) -> Result<(), String> {
    info!("Gathering IoT device data from {}", host.display_name());

    // === Standard system data (same as remote agentless) ===

    // OS release
    if let Some(content) = ssh::read_remote_file(host, "/etc/os-release") {
        write_gathered(tmp, "etc/os-release", &content);
    }

    // dpkg status (Debian/Ubuntu — most Pis)
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

    // passwd (hardening + default credentials check)
    if let Some(content) = ssh::read_remote_file(host, "/etc/passwd") {
        write_gathered(tmp, "etc/passwd", &content);
    }

    // shadow (permissions check)
    let shadow_check = ssh::ssh_exec_optional(host, "stat -c '%a' /etc/shadow 2>/dev/null");
    if !shadow_check.trim().is_empty() {
        write_gathered(tmp, "etc/shadow", "# placeholder for permissions check");
    }

    // SSH config (hardening)
    if let Some(content) = ssh::read_remote_file(host, "/etc/ssh/sshd_config") {
        write_gathered(tmp, "etc/ssh/sshd_config", &content);
    }

    // Cron jobs
    gather_cron_data(host, tmp);

    // Systemd units
    gather_systemd_data(host, tmp);

    // Shell profiles (persistence check)
    for profile in &["/etc/profile", "/etc/bash.bashrc", "/etc/environment"] {
        if let Some(content) = ssh::read_remote_file(host, profile) {
            write_gathered(tmp, &profile[1..], &content);
        }
    }

    // Kernel modules (rootkit check)
    if let Some(content) = ssh::read_remote_file(host, "/proc/modules") {
        write_gathered(tmp, "proc/modules", &content);
    }

    // SUID binaries
    gather_suid_binaries(host, tmp);

    // Apt lists (security repo detection)
    gather_apt_lists(host, tmp);

    // === IoT-specific data ===

    // Device tree model (Pi detection)
    if let Some(content) = ssh::read_remote_file(host, "/proc/device-tree/model") {
        write_gathered(tmp, "proc/device-tree/model", &content);
    }

    // Pi identification
    if let Some(content) = ssh::read_remote_file(host, "/etc/rpi-issue") {
        write_gathered(tmp, "etc/rpi-issue", &content);
    }

    // Boot partition files (boot integrity check)
    for path in &[
        "/boot/firmware/config.txt",
        "/boot/config.txt",
        "/boot/firmware/cmdline.txt",
        "/boot/cmdline.txt",
    ] {
        if let Some(content) = ssh::read_remote_file(host, path) {
            write_gathered(tmp, &path[1..], &content);
        }
    }

    // Boot partition file listing (for anomaly detection)
    for boot_dir in &["/boot/firmware", "/boot"] {
        let listing = ssh::ssh_exec_optional(
            host,
            &format!("ls -la {} 2>/dev/null", boot_dir),
        );
        if !listing.trim().is_empty() {
            write_gathered(
                tmp,
                &format!("protectinator/boot_listing_{}", boot_dir.replace('/', "_")),
                &listing,
            );
        }
    }

    // Device tree overlays listing
    for overlay_dir in &["/boot/firmware/overlays", "/boot/overlays"] {
        let listing = ssh::ssh_exec_optional(
            host,
            &format!("ls {} 2>/dev/null", overlay_dir),
        );
        if !listing.trim().is_empty() {
            // Create overlay directory with marker files so device_tree check works
            let local_dir = &overlay_dir[1..]; // strip leading /
            let dir_path = tmp.join(local_dir);
            std::fs::create_dir_all(&dir_path).ok();
            for name in listing.lines() {
                let name = name.trim();
                if !name.is_empty() {
                    std::fs::write(dir_path.join(name), "").ok();
                }
            }
        }
    }

    // PAM modules (pam_audit check)
    gather_pam_modules(host, tmp);

    // udev rules
    gather_directory_contents(host, tmp, "/etc/udev/rules.d");

    // MOTD scripts
    gather_directory_contents(host, tmp, "/etc/update-motd.d");

    // tmpfiles.d (persistence check)
    gather_directory_contents(host, tmp, "/etc/tmpfiles.d");

    // dpkg md5sums for binary integrity check
    gather_dpkg_md5sums(host, tmp);

    // /proc/net for network services check (since SSH mode has live access)
    for proc_net in &[
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        if let Some(content) = ssh::read_remote_file(host, proc_net) {
            write_gathered(tmp, &proc_net[1..], &content);
        }
    }

    // /proc/cpuinfo (architecture detection)
    if let Some(content) = ssh::read_remote_file(host, "/proc/cpuinfo") {
        write_gathered(tmp, "proc/cpuinfo", &content);
    }

    // /sys/firmware path check (device detection)
    let sys_firmware = ssh::ssh_exec_optional(host, "ls /sys/firmware/ 2>/dev/null");
    if !sys_firmware.trim().is_empty() {
        let dir = tmp.join("sys/firmware");
        std::fs::create_dir_all(&dir).ok();
        for name in sys_firmware.lines() {
            let name = name.trim();
            if !name.is_empty() {
                std::fs::create_dir_all(dir.join(name)).ok();
            }
        }
    }

    info!("IoT data gathering complete for {}", host.display_name());
    Ok(())
}

/// Gather cron job data
fn gather_cron_data(host: &RemoteHost, tmp: &Path) {
    let cron_dirs = &[
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ];

    for dir in cron_dirs {
        let output = ssh::ssh_exec_optional(
            host,
            &format!(
                "for f in {}/*; do [ -f \"$f\" ] && echo '---FILE:'\"$f\" && cat \"$f\"; done 2>/dev/null",
                dir
            ),
        );
        if output.trim().is_empty() {
            continue;
        }

        let local_dir = &dir[1..]; // strip leading /
        let dir_path = tmp.join(local_dir);
        std::fs::create_dir_all(&dir_path).ok();

        let mut current_file: Option<String> = None;
        let mut current_content = String::new();

        for line in output.lines() {
            if let Some(path) = line.strip_prefix("---FILE:") {
                if let Some(ref file) = current_file {
                    let filename = file.rsplit('/').next().unwrap_or(file);
                    std::fs::write(dir_path.join(filename), &current_content).ok();
                }
                current_file = Some(path.to_string());
                current_content.clear();
            } else {
                current_content.push_str(line);
                current_content.push('\n');
            }
        }

        if let Some(ref file) = current_file {
            let filename = file.rsplit('/').next().unwrap_or(file);
            std::fs::write(dir_path.join(filename), &current_content).ok();
        }
    }

    // Root crontab
    let root_crontab = ssh::ssh_exec_optional(host, "crontab -l 2>/dev/null");
    if !root_crontab.trim().is_empty() {
        let cron_tabs_dir = tmp.join("var/spool/cron/crontabs");
        std::fs::create_dir_all(&cron_tabs_dir).ok();
        std::fs::write(cron_tabs_dir.join("root"), &root_crontab).ok();
    }
}

/// Gather systemd unit files
fn gather_systemd_data(host: &RemoteHost, tmp: &Path) {
    let output = ssh::ssh_exec_optional(
        host,
        "find /etc/systemd/system -maxdepth 2 -name '*.service' -o -name '*.timer' 2>/dev/null | head -50",
    );

    let systemd_dir = tmp.join("etc/systemd/system");
    std::fs::create_dir_all(&systemd_dir).ok();

    for path in output.lines() {
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        if let Some(content) = ssh::read_remote_file(host, path) {
            let filename = path.rsplit('/').next().unwrap_or(path);
            std::fs::write(systemd_dir.join(filename), &content).ok();
        }
    }
}

/// Gather SUID binary paths
fn gather_suid_binaries(host: &RemoteHost, tmp: &Path) {
    let output = ssh::ssh_exec_optional(
        host,
        "timeout 30 find / -xdev -perm -4000 -type f 2>/dev/null | head -100",
    );

    for path in output.lines() {
        let path = path.trim();
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        let local_path = &path[1..];
        let full_path = tmp.join(local_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&full_path, "").ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&full_path, std::fs::Permissions::from_mode(0o4755)).ok();
        }
    }
}

/// Gather apt list files for security repo detection
fn gather_apt_lists(host: &RemoteHost, tmp: &Path) {
    let output = ssh::ssh_exec_optional(
        host,
        "ls /var/lib/apt/lists/ 2>/dev/null",
    );

    if output.trim().is_empty() {
        return;
    }

    let lists_dir = tmp.join("var/lib/apt/lists");
    std::fs::create_dir_all(&lists_dir).ok();

    for name in output.lines() {
        let name = name.trim();
        if !name.is_empty() {
            std::fs::write(lists_dir.join(name), "").ok();
        }
    }
}

/// Gather PAM module files
fn gather_pam_modules(host: &RemoteHost, tmp: &Path) {
    // Find PAM security directories
    let output = ssh::ssh_exec_optional(
        host,
        "find /lib/*/security /lib/security /usr/lib/*/security /usr/lib/security -name '*.so' -type f 2>/dev/null | head -200",
    );

    for path in output.lines() {
        let path = path.trim();
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        let local_path = &path[1..];
        let full_path = tmp.join(local_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // Create marker file — the check just needs to see filenames
        std::fs::write(&full_path, "").ok();
    }

    // Also gather PAM config
    gather_directory_contents(host, tmp, "/etc/pam.d");
}

/// Gather all files in a remote directory
fn gather_directory_contents(host: &RemoteHost, tmp: &Path, remote_dir: &str) {
    let listing = ssh::ssh_exec_optional(
        host,
        &format!(
            "for f in {}/*; do [ -f \"$f\" ] && echo '---FILE:'\"$f\" && cat \"$f\"; done 2>/dev/null",
            remote_dir
        ),
    );

    if listing.trim().is_empty() {
        return;
    }

    let local_dir = &remote_dir[1..];
    let dir_path = tmp.join(local_dir);
    std::fs::create_dir_all(&dir_path).ok();

    let mut current_file: Option<String> = None;
    let mut current_content = String::new();

    for line in listing.lines() {
        if let Some(path) = line.strip_prefix("---FILE:") {
            if let Some(ref file) = current_file {
                let filename = file.rsplit('/').next().unwrap_or(file);
                std::fs::write(dir_path.join(filename), &current_content).ok();
            }
            current_file = Some(path.to_string());
            current_content.clear();
        } else {
            current_content.push_str(line);
            current_content.push('\n');
        }
    }

    if let Some(ref file) = current_file {
        let filename = file.rsplit('/').next().unwrap_or(file);
        std::fs::write(dir_path.join(filename), &current_content).ok();
    }
}

/// Gather dpkg md5sums for binary integrity verification
fn gather_dpkg_md5sums(host: &RemoteHost, tmp: &Path) {
    // Get list of critical package md5sums files
    let output = ssh::ssh_exec_optional(
        host,
        "ls /var/lib/dpkg/info/*.md5sums 2>/dev/null | head -500",
    );

    if output.trim().is_empty() {
        return;
    }

    let md5sums_dir = tmp.join("var/lib/dpkg/info");
    std::fs::create_dir_all(&md5sums_dir).ok();

    // Gather in bulk using a single SSH command to reduce round trips
    let files: Vec<&str> = output.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    // Process in batches to avoid overly long SSH commands
    for chunk in files.chunks(50) {
        let cat_cmd = chunk
            .iter()
            .map(|f| format!("echo '---FILE:{}' && cat '{}'", f, f))
            .collect::<Vec<_>>()
            .join(" && ");

        let content = ssh::ssh_exec_optional(host, &cat_cmd);
        if content.trim().is_empty() {
            continue;
        }

        let mut current_file: Option<String> = None;
        let mut current_content = String::new();

        for line in content.lines() {
            if let Some(path) = line.strip_prefix("---FILE:") {
                if let Some(ref file) = current_file {
                    let filename = file.rsplit('/').next().unwrap_or(file);
                    std::fs::write(md5sums_dir.join(filename), &current_content).ok();
                }
                current_file = Some(path.to_string());
                current_content.clear();
            } else {
                current_content.push_str(line);
                current_content.push('\n');
            }
        }

        if let Some(ref file) = current_file {
            let filename = file.rsplit('/').next().unwrap_or(file);
            std::fs::write(md5sums_dir.join(filename), &current_content).ok();
        }
    }

    debug!("Gathered {} dpkg md5sums files", files.len());
}

/// Write content to a file in the temp directory
fn write_gathered(tmp: &Path, relative_path: &str, content: &str) {
    let full_path = tmp.join(relative_path);
    if let Some(parent) = full_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Err(e) = std::fs::write(&full_path, content) {
        warn!("Failed to write gathered data to {}: {}", relative_path, e);
    }
}
