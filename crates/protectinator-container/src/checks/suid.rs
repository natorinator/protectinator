//! SUID/SGID binary audit
//!
//! Walks the container filesystem to find SUID/SGID binaries and
//! cross-references them against known GTFOBins.

use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

/// Known GTFOBins SUID binaries that can be abused for privilege escalation
const GTFOBINS_SUID: &[&str] = &[
    "ar", "aria2c", "ash", "awk", "base32", "base64", "bash", "bridge",
    "busybox", "cat", "chmod", "chown", "chroot", "column", "comm", "cp",
    "csh", "csplit", "cut", "dash", "date", "dd", "dialog", "diff",
    "dig", "dmsetup", "docker", "ed", "emacs", "env", "eqn", "expand",
    "expect", "file", "find", "flock", "fmt", "fold", "gawk", "gdb",
    "gimp", "grep", "head", "hexdump", "highlight", "hping3", "iconv",
    "install", "ip", "jjs", "join", "jq", "ksh", "ld.so", "less",
    "logsave", "look", "lua", "make", "mawk", "more", "mv", "nano",
    "nawk", "nice", "nl", "nmap", "node", "nohup", "od", "openssl",
    "paste", "perl", "pg", "php", "pico", "pr", "python", "python2",
    "python3", "readelf", "restic", "rev", "rlwrap", "rsync", "run-parts",
    "rview", "rvim", "sed", "setarch", "shuf", "socat", "sort",
    "sqlite3", "ss", "ssh-keygen", "start-stop-daemon", "stdbuf",
    "strace", "strings", "sysctl", "systemctl", "tac", "tail", "tar",
    "taskset", "tclsh", "tee", "tftp", "time", "timeout", "troff",
    "ul", "unexpand", "uniq", "unshare", "update-alternatives", "uudecode",
    "uuencode", "vi", "view", "vim", "watch", "wc", "wget", "wish",
    "xargs", "xxd", "zip", "zsh",
];

/// Directories that commonly have legitimate SUID binaries
const STANDARD_SUID_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib",
    "/usr/libexec",
];

/// Common legitimate SUID/SGID binaries (expected on standard Debian/Ubuntu systems)
const STANDARD_SUID_BINARIES: &[&str] = &[
    // Authentication & user management
    "su",
    "sudo",
    "passwd",
    "chsh",
    "chfn",
    "newgrp",
    "gpasswd",
    "chage",          // SGID shadow — password aging
    "expiry",         // SGID shadow — password expiration check
    "unix_chkpwd",    // PAM password verification
    "pam_timestamp_check",
    // Filesystem
    "mount",
    "umount",
    "fusermount",
    "fusermount3",
    "ntfs-3g",        // NTFS filesystem driver
    // Network
    "ping",
    "ping6",
    "traceroute",
    "traceroute6",
    // Scheduling
    "crontab",
    "at",
    // SSH
    "ssh-agent",
    "ssh-keysign",    // Host-based authentication signing
    // D-Bus / PolicyKit / X11
    "pkexec",
    "polkit-agent-helper-1",
    "dbus-daemon-launch-helper",
    "Xorg",
    "Xorg.wrap",
    // Terminal / TTY
    "utempter",       // SGID utmp — terminal login records
    "wall",           // SGID tty — broadcast messages
    "write",          // SGID tty — write to other users
    "bsd-write",
    // Misc system
    "snap-confine",
    "chrome-sandbox",
    "lockscrn",
];

/// SUID/SGID binary audit check
pub struct SuidCheck;

impl ContainerCheck for SuidCheck {
    fn id(&self) -> &str {
        "container-suid"
    }

    fn name(&self) -> &str {
        "SUID/SGID Binary Audit"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root = fs.root();

        // Walk the filesystem looking for SUID/SGID binaries
        for entry in WalkDir::new(root)
            .follow_links(false)
            .max_depth(8)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            if !metadata.is_file() {
                continue;
            }

            let mode = metadata.permissions().mode();
            let is_suid = mode & 0o4000 != 0;
            let is_sgid = mode & 0o2000 != 0;

            if !is_suid && !is_sgid {
                continue;
            }

            let path = entry.path();

            // Get the path relative to the container root
            let inner_path = path
                .strip_prefix(root)
                .map(|p| format!("/{}", p.display()))
                .unwrap_or_else(|_| path.display().to_string());

            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let suid_type = if is_suid && is_sgid {
                "SUID+SGID"
            } else if is_suid {
                "SUID"
            } else {
                "SGID"
            };

            // Check if it's a known GTFOBin
            let is_gtfobin = GTFOBINS_SUID.contains(&file_name.as_str());

            // Check if it's in a standard location
            let in_standard_dir = STANDARD_SUID_DIRS.iter().any(|d| inner_path.starts_with(d));
            let is_standard_binary = STANDARD_SUID_BINARIES.contains(&file_name.as_str());

            let (severity, title) = if is_gtfobin && !is_standard_binary {
                (
                    Severity::High,
                    format!("{} GTFOBin: {} ({})", suid_type, file_name, inner_path),
                )
            } else if !in_standard_dir {
                (
                    Severity::High,
                    format!(
                        "{} binary in non-standard location: {} ({})",
                        suid_type, file_name, inner_path
                    ),
                )
            } else if is_standard_binary {
                (
                    Severity::Info,
                    format!("{} binary: {} ({})", suid_type, file_name, inner_path),
                )
            } else {
                (
                    Severity::Medium,
                    format!("Unusual {} binary: {} ({})", suid_type, file_name, inner_path),
                )
            };

            let mut finding = Finding::new(
                "container-suid-binary",
                title,
                format!(
                    "Found {} binary '{}' at {} with mode {:04o}",
                    suid_type, file_name, inner_path, mode & 0o7777
                ),
                severity,
                FindingSource::PrivilegeEscalation {
                    vector_type: format!("{}_binary", suid_type.to_lowercase().replace('+', "_")),
                },
            )
            .with_resource(&inner_path);

            if is_gtfobin {
                finding = finding
                    .with_reference("https://gtfobins.github.io/")
                    .with_remediation(format!(
                        "DANGEROUS: '{}' can be used for privilege escalation. Remove the {} bit if not needed: chmod u-s {}",
                        file_name,
                        suid_type.to_lowercase(),
                        inner_path,
                    ));
            } else if !is_standard_binary && in_standard_dir {
                finding = finding.with_remediation(format!(
                    "Verify '{}' requires the {} bit. If not needed: chmod u-s {}",
                    file_name,
                    suid_type.to_lowercase(),
                    inner_path,
                ));
            } else if !in_standard_dir {
                finding = finding.with_remediation(format!(
                    "{} binary in unusual location — verify this is legitimate. Remove with: chmod u-s {}",
                    suid_type, inner_path,
                ));
            }

            findings.push(finding);
        }

        findings
    }
}
