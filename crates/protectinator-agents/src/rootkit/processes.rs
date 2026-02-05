//! Suspicious process detection for rootkit hunting

use crate::types::{AgentEntry, AgentType, DetectionMethod, RiskLevel};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

use super::signatures::is_suspicious_process_name;

/// Information about a running process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: Option<PathBuf>,
    pub exe_deleted: bool,
    pub uid: Option<u32>,
}

/// Get list of PIDs from /proc (Linux)
#[cfg(target_os = "linux")]
fn get_proc_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    }

    pids
}

/// Get process info from /proc/<pid>
#[cfg(target_os = "linux")]
fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let proc_path = PathBuf::from(format!("/proc/{}", pid));

    if !proc_path.exists() {
        return None;
    }

    // Read comm (process name)
    let comm_path = proc_path.join("comm");
    let name = fs::read_to_string(&comm_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| String::from("<unknown>"));

    // Read cmdline
    let cmdline_path = proc_path.join("cmdline");
    let cmdline = fs::read_to_string(&cmdline_path)
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_default();

    // Read exe symlink
    let exe_path_link = proc_path.join("exe");
    let (exe_path, exe_deleted) = match fs::read_link(&exe_path_link) {
        Ok(path) => {
            let path_str = path.to_string_lossy().to_string();
            let deleted = path_str.contains("(deleted)");
            let clean_path = if deleted {
                PathBuf::from(path_str.replace(" (deleted)", ""))
            } else {
                path
            };
            (Some(clean_path), deleted)
        }
        Err(_) => (None, false),
    };

    // Read status for UID
    let status_path = proc_path.join("status");
    let uid = fs::read_to_string(&status_path)
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return parts[1].parse().ok();
                    }
                }
            }
            None
        });

    Some(ProcessInfo {
        pid,
        name,
        cmdline,
        exe_path,
        exe_deleted,
        uid,
    })
}

#[cfg(not(target_os = "linux"))]
fn get_proc_pids() -> HashSet<u32> {
    HashSet::new()
}

#[cfg(not(target_os = "linux"))]
fn get_process_info(_pid: u32) -> Option<ProcessInfo> {
    None
}

/// Scan for processes with deleted executables
pub fn scan_deleted_exe_processes() -> Vec<AgentEntry> {
    let mut entries = Vec::new();
    let pids = get_proc_pids();

    for pid in pids {
        if let Some(info) = get_process_info(pid) {
            if info.exe_deleted {
                // Process is running but its executable has been deleted
                let exe_display = info
                    .exe_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());

                entries.push(
                    AgentEntry::new(
                        AgentType::DeletedBinaryProcess,
                        format!("Process with deleted binary: {} (PID {})", info.name, pid),
                        format!(
                            "Process '{}' (PID {}) is running but its executable '{}' has been deleted. \
                             This is a common rootkit technique to evade detection.",
                            info.name, pid, exe_display
                        ),
                        DetectionMethod::ProcessAnomaly {
                            description: format!(
                                "Executable deleted: {}",
                                exe_display
                            ),
                        },
                    )
                    .with_risk(RiskLevel::High)
                    .with_metadata("pid", pid.into())
                    .with_metadata("process_name", info.name.into())
                    .with_metadata("cmdline", info.cmdline.into()),
                );
            }
        }
    }

    debug!(
        "Found {} processes with deleted executables",
        entries.len()
    );
    entries
}

/// Scan for hidden processes by comparing different enumeration methods
#[cfg(target_os = "linux")]
pub fn scan_hidden_processes() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // Get PIDs from /proc directory listing - do this twice to reduce race conditions
    let proc_pids_first = get_proc_pids();

    // Check for processes with suspicious names in known processes
    for pid in &proc_pids_first {
        if let Some(info) = get_process_info(*pid) {
            if is_suspicious_process_name(&info.name) {
                entries.push(
                    AgentEntry::new(
                        AgentType::HiddenProcess,
                        format!("Suspicious process: {} (PID {})", info.name, pid),
                        format!(
                            "Process '{}' (PID {}) has a suspicious name that may indicate malware. \
                             Cmdline: {}",
                            info.name, pid, info.cmdline
                        ),
                        DetectionMethod::Process {
                            pid: Some(*pid),
                            name: info.name.clone(),
                        },
                    )
                    .with_risk(RiskLevel::Medium)
                    .with_metadata("pid", (*pid).into())
                    .with_metadata("cmdline", info.cmdline.into()),
                );
            }
        }
    }

    // NOTE: Hidden process detection via PID scanning has high false positive rates
    // due to race conditions with short-lived processes. We skip this aggressive check
    // and rely on other detection methods (suspicious names, deleted binaries, etc.)
    // that are more reliable.
    //
    // A more robust approach would require kernel-level access or multiple sampling
    // passes with statistical analysis, which is beyond the scope of this userland tool.

    entries
}

#[cfg(not(target_os = "linux"))]
pub fn scan_hidden_processes() -> Vec<AgentEntry> {
    Vec::new()
}

/// Scan for LD_PRELOAD hijacking
#[cfg(target_os = "linux")]
pub fn scan_ld_preload() -> Vec<AgentEntry> {
    let mut entries = Vec::new();
    let preload_path = Path::new("/etc/ld.so.preload");

    if preload_path.exists() {
        match fs::read_to_string(preload_path) {
            Ok(content) => {
                let libraries: Vec<&str> = content
                    .lines()
                    .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
                    .collect();

                if !libraries.is_empty() {
                    // /etc/ld.so.preload exists and has content - this is suspicious
                    entries.push(
                        AgentEntry::new(
                            AgentType::LdPreloadHijack,
                            "LD_PRELOAD hijacking detected".to_string(),
                            format!(
                                "/etc/ld.so.preload contains {} preloaded libraries. \
                                 This can be used by rootkits to hook system calls. \
                                 Libraries: {}",
                                libraries.len(),
                                libraries.join(", ")
                            ),
                            DetectionMethod::LibraryPreload {
                                path: preload_path.to_path_buf(),
                            },
                        )
                        .with_risk(RiskLevel::High)
                        .with_path(preload_path.to_path_buf())
                        .with_metadata(
                            "preloaded_libraries",
                            serde_json::json!(libraries),
                        ),
                    );
                }
            }
            Err(e) => {
                warn!("Failed to read /etc/ld.so.preload: {}", e);
            }
        }
    }

    // Check for preload files in unusual locations
    let suspicious_preload_dirs = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/dev/shm",
        "/tmp",
        "/var/tmp",
    ];

    for dir in suspicious_preload_dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }

        if let Ok(entries_iter) = fs::read_dir(dir_path) {
            for entry in entries_iter.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Look for suspicious library names
                if name_str.starts_with("lib")
                    && name_str.contains(".so")
                    && (name_str.contains("preload")
                        || name_str.contains("hook")
                        || name_str.contains("inject"))
                {
                    entries.push(
                        AgentEntry::new(
                            AgentType::LdPreloadHijack,
                            format!("Suspicious preload library: {}", name_str),
                            format!(
                                "Found suspicious library at {} that may be used for hooking",
                                entry.path().display()
                            ),
                            DetectionMethod::FilePresence {
                                path: entry.path(),
                            },
                        )
                        .with_risk(RiskLevel::Medium)
                        .with_path(entry.path()),
                    );
                }
            }
        }
    }

    entries
}

#[cfg(not(target_os = "linux"))]
pub fn scan_ld_preload() -> Vec<AgentEntry> {
    Vec::new()
}

/// Run all process-based rootkit scans
pub fn scan_all_processes() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    entries.extend(scan_deleted_exe_processes());
    entries.extend(scan_hidden_processes());
    entries.extend(scan_ld_preload());

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_proc_pids() {
        let pids = get_proc_pids();
        assert!(!pids.is_empty(), "Should find at least one process");
        assert!(pids.contains(&1) || pids.len() > 0, "Should find init process or others");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_process_info() {
        let pids = get_proc_pids();
        if let Some(&pid) = pids.iter().next() {
            let info = get_process_info(pid);
            assert!(info.is_some(), "Should get info for existing process");
        }
    }
}
