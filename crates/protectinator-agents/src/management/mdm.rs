//! Mobile Device Management (MDM) detection

use crate::types::{AgentEntry, AgentType, DetectionMethod, RiskLevel};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

/// MDM software signatures for detection
#[allow(dead_code)]
struct MdmSignature {
    agent_type: AgentType,
    name: &'static str,
    paths: &'static [&'static str],
    processes: &'static [&'static str],
    services: &'static [&'static str],
}

const LINUX_MDM_SIGNATURES: &[MdmSignature] = &[
    MdmSignature {
        agent_type: AgentType::Sccm,
        name: "Microsoft SCCM/ConfigMgr",
        paths: &[
            "/opt/microsoft/configmgr",
            "/opt/microsoft/scxcm",
            "/etc/opt/microsoft/scxcm",
            "/var/opt/microsoft/scxcm",
        ],
        processes: &["ccmexec", "cmclient"],
        services: &["ccmexec"],
    },
    MdmSignature {
        agent_type: AgentType::MicrosoftIntune,
        name: "Microsoft Intune",
        paths: &[
            "/opt/microsoft/intune",
            "/opt/microsoft/mdatp",
            "/etc/opt/microsoft/mdatp",
        ],
        processes: &["intune-daemon", "intune-agent"],
        services: &["intune"],
    },
    MdmSignature {
        agent_type: AgentType::WorkspaceOne,
        name: "VMware Workspace ONE",
        paths: &[
            "/opt/vmware/ws1",
            "/opt/vmware/airwatch",
            "/etc/vmware/ws1",
        ],
        processes: &["ws1agent", "awcmd"],
        services: &["ws1agent", "airwatch"],
    },
];

#[cfg(target_os = "macos")]
const MACOS_MDM_SIGNATURES: &[MdmSignature] = &[
    MdmSignature {
        agent_type: AgentType::JamfPro,
        name: "Jamf Pro",
        paths: &[
            "/usr/local/jamf",
            "/usr/local/bin/jamf",
            "/Library/Application Support/JAMF",
            "/var/log/jamf.log",
        ],
        processes: &["jamf", "JamfAgent", "JamfDaemon"],
        services: &["com.jamfsoftware.jamf.daemon"],
    },
    MdmSignature {
        agent_type: AgentType::Kandji,
        name: "Kandji",
        paths: &[
            "/Library/Kandji",
            "/usr/local/bin/kandji",
        ],
        processes: &["kandji-agent", "Kandji"],
        services: &["io.kandji.agent"],
    },
    MdmSignature {
        agent_type: AgentType::Mosyle,
        name: "Mosyle",
        paths: &[
            "/Library/Mosyle",
            "/Library/Application Support/Mosyle",
        ],
        processes: &["Mosyle", "MosyleFusionAgent"],
        services: &["com.mosyle.agent"],
    },
    MdmSignature {
        agent_type: AgentType::WorkspaceOne,
        name: "VMware Workspace ONE",
        paths: &[
            "/Library/Application Support/AirWatch",
            "/Library/Application Support/VMware",
            "/usr/local/bin/hubcli",
        ],
        processes: &["awcm", "hubagent", "AWCMAgent"],
        services: &["com.airwatch.awcmd"],
    },
    MdmSignature {
        agent_type: AgentType::MicrosoftIntune,
        name: "Microsoft Intune",
        paths: &[
            "/Library/Intune",
            "/Applications/Company Portal.app",
        ],
        processes: &["IntuneMdmAgent", "CompanyPortal"],
        services: &["com.microsoft.intune.agent"],
    },
];

/// Check if any path from a list exists
fn check_paths(paths: &[&str]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|p| {
            let path = Path::new(p);
            if path.exists() {
                Some(path.to_path_buf())
            } else {
                None
            }
        })
        .collect()
}

/// Check if a process is running (simple /proc check for Linux)
#[cfg(target_os = "linux")]
fn is_process_running(name: &str) -> bool {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid_str) = entry.file_name().to_str() {
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = fs::read_to_string(&comm_path) {
                        if comm.trim().eq_ignore_ascii_case(name) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn is_process_running(name: &str) -> bool {
    // On macOS we'd use sysctl or ps, but for simplicity check common locations
    // This is a simplified check
    std::process::Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn is_process_running(_name: &str) -> bool {
    false
}

/// Scan for MDM software on Linux
#[cfg(target_os = "linux")]
pub fn scan_mdm() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    for sig in LINUX_MDM_SIGNATURES {
        let found_paths = check_paths(sig.paths);
        let running_processes: Vec<_> = sig
            .processes
            .iter()
            .filter(|p| is_process_running(p))
            .collect();

        if !found_paths.is_empty() || !running_processes.is_empty() {
            let detection = if !running_processes.is_empty() {
                DetectionMethod::Process {
                    pid: None,
                    name: running_processes[0].to_string(),
                }
            } else {
                DetectionMethod::FilePresence {
                    path: found_paths[0].clone(),
                }
            };

            entries.push(
                AgentEntry::new(
                    sig.agent_type,
                    sig.name.to_string(),
                    format!(
                        "{} MDM agent detected on this system",
                        sig.name
                    ),
                    detection,
                )
                .with_risk(RiskLevel::Info)
                .with_paths(found_paths),
            );
        }
    }

    debug!("Found {} MDM agents", entries.len());
    entries
}

/// Scan for MDM software on macOS
#[cfg(target_os = "macos")]
pub fn scan_mdm() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    for sig in MACOS_MDM_SIGNATURES {
        let found_paths = check_paths(sig.paths);
        let running_processes: Vec<_> = sig
            .processes
            .iter()
            .filter(|p| is_process_running(p))
            .collect();

        if !found_paths.is_empty() || !running_processes.is_empty() {
            let detection = if !running_processes.is_empty() {
                DetectionMethod::Process {
                    pid: None,
                    name: running_processes[0].to_string(),
                }
            } else {
                DetectionMethod::FilePresence {
                    path: found_paths[0].clone(),
                }
            };

            entries.push(
                AgentEntry::new(
                    sig.agent_type,
                    sig.name.to_string(),
                    format!(
                        "{} MDM agent detected on this system",
                        sig.name
                    ),
                    detection,
                )
                .with_risk(RiskLevel::Info)
                .with_paths(found_paths),
            );
        }
    }

    // Check for Apple MDM enrollment profile
    entries.extend(scan_apple_mdm_profiles());

    debug!("Found {} MDM agents", entries.len());
    entries
}

/// Scan for Apple MDM profiles (macOS only)
#[cfg(target_os = "macos")]
fn scan_apple_mdm_profiles() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // Check for MDM profile using profiles command
    if let Ok(output) = std::process::Command::new("profiles")
        .args(["show", "-type", "enrollment"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("MDM") || stdout.contains("enrollment") {
            entries.push(
                AgentEntry::new(
                    AgentType::AppleMdm,
                    "Apple MDM Enrollment".to_string(),
                    "This Mac is enrolled in an MDM (Mobile Device Management) solution".to_string(),
                    DetectionMethod::MdmProfile {
                        name: "MDM Enrollment Profile".to_string(),
                    },
                )
                .with_risk(RiskLevel::Info),
            );
        }
    }

    entries
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn scan_mdm() -> Vec<AgentEntry> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_paths() {
        // Test with paths that should exist on most systems
        let paths = &["/etc", "/nonexistent"];
        let found = check_paths(paths);
        assert!(found.iter().any(|p| p.to_str() == Some("/etc")));
    }

    #[test]
    fn test_scan_mdm() {
        // Just verify it doesn't panic
        let _ = scan_mdm();
    }
}
