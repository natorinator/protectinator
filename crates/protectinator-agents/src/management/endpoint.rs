//! Endpoint Detection and Response (EDR) / Antivirus detection

use crate::types::{AgentEntry, AgentType, DetectionMethod, RiskLevel};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

/// EDR/Antivirus software signature
#[allow(dead_code)]
struct EndpointSignature {
    agent_type: AgentType,
    name: &'static str,
    linux_paths: &'static [&'static str],
    macos_paths: &'static [&'static str],
    processes: &'static [&'static str],
}

const ENDPOINT_SIGNATURES: &[EndpointSignature] = &[
    EndpointSignature {
        agent_type: AgentType::CrowdStrike,
        name: "CrowdStrike Falcon",
        linux_paths: &[
            "/opt/CrowdStrike",
            "/opt/CrowdStrike/falconctl",
            "/opt/CrowdStrike/falcond",
            "/var/opt/CrowdStrike",
            "/etc/opt/CrowdStrike",
        ],
        macos_paths: &[
            "/Library/CS",
            "/Applications/Falcon.app",
            "/Library/Application Support/CrowdStrike",
        ],
        processes: &["falcon-sensor", "falcond", "CSFalconService"],
    },
    EndpointSignature {
        agent_type: AgentType::SentinelOne,
        name: "SentinelOne",
        linux_paths: &[
            "/opt/sentinelone",
            "/opt/sentinelone/bin/sentinelctl",
        ],
        macos_paths: &[
            "/Library/Sentinel",
            "/Applications/SentinelOne",
        ],
        processes: &["sentineld", "SentinelAgent"],
    },
    EndpointSignature {
        agent_type: AgentType::MicrosoftDefender,
        name: "Microsoft Defender",
        linux_paths: &[
            "/opt/microsoft/mdatp",
            "/etc/opt/microsoft/mdatp",
            "/var/opt/microsoft/mdatp",
        ],
        macos_paths: &[
            "/Library/Application Support/Microsoft Defender",
            "/Applications/Microsoft Defender.app",
        ],
        processes: &["mdatp", "wdavdaemon"],
    },
    EndpointSignature {
        agent_type: AgentType::CarbonBlack,
        name: "VMware Carbon Black",
        linux_paths: &[
            "/opt/carbonblack",
            "/var/opt/carbonblack",
            "/opt/cbsensor",
        ],
        macos_paths: &[
            "/Applications/VMware Carbon Black Cloud",
            "/Library/Application Support/com.vmware.carbonblack",
        ],
        processes: &["cbdaemon", "cbsensor", "cbagentd"],
    },
    EndpointSignature {
        agent_type: AgentType::Sophos,
        name: "Sophos",
        linux_paths: &[
            "/opt/sophos-av",
            "/opt/sophos-spl",
            "/etc/sophos-av",
        ],
        macos_paths: &[
            "/Library/Sophos Anti-Virus",
            "/Library/Application Support/Sophos",
        ],
        processes: &["savscand", "sophos-spl", "SophosAgent"],
    },
    EndpointSignature {
        agent_type: AgentType::McAfee,
        name: "McAfee/Trellix",
        linux_paths: &[
            "/opt/McAfee",
            "/opt/NAI",
            "/opt/isec/ens",
        ],
        macos_paths: &[
            "/Library/McAfee",
            "/Applications/McAfee Endpoint Security for Mac.app",
        ],
        processes: &["VShield", "mfetpd", "masvc"],
    },
    EndpointSignature {
        agent_type: AgentType::Symantec,
        name: "Symantec/Broadcom Endpoint",
        linux_paths: &[
            "/opt/Symantec",
            "/etc/symantec",
            "/opt/sep",
        ],
        macos_paths: &[
            "/Library/Application Support/Symantec",
            "/Applications/Symantec Endpoint Protection.app",
        ],
        processes: &["symcfgd", "sepd", "SymDaemon"],
    },
    EndpointSignature {
        agent_type: AgentType::TrendMicro,
        name: "Trend Micro",
        linux_paths: &[
            "/opt/TrendMicro",
            "/opt/ds_agent",
        ],
        macos_paths: &[
            "/Library/Application Support/TrendMicro",
        ],
        processes: &["ds_agent", "dsa_query", "iCoreService"],
    },
    EndpointSignature {
        agent_type: AgentType::Cylance,
        name: "Cylance/BlackBerry",
        linux_paths: &[
            "/opt/cylance",
        ],
        macos_paths: &[
            "/Library/Application Support/Cylance",
            "/Applications/Cylance",
        ],
        processes: &["CylanceSvc", "cylancesvc"],
    },
    EndpointSignature {
        agent_type: AgentType::Tanium,
        name: "Tanium",
        linux_paths: &[
            "/opt/Tanium",
            "/opt/Tanium/TaniumClient",
        ],
        macos_paths: &[
            "/Library/Tanium",
        ],
        processes: &["TaniumClient", "taniumclient"],
    },
    EndpointSignature {
        agent_type: AgentType::OsQuery,
        name: "osquery",
        linux_paths: &[
            "/opt/osquery",
            "/var/osquery",
            "/etc/osquery",
            "/usr/bin/osqueryd",
            "/usr/local/bin/osqueryd",
        ],
        macos_paths: &[
            "/var/osquery",
            "/etc/osquery",
            "/usr/local/bin/osqueryd",
        ],
        processes: &["osqueryd"],
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

/// Check if a process is running
#[cfg(target_os = "linux")]
fn is_process_running(name: &str) -> bool {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid_str) = entry.file_name().to_str() {
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = fs::read_to_string(&comm_path) {
                        let comm_lower = comm.trim().to_lowercase();
                        let name_lower = name.to_lowercase();
                        if comm_lower == name_lower || comm_lower.contains(&name_lower) {
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
    std::process::Command::new("pgrep")
        .arg("-i")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn is_process_running(_name: &str) -> bool {
    false
}

/// Scan for endpoint security software
pub fn scan_endpoint_security() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    for sig in ENDPOINT_SIGNATURES {
        #[cfg(target_os = "linux")]
        let paths_to_check = sig.linux_paths;
        #[cfg(target_os = "macos")]
        let paths_to_check = sig.macos_paths;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let paths_to_check: &[&str] = &[];

        let found_paths = check_paths(paths_to_check);
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

            let is_running = !running_processes.is_empty();

            entries.push(
                AgentEntry::new(
                    sig.agent_type,
                    sig.name.to_string(),
                    format!(
                        "{} endpoint security agent {}",
                        sig.name,
                        if is_running { "is running" } else { "is installed" }
                    ),
                    detection,
                )
                .with_risk(RiskLevel::Info)
                .with_paths(found_paths)
                .with_metadata("is_running", is_running.into()),
            );
        }
    }

    debug!("Found {} endpoint security agents", entries.len());
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_endpoint_security() {
        // Just verify it doesn't panic
        let _ = scan_endpoint_security();
    }
}
