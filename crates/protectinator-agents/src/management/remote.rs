//! Remote access tool and configuration management detection

use crate::types::{AgentCategory, AgentEntry, AgentType, DetectionMethod, RiskLevel};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Remote access software signature
#[allow(dead_code)]
struct RemoteSignature {
    agent_type: AgentType,
    name: &'static str,
    linux_paths: &'static [&'static str],
    macos_paths: &'static [&'static str],
    processes: &'static [&'static str],
}

const REMOTE_ACCESS_SIGNATURES: &[RemoteSignature] = &[
    RemoteSignature {
        agent_type: AgentType::TeamViewer,
        name: "TeamViewer",
        linux_paths: &[
            "/opt/teamviewer",
            "/var/log/teamviewer",
            "/etc/teamviewer",
        ],
        macos_paths: &[
            "/Applications/TeamViewer.app",
            "/Library/Application Support/TeamViewer",
        ],
        processes: &["teamviewerd", "TeamViewer"],
    },
    RemoteSignature {
        agent_type: AgentType::AnyDesk,
        name: "AnyDesk",
        linux_paths: &[
            "/usr/bin/anydesk",
            "/opt/anydesk",
            "/etc/anydesk",
        ],
        macos_paths: &[
            "/Applications/AnyDesk.app",
        ],
        processes: &["anydesk", "AnyDesk"],
    },
    RemoteSignature {
        agent_type: AgentType::ScreenConnect,
        name: "ConnectWise ScreenConnect",
        linux_paths: &[
            "/opt/screenconnect-client",
            "/opt/connectwisecontrol-client",
        ],
        macos_paths: &[
            "/opt/connectwisecontrol-client",
            "/Library/Application Support/ScreenConnect Client",
        ],
        processes: &["screenconnect", "connectwisecontrol"],
    },
    RemoteSignature {
        agent_type: AgentType::LogMeIn,
        name: "LogMeIn",
        linux_paths: &[
            "/opt/logmein",
        ],
        macos_paths: &[
            "/Library/Application Support/LogMeIn",
            "/Applications/LogMeIn Client.app",
        ],
        processes: &["logmein", "LogMeInClient"],
    },
    RemoteSignature {
        agent_type: AgentType::Splashtop,
        name: "Splashtop",
        linux_paths: &[
            "/opt/splashtop",
        ],
        macos_paths: &[
            "/Applications/Splashtop Streamer.app",
            "/Library/Application Support/Splashtop Streamer",
        ],
        processes: &["splashtop", "SRAgent"],
    },
    RemoteSignature {
        agent_type: AgentType::RustDesk,
        name: "RustDesk",
        linux_paths: &[
            "/usr/bin/rustdesk",
            "/opt/rustdesk",
            "/usr/share/rustdesk",
        ],
        macos_paths: &[
            "/Applications/RustDesk.app",
        ],
        processes: &["rustdesk"],
    },
    RemoteSignature {
        agent_type: AgentType::VncServer,
        name: "VNC Server",
        linux_paths: &[
            "/usr/bin/vncserver",
            "/usr/bin/x11vnc",
            "/usr/bin/tigervncserver",
            "/etc/vnc",
        ],
        macos_paths: &[
            // macOS has built-in Screen Sharing
        ],
        processes: &["Xvnc", "x11vnc", "vncserver"],
    },
];

const CONFIG_MANAGEMENT_SIGNATURES: &[RemoteSignature] = &[
    RemoteSignature {
        agent_type: AgentType::Puppet,
        name: "Puppet Agent",
        linux_paths: &[
            "/opt/puppetlabs",
            "/etc/puppetlabs",
            "/var/log/puppetlabs",
            "/opt/puppet",
            "/etc/puppet",
        ],
        macos_paths: &[
            "/opt/puppetlabs",
            "/etc/puppetlabs",
        ],
        processes: &["puppet", "pxp-agent"],
    },
    RemoteSignature {
        agent_type: AgentType::Chef,
        name: "Chef Client",
        linux_paths: &[
            "/opt/chef",
            "/etc/chef",
            "/var/log/chef",
            "/opt/cinc",
        ],
        macos_paths: &[
            "/opt/chef",
            "/etc/chef",
        ],
        processes: &["chef-client", "cinc-client"],
    },
    RemoteSignature {
        agent_type: AgentType::Ansible,
        name: "Ansible",
        linux_paths: &[
            "/etc/ansible",
            "/var/log/ansible",
        ],
        macos_paths: &[
            "/etc/ansible",
            "/usr/local/etc/ansible",
        ],
        processes: &["ansible", "ansible-playbook"],
    },
    RemoteSignature {
        agent_type: AgentType::Salt,
        name: "Salt Minion",
        linux_paths: &[
            "/etc/salt",
            "/var/log/salt",
            "/opt/saltstack",
        ],
        macos_paths: &[
            "/etc/salt",
            "/opt/salt",
        ],
        processes: &["salt-minion", "salt-master"],
    },
    RemoteSignature {
        agent_type: AgentType::Cfengine,
        name: "CFEngine",
        linux_paths: &[
            "/var/cfengine",
            "/opt/cfengine",
        ],
        macos_paths: &[
            "/var/cfengine",
        ],
        processes: &["cf-agent", "cf-execd"],
    },
];

const RMM_SIGNATURES: &[RemoteSignature] = &[
    RemoteSignature {
        agent_type: AgentType::Datto,
        name: "Datto RMM",
        linux_paths: &[
            "/opt/CentraStage",
            "/usr/local/centrastage",
        ],
        macos_paths: &[
            "/Library/Application Support/CentraStage",
        ],
        processes: &["CagService", "AEMAgent"],
    },
    RemoteSignature {
        agent_type: AgentType::NinjaRmm,
        name: "NinjaRMM",
        linux_paths: &[
            "/opt/NinjaRMMAgent",
        ],
        macos_paths: &[
            "/Library/NinjaRMMAgent",
        ],
        processes: &["ninjarmm-agent", "NinjaRMMAgent"],
    },
    RemoteSignature {
        agent_type: AgentType::ConnectWise,
        name: "ConnectWise Automate",
        linux_paths: &[
            "/opt/ltechagent",
            "/usr/local/ltechagent",
        ],
        macos_paths: &[
            "/usr/local/ltechagent",
        ],
        processes: &["ltechagent", "ltsvc"],
    },
    RemoteSignature {
        agent_type: AgentType::Atera,
        name: "Atera Agent",
        linux_paths: &[
            "/opt/atera",
        ],
        macos_paths: &[
            "/Library/Application Support/Atera",
        ],
        processes: &["AteraAgent"],
    },
    RemoteSignature {
        agent_type: AgentType::Kaseya,
        name: "Kaseya VSA",
        linux_paths: &[
            "/opt/Kaseya",
        ],
        macos_paths: &[
            "/Library/Kaseya",
        ],
        processes: &["KaseyaAgent", "agentmon"],
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

fn scan_signatures(
    signatures: &[RemoteSignature],
    category: AgentCategory,
    risk: RiskLevel,
) -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    for sig in signatures {
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
            let category_str = match category {
                AgentCategory::RemoteAccess => "remote access tool",
                AgentCategory::ConfigManagement => "configuration management tool",
                AgentCategory::Rmm => "RMM agent",
                _ => "software",
            };

            entries.push(
                AgentEntry::new(
                    sig.agent_type,
                    sig.name.to_string(),
                    format!(
                        "{} {} {}",
                        sig.name,
                        category_str,
                        if is_running { "is running" } else { "is installed" }
                    ),
                    detection,
                )
                .with_risk(risk)
                .with_paths(found_paths)
                .with_metadata("is_running", is_running.into()),
            );
        }
    }

    entries
}

/// Scan for remote access tools
pub fn scan_remote_access() -> Vec<AgentEntry> {
    let mut entries = scan_signatures(
        REMOTE_ACCESS_SIGNATURES,
        AgentCategory::RemoteAccess,
        RiskLevel::Low,
    );

    // Check for SSH server
    entries.extend(scan_ssh_server());

    debug!("Found {} remote access tools", entries.len());
    entries
}

/// Scan for SSH server
fn scan_ssh_server() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    let ssh_paths = [
        "/usr/sbin/sshd",
        "/etc/ssh/sshd_config",
    ];

    let found_paths: Vec<PathBuf> = ssh_paths
        .iter()
        .filter(|p| Path::new(p).exists())
        .map(|p| PathBuf::from(p))
        .collect();

    #[cfg(target_os = "linux")]
    let ssh_running = is_process_running("sshd");
    #[cfg(target_os = "macos")]
    let ssh_running = is_process_running("sshd");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let ssh_running = false;

    if !found_paths.is_empty() || ssh_running {
        entries.push(
            AgentEntry::new(
                AgentType::SshServer,
                "SSH Server".to_string(),
                format!(
                    "OpenSSH server {}",
                    if ssh_running { "is running" } else { "is installed" }
                ),
                if ssh_running {
                    DetectionMethod::Process {
                        pid: None,
                        name: "sshd".to_string(),
                    }
                } else {
                    DetectionMethod::FilePresence {
                        path: found_paths[0].clone(),
                    }
                },
            )
            .with_risk(RiskLevel::Info)
            .with_paths(found_paths)
            .with_metadata("is_running", ssh_running.into()),
        );
    }

    entries
}

/// Scan for configuration management tools
pub fn scan_config_management() -> Vec<AgentEntry> {
    let entries = scan_signatures(
        CONFIG_MANAGEMENT_SIGNATURES,
        AgentCategory::ConfigManagement,
        RiskLevel::Info,
    );

    debug!("Found {} config management tools", entries.len());
    entries
}

/// Scan for RMM tools
pub fn scan_rmm() -> Vec<AgentEntry> {
    let entries = scan_signatures(
        RMM_SIGNATURES,
        AgentCategory::Rmm,
        RiskLevel::Low,
    );

    debug!("Found {} RMM tools", entries.len());
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_remote_access() {
        let _ = scan_remote_access();
    }

    #[test]
    fn test_scan_config_management() {
        let _ = scan_config_management();
    }

    #[test]
    fn test_scan_rmm() {
        let _ = scan_rmm();
    }
}
