//! Container types for security scanning

use protectinator_core::ScanResults;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Container runtime type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerRuntime {
    /// systemd-nspawn container
    Nspawn,
    /// Docker container
    Docker,
}

impl fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerRuntime::Nspawn => write!(f, "nspawn"),
            ContainerRuntime::Docker => write!(f, "docker"),
        }
    }
}

/// Container state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerState {
    /// Container is currently running
    Running,
    /// Container is stopped
    Stopped,
    /// State could not be determined
    Unknown,
}

impl fmt::Display for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerState::Running => write!(f, "running"),
            ContainerState::Stopped => write!(f, "stopped"),
            ContainerState::Unknown => write!(f, "unknown"),
        }
    }
}

/// A discovered container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// Container name
    pub name: String,
    /// Container runtime type
    pub runtime: ContainerRuntime,
    /// Root filesystem path on the host (e.g., /var/lib/machines/mycontainer)
    pub root_path: PathBuf,
    /// Current state
    pub state: ContainerState,
    /// OS information parsed from the container's /etc/os-release
    pub os_info: Option<ContainerOsInfo>,
}

/// OS information from a container's /etc/os-release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerOsInfo {
    /// Distribution ID (e.g., "debian", "ubuntu", "fedora")
    pub id: String,
    /// Version string
    pub version: String,
    /// Human-readable name (e.g., "Debian GNU/Linux 12 (bookworm)")
    pub pretty_name: String,
    /// Whether this OS version is known to be end-of-life
    pub eol: Option<bool>,
}

/// Results of scanning a single container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanResults {
    /// The container that was scanned
    pub container: Container,
    /// Security scan results
    pub scan_results: ScanResults,
}
