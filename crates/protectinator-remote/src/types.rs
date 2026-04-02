//! Types for remote scanning

use protectinator_core::ScanResults;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Remote scan mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Run protectinator on the remote host, collect JSON results
    Agent,
    /// Gather data via SSH commands, analyze locally
    Agentless,
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanMode::Agent => write!(f, "agent"),
            ScanMode::Agentless => write!(f, "agentless"),
        }
    }
}

/// A remote host to scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteHost {
    /// Hostname or IP address
    pub hostname: String,
    /// SSH port (default 22)
    pub port: u16,
    /// SSH user (default "root")
    pub user: String,
    /// Path to SSH private key (None = use SSH agent / default keys)
    pub key_path: Option<PathBuf>,
    /// Friendly name for display
    pub name: Option<String>,
    /// Use sudo for privileged commands
    pub use_sudo: bool,
}

impl RemoteHost {
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            port: 22,
            user: "root".to_string(),
            key_path: None,
            name: None,
            use_sudo: false,
        }
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_key(mut self, key: impl Into<PathBuf>) -> Self {
        self.key_path = Some(key.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_sudo(mut self, use_sudo: bool) -> Self {
        self.use_sudo = use_sudo;
        self
    }

    /// Display name: friendly name or user@host
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}@{}", self.user, self.hostname))
    }

    /// SSH destination string: user@host
    pub fn ssh_dest(&self) -> String {
        format!("{}@{}", self.user, self.hostname)
    }
}

/// Results of scanning a remote host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteScanResults {
    /// The host that was scanned
    pub host: RemoteHost,
    /// Scan mode used
    pub scan_mode: ScanMode,
    /// Security scan results
    pub scan_results: ScanResults,
}
