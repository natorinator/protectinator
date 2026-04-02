//! Fleet configuration file parsing

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Fleet configuration loaded from fleet.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    #[serde(default)]
    pub settings: FleetSettings,

    #[serde(default)]
    pub notifications: NotificationConfig,

    #[serde(default)]
    pub hosts: Vec<HostEntry>,

    #[serde(default)]
    pub containers: ContainerConfig,

    #[serde(default)]
    pub repos: Vec<RepoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSettings {
    /// Max concurrent SSH connections for host scanning
    #[serde(default = "default_parallel")]
    pub parallel: usize,

    /// Whether to persist results to scan_history.db
    #[serde(default = "default_true")]
    pub save_history: bool,

    /// Skip live CVE vulnerability scanning (offline mode)
    #[serde(default)]
    pub offline: bool,
}

impl Default for FleetSettings {
    fn default() -> Self {
        Self {
            parallel: 4,
            save_history: true,
            offline: false,
        }
    }
}

fn default_parallel() -> usize {
    4
}
fn default_true() -> bool {
    true
}

/// Remote host entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    /// Friendly name (used as scan key and display)
    pub name: String,
    /// Hostname or IP address
    pub host: String,
    /// SSH user (default: root)
    #[serde(default = "default_user")]
    pub user: String,
    /// SSH port (default: 22)
    #[serde(default = "default_port")]
    pub port: u16,
    /// Path to SSH private key
    pub key: Option<PathBuf>,
    /// Use sudo for privileged commands
    #[serde(default)]
    pub sudo: bool,
}

fn default_user() -> String {
    "root".to_string()
}
fn default_port() -> u16 {
    22
}

/// Container scanning configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Scan all discovered containers
    #[serde(default)]
    pub scan_all: bool,
    /// Specific container names to scan (if not scan_all)
    #[serde(default)]
    pub names: Vec<String>,
    /// Filter by runtime (nspawn, docker)
    pub runtime: Option<String>,
}

/// Supply chain repo entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoEntry {
    /// Path to the repo (supports ~ expansion)
    pub path: String,
    /// Ecosystem filter
    pub ecosystem: Option<String>,
}

/// Notification configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
}

/// Webhook notification settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL to POST to
    pub url: String,
    /// Events that trigger notification
    #[serde(default = "default_webhook_events")]
    pub on: Vec<String>,
}

fn default_webhook_events() -> Vec<String> {
    vec!["new_critical".to_string(), "new_high".to_string()]
}

impl FleetConfig {
    /// Load from a TOML file
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))
    }

    /// Default config file path
    pub fn default_path() -> Result<PathBuf, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        Ok(PathBuf::from(home).join(".config/protectinator/fleet.toml"))
    }

    /// Generate a template config
    pub fn template() -> String {
        r#"# Protectinator Fleet Configuration
# See: protectinator fleet init

[settings]
parallel = 4           # max concurrent SSH connections
save_history = true    # persist results to scan_history.db
# offline = false      # skip live CVE scanning

# Webhook notifications (optional)
# [notifications.webhook]
# url = "https://hooks.slack.com/services/..."
# on = ["new_critical", "new_high"]

# Remote hosts to scan via SSH
# [[hosts]]
# name = "webserver"
# host = "webserver.example.com"
# user = "root"
# port = 22
# key = "~/.ssh/id_ed25519"

# Container scanning
[containers]
scan_all = false
# names = ["my-container"]
# runtime = "nspawn"   # or "docker"

# Supply chain repos
# [[repos]]
# path = "~/Projects/myapp"
# ecosystem = "npm"
"#
        .to_string()
    }

    /// Expand ~ in a path string
    pub fn expand_path(path: &str) -> PathBuf {
        if path.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(&path[2..]);
            }
        }
        PathBuf::from(path)
    }

    /// Convert a HostEntry to a RemoteHost
    pub fn host_to_remote(entry: &HostEntry) -> protectinator_remote::RemoteHost {
        let mut host = protectinator_remote::RemoteHost::new(&entry.host)
            .with_user(&entry.user)
            .with_port(entry.port)
            .with_name(&entry.name)
            .with_sudo(entry.sudo);
        if let Some(ref key) = entry.key {
            host = host.with_key(Self::expand_path(&key.display().to_string()));
        }
        host
    }
}
