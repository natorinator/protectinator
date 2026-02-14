//! Container discovery
//!
//! Discovers nspawn containers on the system by examining:
//! - `/var/lib/machines/` directory entries (directory-based containers)
//! - `machinectl list --output=json` output (includes running state and .raw images)

use crate::filesystem::ContainerFs;
use crate::types::{Container, ContainerRuntime, ContainerState};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

/// Default path where nspawn containers are stored
const MACHINES_PATH: &str = "/var/lib/machines";

/// Discover all nspawn containers on the system
pub fn list_nspawn_containers() -> Vec<Container> {
    let mut containers: HashMap<String, Container> = HashMap::new();

    // First, enumerate directory-based containers from /var/lib/machines/
    discover_from_machines_dir(&mut containers);

    // Then, augment with machinectl output for running state
    discover_from_machinectl(&mut containers);

    // Detect OS info for each container
    for container in containers.values_mut() {
        if container.root_path.is_dir() {
            let fs = ContainerFs::new(&container.root_path);
            container.os_info = fs.detect_os();
        }
    }

    let mut result: Vec<Container> = containers.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Discover containers from /var/lib/machines/ directory
fn discover_from_machines_dir(containers: &mut HashMap<String, Container>) {
    let machines_path = Path::new(MACHINES_PATH);
    if !machines_path.is_dir() {
        debug!("{} does not exist or is not a directory", MACHINES_PATH);
        return;
    }

    let entries = match std::fs::read_dir(machines_path) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read {}: {}", MACHINES_PATH, e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        // Skip hidden files and non-directory/non-raw entries
        if name.starts_with('.') {
            continue;
        }

        if path.is_dir() {
            // Directory-based container
            debug!("Found directory-based nspawn container: {}", name);
            containers.insert(
                name.clone(),
                Container {
                    name,
                    runtime: ContainerRuntime::Nspawn,
                    root_path: path,
                    state: ContainerState::Stopped, // Will be updated by machinectl
                    os_info: None,
                },
            );
        } else if name.ends_with(".raw") {
            // Image-based container — we note it but can't scan it without mounting
            let container_name = name.trim_end_matches(".raw").to_string();
            debug!("Found .raw image container: {} (not scannable without mounting)", container_name);
            // Skip .raw images for now — they need to be mounted first
        }
    }
}

/// Augment container information with machinectl output
fn discover_from_machinectl(containers: &mut HashMap<String, Container>) {
    let output = match std::process::Command::new("machinectl")
        .args(["list", "--output=json", "--no-legend", "--no-pager"])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            debug!("machinectl not available: {}", e);
            return;
        }
    };

    if !output.status.success() {
        debug!(
            "machinectl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if stdout.is_empty() {
        return;
    }

    // Parse JSON array of machines
    let machines: Vec<serde_json::Value> = match serde_json::from_str(stdout) {
        Ok(machines) => machines,
        Err(e) => {
            debug!("Failed to parse machinectl JSON output: {}", e);
            return;
        }
    };

    for machine in machines {
        let name = match machine.get("machine").and_then(|v| v.as_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        let state = match machine.get("state").and_then(|v| v.as_str()) {
            Some("running") => ContainerState::Running,
            Some("degraded") => ContainerState::Running,
            _ => ContainerState::Stopped,
        };

        if let Some(container) = containers.get_mut(&name) {
            container.state = state;
        } else {
            // Container found by machinectl but not in /var/lib/machines/
            // This can happen for .raw images or other backing stores
            let root_path = Path::new(MACHINES_PATH).join(&name);
            if root_path.is_dir() {
                containers.insert(
                    name.clone(),
                    Container {
                        name,
                        runtime: ContainerRuntime::Nspawn,
                        root_path,
                        state,
                        os_info: None,
                    },
                );
            }
        }
    }
}
