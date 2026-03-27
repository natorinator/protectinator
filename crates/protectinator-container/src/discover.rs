//! Container discovery
//!
//! Discovers containers on the system:
//! - **nspawn**: `/var/lib/machines/` directory entries + `machinectl list`
//! - **Docker**: `docker ps -a` + `docker inspect` for overlay2 filesystem roots

use crate::filesystem::ContainerFs;
use crate::types::{Container, ContainerRuntime, ContainerState};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

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

/// Discover all containers on the system (nspawn + Docker)
pub fn list_all_containers() -> Vec<Container> {
    let mut containers = list_nspawn_containers();
    containers.extend(list_docker_containers());
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    containers
}

/// Discover all Docker containers on the system
///
/// Uses `docker ps -a --format json` for container listing and
/// `docker inspect` for overlay2 merged directory paths.
/// Only running containers have accessible merged filesystems.
pub fn list_docker_containers() -> Vec<Container> {
    let output = match std::process::Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.ID}}"])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            debug!("docker not available: {}", e);
            return Vec::new();
        }
    };

    if !output.status.success() {
        debug!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    if lines.is_empty() {
        return Vec::new();
    }

    // Collect container IDs for bulk inspect
    let container_ids: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.rsplit('|').next())
        .collect();

    // Get merged dirs for all containers in one docker inspect call
    let merged_dirs = get_docker_merged_dirs(&container_ids);

    let mut containers = Vec::new();

    for line in &lines {
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() < 3 {
            continue;
        }

        let name = parts[0].to_string();
        let state = match parts[1] {
            "running" => ContainerState::Running,
            "exited" | "dead" => ContainerState::Stopped,
            "created" | "paused" | "restarting" => ContainerState::Unknown,
            _ => ContainerState::Unknown,
        };
        let id = parts[2];

        let root_path = merged_dirs
            .get(id)
            .cloned()
            .unwrap_or_else(|| PathBuf::from(format!("/var/lib/docker/containers/{}", id)));

        let scannable = state == ContainerState::Running && root_path.is_dir();

        let os_info = if scannable {
            let fs = ContainerFs::new(&root_path);
            fs.detect_os()
        } else {
            None
        };

        debug!(
            "Found Docker container: {} (state={}, scannable={})",
            name, state, scannable
        );

        containers.push(Container {
            name,
            runtime: ContainerRuntime::Docker,
            root_path,
            state,
            os_info,
        });
    }

    info!("Discovered {} Docker containers", containers.len());
    containers
}

/// Get overlay2 merged directory paths for a batch of container IDs
fn get_docker_merged_dirs(container_ids: &[&str]) -> HashMap<String, PathBuf> {
    let mut result = HashMap::new();

    if container_ids.is_empty() {
        return result;
    }

    let output = match std::process::Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{.Id}}|{{.GraphDriver.Data.MergedDir}}")
        .args(container_ids)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            warn!("docker inspect failed: {}", e);
            return result;
        }
    };

    if !output.status.success() {
        debug!(
            "docker inspect failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return result;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.trim().lines() {
        if let Some((full_id, merged_dir)) = line.split_once('|') {
            if !merged_dir.is_empty() && merged_dir != "<no value>" {
                // Map both the full ID and the short ID (first 12 chars)
                let short_id = &full_id[..full_id.len().min(12)];
                let path = PathBuf::from(merged_dir);
                result.insert(short_id.to_string(), path.clone());
                result.insert(full_id.to_string(), path);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_all_containers_returns_sorted() {
        // This is an integration test that depends on system state,
        // but it should not panic regardless of what's available
        let containers = list_all_containers();
        // Verify sorted by name
        for window in containers.windows(2) {
            assert!(window[0].name <= window[1].name);
        }
    }

    #[test]
    fn test_docker_discovery_does_not_panic() {
        // Should gracefully handle Docker not being available or no containers
        let _containers = list_docker_containers();
    }
}
