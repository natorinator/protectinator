//! Kernel module scanning for rootkit detection

use crate::types::{AgentEntry, AgentType, DetectionMethod, RiskLevel};
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

use super::signatures::{is_known_rootkit_module, is_suspicious_module_name};

/// Information about a loaded kernel module
#[derive(Debug, Clone)]
pub struct KernelModule {
    pub name: String,
    pub size: usize,
    pub used_by: Vec<String>,
    pub state: String,
}

/// Parse /proc/modules to get list of loaded kernel modules (Linux)
#[cfg(target_os = "linux")]
pub fn get_loaded_modules() -> Vec<KernelModule> {
    let mut modules = Vec::new();

    let content = match fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read /proc/modules: {}", e);
            return modules;
        }
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let name = parts[0].to_string();
            let size = parts[1].parse().unwrap_or(0);
            let _used_count: usize = parts[2].parse().unwrap_or(0);
            let used_by: Vec<String> = if parts.len() > 3 && parts[3] != "-" {
                parts[3]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            } else {
                Vec::new()
            };
            let state = if parts.len() > 4 {
                parts[4].to_string()
            } else {
                "Live".to_string()
            };

            modules.push(KernelModule {
                name,
                size,
                used_by,
                state,
            });
        }
    }

    debug!("Found {} loaded kernel modules", modules.len());
    modules
}

#[cfg(not(target_os = "linux"))]
pub fn get_loaded_modules() -> Vec<KernelModule> {
    Vec::new()
}

/// Scan loaded kernel modules for rootkit indicators
pub fn scan_modules() -> Vec<AgentEntry> {
    let mut entries = Vec::new();
    let modules = get_loaded_modules();

    for module in modules {
        // Check for known rootkit modules
        if let Some(description) = is_known_rootkit_module(&module.name) {
            entries.push(
                AgentEntry::new(
                    AgentType::SuspiciousKernelModule,
                    format!("Known rootkit module: {}", module.name),
                    format!(
                        "Loaded kernel module '{}' matches known rootkit signature: {}",
                        module.name, description
                    ),
                    DetectionMethod::KernelModule {
                        name: module.name.clone(),
                    },
                )
                .with_risk(RiskLevel::Critical)
                .with_metadata("module_size", module.size.into())
                .with_metadata("module_state", module.state.clone().into()),
            );
            continue;
        }

        // Check for suspicious module names
        if is_suspicious_module_name(&module.name) {
            entries.push(
                AgentEntry::new(
                    AgentType::SuspiciousKernelModule,
                    format!("Suspicious module: {}", module.name),
                    format!(
                        "Loaded kernel module '{}' has a suspicious name pattern",
                        module.name
                    ),
                    DetectionMethod::KernelModule {
                        name: module.name.clone(),
                    },
                )
                .with_risk(RiskLevel::High)
                .with_metadata("module_size", module.size.into())
                .with_metadata("module_state", module.state.into()),
            );
        }
    }

    entries
}

/// Check for hidden kernel modules by comparing /proc/modules with /sys/module
#[cfg(target_os = "linux")]
pub fn scan_hidden_modules() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // Get modules from /proc/modules
    let proc_modules: std::collections::HashSet<String> = get_loaded_modules()
        .into_iter()
        .map(|m| m.name)
        .collect();

    // Get modules from /sys/module
    let sys_module_path = Path::new("/sys/module");
    if !sys_module_path.exists() {
        return entries;
    }

    let sys_modules: std::collections::HashSet<String> = match fs::read_dir(sys_module_path) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect(),
        Err(e) => {
            warn!("Failed to read /sys/module: {}", e);
            return entries;
        }
    };

    // Modules in /sys/module but not in /proc/modules might be hidden
    // Note: Some built-in modules appear in /sys/module but not /proc/modules, so we need to check
    for module in sys_modules.difference(&proc_modules) {
        // Check if this is a built-in module by looking for the module refcount
        let refcount_path = sys_module_path.join(module).join("refcnt");
        if refcount_path.exists() {
            // This module has a refcount, so it's a loadable module that's hidden from /proc/modules
            entries.push(
                AgentEntry::new(
                    AgentType::SuspiciousKernelModule,
                    format!("Potentially hidden module: {}", module),
                    format!(
                        "Module '{}' found in /sys/module but not in /proc/modules. \
                         This could indicate a rootkit hiding the module.",
                        module
                    ),
                    DetectionMethod::KernelModule {
                        name: module.clone(),
                    },
                )
                .with_risk(RiskLevel::High),
            );
        }
    }

    entries
}

#[cfg(not(target_os = "linux"))]
pub fn scan_hidden_modules() -> Vec<AgentEntry> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_modules() {
        // This test will only work on Linux with /proc/modules accessible
        #[cfg(target_os = "linux")]
        {
            let modules = get_loaded_modules();
            // Should find at least some modules on a running Linux system
            // (unless in a very minimal container)
            println!("Found {} modules", modules.len());
        }
    }
}
