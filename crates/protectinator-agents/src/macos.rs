//! macOS-specific agent scanning coordinator

use crate::management;
use crate::types::{AgentEntry, AgentType, DetectionMethod, RiskLevel, ScanFilter};
use std::process::Command;
use tracing::{debug, warn};

/// Scan for suspicious kernel extensions (kexts)
fn scan_kexts() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // Run kextstat to get loaded kernel extensions
    let output = match Command::new("kextstat").output() {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to run kextstat: {}", e);
            return entries;
        }
    };

    if !output.status.success() {
        warn!("kextstat returned non-zero exit code");
        return entries;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Known suspicious or commonly abused kext patterns
    let suspicious_patterns = [
        ("com.vmware", false),      // VMware - legitimate but notable
        ("com.parallels", false),   // Parallels - legitimate but notable
        ("com.virtualbox", false),  // VirtualBox - legitimate but notable
    ];

    // Known malicious kext patterns
    let malicious_patterns = [
        "rootkit",
        "backdoor",
        "keylogger",
        "stealth",
        "hidden",
    ];

    for line in stdout.lines().skip(1) {
        // Skip header line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        // Bundle ID is typically the last field
        let bundle_id = parts.last().unwrap_or(&"");

        // Check for malicious patterns
        let bundle_lower = bundle_id.to_lowercase();
        for pattern in malicious_patterns {
            if bundle_lower.contains(pattern) {
                entries.push(
                    AgentEntry::new(
                        AgentType::SuspiciousKext,
                        format!("Suspicious kext: {}", bundle_id),
                        format!(
                            "Kernel extension '{}' has suspicious naming pattern",
                            bundle_id
                        ),
                        DetectionMethod::KernelExtension {
                            name: bundle_id.to_string(),
                        },
                    )
                    .with_risk(RiskLevel::High),
                );
            }
        }
    }

    debug!("Found {} suspicious kexts", entries.len());
    entries
}

/// Scan for all agents and rootkits on macOS
pub fn scan_all() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // macOS kext scanning
    entries.extend(scan_kexts());

    // Management software detection (uses cross-platform module)
    entries.extend(management::scan_all());

    entries
}

/// Scan with filter options
pub fn scan_filtered(filter: &ScanFilter) -> Vec<AgentEntry> {
    let entries = scan_all();
    entries.into_iter().filter(|e| filter.matches(e)).collect()
}

/// Scan only for rootkit indicators
pub fn scan_rootkits() -> Vec<AgentEntry> {
    scan_kexts()
}

/// Scan only for management software
pub fn scan_management() -> Vec<AgentEntry> {
    management::scan_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_all() {
        let entries = scan_all();
        println!("Found {} entries on macOS", entries.len());
    }
}
