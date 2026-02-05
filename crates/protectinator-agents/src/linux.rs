//! Linux-specific agent scanning coordinator

use crate::management;
use crate::rootkit;
use crate::types::{AgentEntry, ScanFilter};

/// Scan for all agents and rootkits on Linux
pub fn scan_all() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // Rootkit detection
    entries.extend(rootkit::scan_all());

    // Management software detection
    entries.extend(management::scan_all());

    entries
}

/// Scan with filter options
pub fn scan_filtered(filter: &ScanFilter) -> Vec<AgentEntry> {
    let entries = scan_all();
    entries.into_iter().filter(|e| filter.matches(e)).collect()
}

/// Scan only for rootkits
pub fn scan_rootkits() -> Vec<AgentEntry> {
    rootkit::scan_all()
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
        println!("Found {} entries on Linux", entries.len());
    }
}
