//! Rootkit detection module
//!
//! Provides detection capabilities for:
//! - Suspicious kernel modules
//! - Hidden processes
//! - Processes with deleted binaries
//! - LD_PRELOAD hijacking
//! - Known rootkit signatures

pub mod modules;
pub mod processes;
pub mod signatures;

use crate::types::AgentEntry;

/// Run all rootkit detection scans
pub fn scan_all() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    // Kernel module scanning
    entries.extend(modules::scan_modules());
    entries.extend(modules::scan_hidden_modules());

    // Process-based detection
    entries.extend(processes::scan_all_processes());

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_all() {
        // Just verify it runs without panicking
        let entries = scan_all();
        println!("Found {} rootkit indicators", entries.len());
    }
}
