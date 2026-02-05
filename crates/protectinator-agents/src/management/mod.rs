//! Management software detection module
//!
//! Detects various management and remote access software:
//! - MDM (Mobile Device Management) agents
//! - EDR (Endpoint Detection and Response) / Antivirus
//! - Remote access tools (TeamViewer, AnyDesk, etc.)
//! - Configuration management (Puppet, Chef, Ansible, Salt)
//! - RMM (Remote Monitoring and Management) tools

pub mod endpoint;
pub mod mdm;
pub mod remote;

use crate::types::AgentEntry;

/// Scan for all management software
pub fn scan_all() -> Vec<AgentEntry> {
    let mut entries = Vec::new();

    entries.extend(mdm::scan_mdm());
    entries.extend(endpoint::scan_endpoint_security());
    entries.extend(remote::scan_remote_access());
    entries.extend(remote::scan_config_management());
    entries.extend(remote::scan_rmm());

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_all() {
        let entries = scan_all();
        println!("Found {} management agents", entries.len());
    }
}
