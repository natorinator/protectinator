//! Rootkit and Management Software Detection for Protectinator
//!
//! Detects rootkits, management agents, and remote access tools on Linux and macOS.
//!
//! # Features
//!
//! ## Rootkit Detection
//! - Suspicious kernel modules (Linux) / kernel extensions (macOS)
//! - Hidden processes
//! - Processes with deleted binaries
//! - LD_PRELOAD hijacking
//! - Known rootkit signatures
//!
//! ## Management Software Detection
//! - MDM (Jamf, Kandji, Intune, SCCM, etc.)
//! - Endpoint Security (CrowdStrike, SentinelOne, Defender, etc.)
//! - Remote Access (TeamViewer, AnyDesk, VNC, etc.)
//! - Config Management (Puppet, Chef, Ansible, Salt)
//! - RMM tools (Datto, NinjaRMM, etc.)
//!
//! # Example
//!
//! ```no_run
//! use protectinator_agents::{scan_agents, AgentSummary, ScanFilter};
//!
//! // Full scan
//! let entries = scan_agents(None);
//! let summary = AgentSummary::from_entries(&entries);
//!
//! println!("Found {} agents", summary.total_findings);
//! if summary.has_rootkit_indicators() {
//!     println!("Warning: Rootkit indicators detected!");
//! }
//!
//! // Rootkit-only scan
//! let filter = ScanFilter::rootkits_only();
//! let rootkit_entries = scan_agents(Some(&filter));
//! ```

pub mod management;
pub mod rootkit;
pub mod types;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub use types::{
    AgentCategory, AgentEntry, AgentSummary, AgentType, DetectionMethod, RiskLevel, ScanFilter,
};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource, Result, SecurityCheck,
    Severity,
};
use std::sync::Arc;

/// Scan for agents and rootkits
pub fn scan_agents(filter: Option<&ScanFilter>) -> Vec<AgentEntry> {
    let entries = {
        #[cfg(target_os = "linux")]
        {
            linux::scan_all()
        }

        #[cfg(target_os = "macos")]
        {
            macos::scan_all()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Vec::new()
        }
    };

    if let Some(f) = filter {
        entries.into_iter().filter(|e| f.matches(e)).collect()
    } else {
        entries
    }
}

/// Scan only for rootkit indicators
pub fn scan_rootkits() -> Vec<AgentEntry> {
    #[cfg(target_os = "linux")]
    {
        linux::scan_rootkits()
    }

    #[cfg(target_os = "macos")]
    {
        macos::scan_rootkits()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Scan only for management software
pub fn scan_management() -> Vec<AgentEntry> {
    #[cfg(target_os = "linux")]
    {
        linux::scan_management()
    }

    #[cfg(target_os = "macos")]
    {
        macos::scan_management()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Agent detection check provider for integration with engine
pub struct AgentsProvider {
    filter: Option<ScanFilter>,
}

impl AgentsProvider {
    /// Create a new agents provider
    pub fn new() -> Self {
        Self { filter: None }
    }

    /// Set scan filter
    pub fn with_filter(mut self, filter: ScanFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Run the scan
    pub fn scan(&self) -> Vec<AgentEntry> {
        scan_agents(self.filter.as_ref())
    }
}

impl Default for AgentsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for AgentsProvider {
    fn name(&self) -> &str {
        "agents"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        vec![Arc::new(AgentsSecurityCheck {
            filter: self.filter.clone(),
        })]
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Security check for agent detection
struct AgentsSecurityCheck {
    filter: Option<ScanFilter>,
}

impl SecurityCheck for AgentsSecurityCheck {
    fn id(&self) -> &str {
        "agents-scan"
    }

    fn name(&self) -> &str {
        "Agent and Rootkit Detection"
    }

    fn description(&self) -> &str {
        "Scans for rootkits, management agents, and remote access tools"
    }

    fn category(&self) -> &str {
        "agents"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            Applicability::Applicable
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Applicability::NotApplicable("Platform not supported".to_string())
        }
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let entries = scan_agents(self.filter.as_ref());
        let mut findings = Vec::new();

        for entry in entries {
            let severity = match entry.risk {
                RiskLevel::Critical => Severity::Critical,
                RiskLevel::High => Severity::High,
                RiskLevel::Medium => Severity::Medium,
                RiskLevel::Low => Severity::Low,
                RiskLevel::Info => Severity::Info,
            };

            let title = format!("{}: {}", entry.category, entry.name);

            let source = FindingSource::AgentDetection {
                agent_type: entry.agent_type.as_str().to_string(),
                category: entry.category.as_str().to_string(),
            };

            let mut finding = Finding::new(
                format!("agent-{}", entry.agent_type.as_str()),
                title,
                entry.description.clone(),
                severity,
                source,
            );

            if let Some(path) = entry.paths.first() {
                finding = finding.with_resource(path.display().to_string());
            }

            // Add detection method to metadata
            finding = finding.with_metadata(
                "detection_method",
                serde_json::json!(entry.detection_method.as_str()),
            );

            findings.push(finding);
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(15)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_agents() {
        let entries = scan_agents(None);
        println!("Found {} agents", entries.len());
    }

    #[test]
    fn test_scan_rootkits() {
        let entries = scan_rootkits();
        println!("Found {} rootkit indicators", entries.len());
    }

    #[test]
    fn test_scan_management() {
        let entries = scan_management();
        println!("Found {} management agents", entries.len());
    }

    #[test]
    fn test_provider() {
        let provider = AgentsProvider::new();
        let entries = provider.scan();
        let summary = AgentSummary::from_entries(&entries);
        println!("Summary: {:?}", summary);
    }
}
