//! Supply chain security checks
//!
//! Each module implements a check targeting specific supply chain
//! attack vectors.

pub mod cicd_actions;
pub mod cicd_secrets;
pub mod lockfile_integrity;
pub mod malware_signatures;
pub mod npm_postinstall;
pub mod pip_build_hooks;
pub mod pth_injection;
pub mod registry_audit;
pub mod shell_profile;
pub mod user_systemd;
pub mod vulnerability;

use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::Finding;

/// Trait for supply chain security checks
pub trait SupplyChainCheck: Send + Sync {
    /// Unique identifier for this check
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Whether this check requires network access (e.g., OSV API)
    fn requires_network(&self) -> bool {
        false
    }

    /// Run the check against the filesystem and return findings
    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding>;
}
