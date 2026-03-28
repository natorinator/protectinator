//! Container security checks
//!
//! Each module implements security checks that operate on the container's
//! filesystem from the host, without entering the container.

pub mod hardening;
pub mod os_version;
pub mod packages;
pub mod persistence;
pub mod rootkit;
pub mod suid;
pub mod vulnerability;

use crate::filesystem::ContainerFs;
use protectinator_core::Finding;

/// Trait for container-specific security checks
pub trait ContainerCheck: Send + Sync {
    /// Unique identifier for this check
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Run the check against the container filesystem and return findings
    fn run(&self, fs: &ContainerFs) -> Vec<Finding>;
}
