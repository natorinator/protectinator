//! IoT-specific security checks
//!
//! Each module implements a security check targeting IoT/Raspberry Pi
//! attack vectors. Checks operate on `ContainerFs` for filesystem access
//! and declare whether they require local execution.

pub mod binary_integrity;
pub mod boot_integrity;
pub mod default_credentials;
pub mod device_tree;
pub mod iot_rootkit;
pub mod kernel_integrity;
pub mod motd_persistence;
pub mod network_services;
pub mod pam_audit;
pub mod tmpfiles_persistence;
pub mod udev_audit;

use protectinator_container::filesystem::ContainerFs;
use protectinator_core::Finding;

/// Trait for IoT-specific security checks
///
/// Extends the container check pattern with `requires_local()` to indicate
/// checks that need /proc or other live-system access.
pub trait IotCheck: Send + Sync {
    /// Unique identifier for this check
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Whether this check requires running on the live device (not mounted)
    fn requires_local(&self) -> bool {
        false
    }

    /// Run the check against the filesystem and return findings
    fn run(&self, fs: &ContainerFs) -> Vec<Finding>;
}
