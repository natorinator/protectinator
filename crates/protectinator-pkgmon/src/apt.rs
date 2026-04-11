//! apt/dpkg binary integrity checks
//!
//! Verifies system binaries against dpkg md5sums manifests and audits
//! package source configuration for security issues.
//!
//! Implementation follows patterns from protectinator-iot binary_integrity
//! and protectinator-osverify dpkg verification.

use crate::scanner::PkgMonCheck;
use crate::types::{PackageManager, PkgMonContext};
use protectinator_core::Finding;

/// apt binary integrity verification via dpkg md5sums
pub struct AptIntegrityCheck;

impl PkgMonCheck for AptIntegrityCheck {
    fn name(&self) -> &str {
        "apt-binary-integrity"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Apt
    }

    fn check(&self, _ctx: &PkgMonContext) -> Vec<Finding> {
        // Implementation in Task 2
        Vec::new()
    }
}

/// apt source configuration audit
pub struct AptSourceAudit;

impl PkgMonCheck for AptSourceAudit {
    fn name(&self) -> &str {
        "apt-source-audit"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Apt
    }

    fn check(&self, _ctx: &PkgMonContext) -> Vec<Finding> {
        // Implementation in Task 2
        Vec::new()
    }
}
