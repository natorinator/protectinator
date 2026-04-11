//! Package monitor scanner orchestrator
//!
//! Discovers available package managers, runs integrity checks, and collects findings.

use crate::types::{PackageManager, PkgMonConfig, PkgMonContext};
use protectinator_core::Finding;
use tracing::{debug, info};

/// Trait for package monitor checks
pub trait PkgMonCheck: Send + Sync {
    /// Check name for logging and finding identification
    fn name(&self) -> &str;

    /// Which package manager this check is for
    fn package_manager(&self) -> PackageManager;

    /// Run the check and return findings
    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding>;
}

/// Orchestrates package manager integrity scanning
pub struct PkgMonScanner {
    config: PkgMonConfig,
    checks: Vec<Box<dyn PkgMonCheck>>,
}

impl PkgMonScanner {
    /// Create a new scanner with default checks
    pub fn new(config: PkgMonConfig) -> Self {
        Self {
            config,
            checks: Vec::new(),
        }
    }

    /// Register a check
    pub fn add_check(&mut self, check: Box<dyn PkgMonCheck>) {
        self.checks.push(check);
    }

    /// Run all applicable checks
    pub fn scan(&self) -> Result<Vec<Finding>, String> {
        let ctx = PkgMonContext::new(self.config.clone());

        if ctx.detected_managers.is_empty() {
            info!("No supported package managers detected");
            return Ok(Vec::new());
        }

        info!(
            "Detected package managers: {:?}",
            ctx.detected_managers
        );

        let mut all_findings = Vec::new();

        for check in &self.checks {
            let manager = check.package_manager();

            if !ctx.config.should_scan(manager) {
                debug!("Skipping {} (filtered out)", check.name());
                continue;
            }

            if !ctx.has_manager(manager) {
                debug!("Skipping {} ({} not detected)", check.name(), manager);
                continue;
            }

            info!("Running check: {}", check.name());
            let findings = check.check(&ctx);
            debug!("{}: {} findings", check.name(), findings.len());
            all_findings.extend(findings);
        }

        info!(
            "Package monitor scan complete: {} total findings",
            all_findings.len()
        );
        Ok(all_findings)
    }

    /// Get detected package managers without running checks
    pub fn detect(&self) -> Vec<PackageManager> {
        let ctx = PkgMonContext::new(self.config.clone());
        ctx.detected_managers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protectinator_core::{FindingSource, Severity};

    struct DummyCheck;

    impl PkgMonCheck for DummyCheck {
        fn name(&self) -> &str {
            "dummy"
        }

        fn package_manager(&self) -> PackageManager {
            PackageManager::Apt
        }

        fn check(&self, _ctx: &PkgMonContext) -> Vec<Finding> {
            vec![Finding::new(
                "dummy-001",
                "Dummy Finding",
                "This is a test finding",
                Severity::Info,
                FindingSource::PackageMonitor {
                    package_manager: "apt".to_string(),
                    check_category: "test".to_string(),
                },
            )]
        }
    }

    #[test]
    fn scanner_no_managers_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let config = PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let scanner = PkgMonScanner::new(config);
        let findings = scanner.scan().unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn scanner_filters_by_manager() {
        let tmp = tempfile::tempdir().unwrap();
        // Create dpkg status so apt is detected
        let dpkg_dir = tmp.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg_dir).unwrap();
        std::fs::write(dpkg_dir.join("status"), "").unwrap();

        let config = PkgMonConfig {
            root: tmp.path().to_path_buf(),
            manager_filter: Some(PackageManager::Homebrew), // filter to brew only
            ..Default::default()
        };

        let mut scanner = PkgMonScanner::new(config);
        scanner.add_check(Box::new(DummyCheck)); // apt check

        let findings = scanner.scan().unwrap();
        assert!(findings.is_empty()); // filtered out
    }

    #[test]
    fn scanner_runs_matching_check() {
        let tmp = tempfile::tempdir().unwrap();
        let dpkg_dir = tmp.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg_dir).unwrap();
        std::fs::write(dpkg_dir.join("status"), "").unwrap();

        let config = PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let mut scanner = PkgMonScanner::new(config);
        scanner.add_check(Box::new(DummyCheck));

        let findings = scanner.scan().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "dummy-001");
    }

    #[test]
    fn detect_returns_managers() {
        let tmp = tempfile::tempdir().unwrap();
        let dpkg_dir = tmp.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg_dir).unwrap();
        std::fs::write(dpkg_dir.join("status"), "").unwrap();

        let config = PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let scanner = PkgMonScanner::new(config);
        let managers = scanner.detect();
        assert!(managers.contains(&PackageManager::Apt));
    }
}
