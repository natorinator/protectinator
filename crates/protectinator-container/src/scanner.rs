//! Container scan orchestration
//!
//! Coordinates running all container security checks against a container.

use crate::checks::hardening::HardeningCheck;
use crate::checks::os_version::OsVersionCheck;
use crate::checks::packages::PackageCheck;
use crate::checks::persistence::PersistenceCheck;
use crate::checks::rootkit::RootkitCheck;
use crate::checks::suid::SuidCheck;
use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use crate::types::{Container, ContainerScanResults};
use protectinator_core::{Finding, FindingSource, ScanResults, SystemInfo};
use tracing::{debug, info};

/// Scanner that runs all container security checks
pub struct ContainerScanner {
    skip_packages: bool,
    skip_rootkit: bool,
    skip_persistence: bool,
    skip_hardening: bool,
    skip_os_version: bool,
    skip_suid: bool,
}

impl ContainerScanner {
    /// Create a new container scanner with all checks enabled
    pub fn new() -> Self {
        Self {
            skip_packages: false,
            skip_rootkit: false,
            skip_persistence: false,
            skip_hardening: false,
            skip_os_version: false,
            skip_suid: false,
        }
    }

    /// Skip package checks
    pub fn skip_packages(mut self, skip: bool) -> Self {
        self.skip_packages = skip;
        self
    }

    /// Skip rootkit checks
    pub fn skip_rootkit(mut self, skip: bool) -> Self {
        self.skip_rootkit = skip;
        self
    }

    /// Skip persistence checks
    pub fn skip_persistence(mut self, skip: bool) -> Self {
        self.skip_persistence = skip;
        self
    }

    /// Skip hardening checks
    pub fn skip_hardening(mut self, skip: bool) -> Self {
        self.skip_hardening = skip;
        self
    }

    /// Skip OS version checks
    pub fn skip_os_version(mut self, skip: bool) -> Self {
        self.skip_os_version = skip;
        self
    }

    /// Skip SUID/SGID binary audit
    pub fn skip_suid(mut self, skip: bool) -> Self {
        self.skip_suid = skip;
        self
    }

    /// Scan a container and return results
    pub fn scan(&self, container: &Container) -> ContainerScanResults {
        info!("Scanning container: {} ({})", container.name, container.runtime);

        let fs = ContainerFs::new(&container.root_path);
        let mut all_findings: Vec<Finding> = Vec::new();

        let checks: Vec<Box<dyn ContainerCheck>> = self.build_checks();

        for check in &checks {
            debug!("Running check: {} ({})", check.name(), check.id());
            let check_findings = check.run(&fs);
            debug!("  {} findings", check_findings.len());
            all_findings.extend(check_findings);
        }

        // Wrap all findings with container source info
        let tagged_findings: Vec<Finding> = all_findings
            .into_iter()
            .map(|mut f| {
                f.source = FindingSource::Container {
                    container_name: container.name.clone(),
                    container_type: container.runtime.to_string(),
                    inner_source: Box::new(f.source),
                };
                f
            })
            .collect();

        // Build scan results
        let system_info = SystemInfo {
            os_name: container
                .os_info
                .as_ref()
                .map(|o| o.id.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            os_version: container
                .os_info
                .as_ref()
                .map(|o| o.version.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            hostname: container.name.clone(),
            architecture: std::env::consts::ARCH.to_string(),
            is_elevated: false, // Container scans from host don't need elevation
            kernel_version: None,
        };

        let mut results = ScanResults::new(system_info);
        for finding in tagged_findings {
            results.add_finding(finding);
        }
        results.summary.total_checks = checks.len();
        results.summary.checks_passed = checks.len();
        results.complete();

        info!(
            "Container scan complete: {} findings",
            results.findings.len()
        );

        ContainerScanResults {
            container: container.clone(),
            scan_results: results,
        }
    }

    /// Build the list of checks to run
    fn build_checks(&self) -> Vec<Box<dyn ContainerCheck>> {
        let mut checks: Vec<Box<dyn ContainerCheck>> = Vec::new();

        if !self.skip_os_version {
            checks.push(Box::new(OsVersionCheck));
        }
        if !self.skip_packages {
            checks.push(Box::new(PackageCheck));
        }
        if !self.skip_rootkit {
            checks.push(Box::new(RootkitCheck));
        }
        if !self.skip_persistence {
            checks.push(Box::new(PersistenceCheck));
        }
        if !self.skip_hardening {
            checks.push(Box::new(HardeningCheck));
        }
        if !self.skip_suid {
            checks.push(Box::new(SuidCheck));
        }

        checks
    }
}

impl Default for ContainerScanner {
    fn default() -> Self {
        Self::new()
    }
}
