//! Supply chain scan orchestration
//!
//! Coordinates running all supply chain security checks, including
//! lock file discovery, package parsing, and check execution.

use crate::checks::cicd_actions::CicdActionsCheck;
use crate::checks::cicd_secrets::CicdSecretsCheck;
use crate::checks::lockfile_integrity::LockfileIntegrityCheck;
use crate::checks::malware_signatures::MalwareSignaturesCheck;
use crate::checks::npm_postinstall::NpmPostinstallCheck;
use crate::checks::pip_build_hooks::PipBuildHooksCheck;
use crate::checks::pth_injection::PthInjectionCheck;
use crate::checks::registry_audit::RegistryAuditCheck;
use crate::checks::shell_profile::ShellProfileCheck;
use crate::checks::user_systemd::UserSystemdCheck;
use crate::checks::vulnerability::VulnerabilityCheck;
use crate::checks::SupplyChainCheck;
use crate::lockfile;
use crate::trust::TrustVerificationCheck;
use crate::types::{SupplyChainContext, SupplyChainScanResults};
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, ScanResults, SystemInfo};
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::{debug, info};

/// Scanner that runs supply chain security checks
pub struct SupplyChainScanner {
    root: PathBuf,
    online: bool,
    skip_osv: bool,
    skip_ioc: bool,
    skip_lockfile: bool,
    skip_npm_postinstall: bool,
    skip_pip_build_hooks: bool,
    skip_user_systemd: bool,
    skip_lockfile_integrity: bool,
    skip_cicd: bool,
    skip_malware: bool,
    skip_registry: bool,
    skip_secrets: bool,
    skip_trust: bool,
    ecosystem_filter: Option<String>,
}

impl SupplyChainScanner {
    /// Create a new scanner with the given root path
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            online: true,
            skip_osv: false,
            skip_ioc: false,
            skip_lockfile: false,
            skip_npm_postinstall: false,
            skip_pip_build_hooks: false,
            skip_user_systemd: false,
            skip_lockfile_integrity: false,
            skip_cicd: false,
            skip_malware: false,
            skip_registry: false,
            skip_secrets: false,
            skip_trust: false,
            ecosystem_filter: None,
        }
    }

    pub fn offline(mut self, offline: bool) -> Self {
        self.online = !offline;
        self
    }

    pub fn skip_osv(mut self, skip: bool) -> Self {
        self.skip_osv = skip;
        self
    }

    pub fn skip_ioc(mut self, skip: bool) -> Self {
        self.skip_ioc = skip;
        self
    }

    pub fn skip_lockfile(mut self, skip: bool) -> Self {
        self.skip_lockfile = skip;
        self
    }

    pub fn skip_npm_postinstall(mut self, skip: bool) -> Self {
        self.skip_npm_postinstall = skip;
        self
    }

    pub fn skip_pip_build_hooks(mut self, skip: bool) -> Self {
        self.skip_pip_build_hooks = skip;
        self
    }

    pub fn skip_user_systemd(mut self, skip: bool) -> Self {
        self.skip_user_systemd = skip;
        self
    }

    pub fn skip_lockfile_integrity(mut self, skip: bool) -> Self {
        self.skip_lockfile_integrity = skip;
        self
    }

    pub fn skip_cicd(mut self, skip: bool) -> Self {
        self.skip_cicd = skip;
        self
    }

    pub fn skip_malware(mut self, skip: bool) -> Self {
        self.skip_malware = skip;
        self
    }

    pub fn skip_registry(mut self, skip: bool) -> Self {
        self.skip_registry = skip;
        self
    }

    pub fn skip_secrets(mut self, skip: bool) -> Self {
        self.skip_secrets = skip;
        self
    }

    pub fn skip_trust(mut self, skip: bool) -> Self {
        self.skip_trust = skip;
        self
    }

    pub fn ecosystem(mut self, eco: Option<String>) -> Self {
        self.ecosystem_filter = eco;
        self
    }

    /// Run the scan and return results
    pub fn scan(&self) -> SupplyChainScanResults {
        let fs = ContainerFs::new(&self.root);

        info!(
            "Supply chain scan starting (root: {}, online: {})",
            self.root.display(),
            self.online
        );

        // Discover user home directories
        let user_homes = discover_user_homes(&fs);
        debug!("Found {} user home directories", user_homes.len());

        // Discover and parse lock files
        let lock_files = if !self.skip_lockfile {
            lockfile::discover_lock_files(&fs)
        } else {
            Vec::new()
        };
        info!("Found {} lock files", lock_files.len());

        let mut packages = Vec::new();
        for lf in &lock_files {
            let parsed = lockfile::parse_lock_file(&fs, lf);
            debug!(
                "Parsed {} packages from {}",
                parsed.len(),
                lf.path.display()
            );
            packages.extend(parsed);
        }

        // Filter by ecosystem if requested
        if let Some(ref eco_filter) = self.ecosystem_filter {
            let eco_lower = eco_filter.to_lowercase();
            packages.retain(|p| p.ecosystem.to_string() == eco_lower);
        }

        info!("Total packages to scan: {}", packages.len());

        // Build context
        let ctx = SupplyChainContext {
            root: self.root.clone(),
            user_homes,
            lock_files,
            packages,
            online: self.online,
        };

        // Collect ecosystems
        let ecosystems: Vec<String> = {
            let mut set = HashSet::new();
            for p in &ctx.packages {
                set.insert(p.ecosystem.to_string());
            }
            let mut v: Vec<String> = set.into_iter().collect();
            v.sort();
            v
        };

        // Build checks
        let checks = self.build_checks();
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut total_checks = 0;

        for check in &checks {
            if check.requires_network() && !self.online {
                debug!("Skipping {} (requires network, running offline)", check.name());
                continue;
            }
            total_checks += 1;
            debug!("Running check: {} ({})", check.name(), check.id());
            let findings = check.run(&fs, &ctx);
            debug!("  {} findings", findings.len());
            all_findings.extend(findings);
        }

        // Build scan results
        let system_info = SystemInfo {
            os_name: "developer-workstation".to_string(),
            os_version: String::new(),
            hostname: hostname(),
            architecture: std::env::consts::ARCH.to_string(),
            is_elevated: false,
            kernel_version: None,
        };

        let packages_scanned = ctx.packages.len();
        let lock_files_found = ctx.lock_files.len();

        let mut results = ScanResults::new(system_info);
        for finding in all_findings {
            results.add_finding(finding);
        }
        results.summary.total_checks = total_checks;
        results.summary.checks_passed = total_checks;
        results.complete();

        info!(
            "Supply chain scan complete: {} findings from {} checks, {} packages scanned",
            results.findings.len(),
            total_checks,
            packages_scanned
        );

        SupplyChainScanResults {
            scan_results: results,
            packages_scanned,
            lock_files_found,
            ecosystems,
        }
    }

    fn build_checks(&self) -> Vec<Box<dyn SupplyChainCheck>> {
        let mut checks: Vec<Box<dyn SupplyChainCheck>> = Vec::new();

        if !self.skip_osv {
            checks.push(Box::new(VulnerabilityCheck));
        }

        if !self.skip_ioc {
            checks.push(Box::new(PthInjectionCheck));
            checks.push(Box::new(ShellProfileCheck));
            if !self.skip_user_systemd {
                checks.push(Box::new(UserSystemdCheck));
            }
        }

        // Phase 2 — Package manager deep inspection
        if !self.skip_npm_postinstall {
            checks.push(Box::new(NpmPostinstallCheck));
        }
        if !self.skip_pip_build_hooks {
            checks.push(Box::new(PipBuildHooksCheck));
        }
        if !self.skip_lockfile_integrity {
            checks.push(Box::new(LockfileIntegrityCheck));
        }

        // Phase 3 — CI/CD and advanced detection
        if !self.skip_malware {
            checks.push(Box::new(MalwareSignaturesCheck));
        }
        if !self.skip_cicd {
            checks.push(Box::new(CicdActionsCheck));
        }
        if !self.skip_secrets {
            checks.push(Box::new(CicdSecretsCheck));
        }
        if !self.skip_registry {
            checks.push(Box::new(RegistryAuditCheck));
        }

        // Phase 4 — Cryptographic trust verification
        if !self.skip_trust {
            checks.push(Box::new(TrustVerificationCheck));
        }

        checks
    }
}

/// Discover user home directories
fn discover_user_homes(fs: &ContainerFs) -> Vec<PathBuf> {
    let mut homes = Vec::new();

    // Check /home/*
    if let Ok(entries) = fs.read_dir("/home") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                homes.push(path);
            }
        }
    }

    // Check /root
    let root_home = fs.resolve("/root");
    if root_home.is_dir() {
        homes.push(root_home);
    }

    // Check current user's home from env (for local scans)
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);
        if home_path.is_dir() && !homes.contains(&home_path) {
            homes.push(home_path);
        }
    }

    homes
}

/// Get hostname for system info
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
