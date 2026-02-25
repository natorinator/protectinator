//! IoT scan orchestration
//!
//! Coordinates running both reused container checks and IoT-specific checks
//! against an IoT device filesystem.

use crate::checks::binary_integrity::BinaryIntegrityCheck;
use crate::checks::boot_integrity::BootIntegrityCheck;
use crate::checks::default_credentials::DefaultCredentialsCheck;
use crate::checks::device_tree::DeviceTreeCheck;
use crate::checks::iot_rootkit::IotRootkitCheck;
use crate::checks::kernel_integrity::KernelIntegrityCheck;
use crate::checks::motd_persistence::MotdPersistenceCheck;
use crate::checks::network_services::NetworkServicesCheck;
use crate::checks::pam_audit::PamAuditCheck;
use crate::checks::tmpfiles_persistence::TmpfilesPersistenceCheck;
use crate::checks::udev_audit::UdevAuditCheck;
use crate::checks::IotCheck;
use crate::platform;
use crate::types::{IotDevice, IotScanMode, IotScanResults};
use protectinator_container::checks::hardening::HardeningCheck;
use protectinator_container::checks::os_version::OsVersionCheck;
use protectinator_container::checks::packages::PackageCheck;
use protectinator_container::checks::persistence::PersistenceCheck;
use protectinator_container::checks::rootkit::RootkitCheck;
use protectinator_container::checks::suid::SuidCheck;
use protectinator_container::checks::ContainerCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, ScanResults, SystemInfo};
use std::path::PathBuf;
use tracing::{debug, info};

/// Scanner that runs container + IoT-specific checks against a device
pub struct IotScanner {
    name: String,
    scan_mode: IotScanMode,
    root_path: PathBuf,
    // Container check skip flags
    skip_packages: bool,
    skip_rootkit: bool,
    skip_persistence: bool,
    skip_hardening: bool,
    skip_os_version: bool,
    skip_suid: bool,
    // IoT check skip flags
    skip_binary_integrity: bool,
    skip_boot_integrity: bool,
    skip_pam_audit: bool,
    skip_udev_audit: bool,
    skip_motd_persistence: bool,
    skip_iot_rootkit: bool,
    skip_network_services: bool,
    skip_default_credentials: bool,
    skip_kernel_integrity: bool,
    skip_tmpfiles_persistence: bool,
    skip_device_tree: bool,
    // Meta flags
    iot_only: bool,
    tier1_only: bool,
}

impl IotScanner {
    /// Create a new IoT scanner
    pub fn new(name: String, scan_mode: IotScanMode, root_path: PathBuf) -> Self {
        Self {
            name,
            scan_mode,
            root_path,
            skip_packages: false,
            skip_rootkit: false,
            skip_persistence: false,
            skip_hardening: false,
            skip_os_version: false,
            skip_suid: false,
            skip_binary_integrity: false,
            skip_boot_integrity: false,
            skip_pam_audit: false,
            skip_udev_audit: false,
            skip_motd_persistence: false,
            skip_iot_rootkit: false,
            skip_network_services: false,
            skip_default_credentials: false,
            skip_kernel_integrity: false,
            skip_tmpfiles_persistence: false,
            skip_device_tree: false,
            iot_only: false,
            tier1_only: false,
        }
    }

    // Container check skip setters
    pub fn skip_packages(mut self, skip: bool) -> Self {
        self.skip_packages = skip;
        self
    }
    pub fn skip_rootkit(mut self, skip: bool) -> Self {
        self.skip_rootkit = skip;
        self
    }
    pub fn skip_persistence(mut self, skip: bool) -> Self {
        self.skip_persistence = skip;
        self
    }
    pub fn skip_hardening(mut self, skip: bool) -> Self {
        self.skip_hardening = skip;
        self
    }
    pub fn skip_os_version(mut self, skip: bool) -> Self {
        self.skip_os_version = skip;
        self
    }
    pub fn skip_suid(mut self, skip: bool) -> Self {
        self.skip_suid = skip;
        self
    }

    // IoT check skip setters
    pub fn skip_binary_integrity(mut self, skip: bool) -> Self {
        self.skip_binary_integrity = skip;
        self
    }
    pub fn skip_boot_integrity(mut self, skip: bool) -> Self {
        self.skip_boot_integrity = skip;
        self
    }
    pub fn skip_pam_audit(mut self, skip: bool) -> Self {
        self.skip_pam_audit = skip;
        self
    }
    pub fn skip_udev_audit(mut self, skip: bool) -> Self {
        self.skip_udev_audit = skip;
        self
    }
    pub fn skip_motd_persistence(mut self, skip: bool) -> Self {
        self.skip_motd_persistence = skip;
        self
    }
    pub fn skip_iot_rootkit(mut self, skip: bool) -> Self {
        self.skip_iot_rootkit = skip;
        self
    }
    pub fn skip_network_services(mut self, skip: bool) -> Self {
        self.skip_network_services = skip;
        self
    }
    pub fn skip_default_credentials(mut self, skip: bool) -> Self {
        self.skip_default_credentials = skip;
        self
    }
    pub fn skip_kernel_integrity(mut self, skip: bool) -> Self {
        self.skip_kernel_integrity = skip;
        self
    }
    pub fn skip_tmpfiles_persistence(mut self, skip: bool) -> Self {
        self.skip_tmpfiles_persistence = skip;
        self
    }
    pub fn skip_device_tree(mut self, skip: bool) -> Self {
        self.skip_device_tree = skip;
        self
    }

    // Meta flags
    pub fn iot_only(mut self, iot_only: bool) -> Self {
        self.iot_only = iot_only;
        self
    }
    pub fn tier1_only(mut self, tier1_only: bool) -> Self {
        self.tier1_only = tier1_only;
        self
    }

    /// Run the scan and return results
    pub fn scan(&self) -> IotScanResults {
        let fs = ContainerFs::new(&self.root_path);

        info!(
            "Scanning IoT device '{}' (mode: {}, root: {})",
            self.name,
            self.scan_mode,
            self.root_path.display()
        );

        // Detect device type
        let device_type = platform::detect_device(&fs);
        info!("Detected device type: {}", device_type);

        // Detect OS
        let os_info = fs.detect_os();

        let device = IotDevice {
            name: self.name.clone(),
            device_type,
            scan_mode: self.scan_mode,
            root_path: self.root_path.clone(),
            os_info,
        };

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut total_checks: usize = 0;

        // Run reused container checks (unless --iot-only)
        if !self.iot_only {
            let container_checks = self.build_container_checks();
            total_checks += container_checks.len();
            for check in &container_checks {
                debug!("Running container check: {} ({})", check.name(), check.id());
                let findings = check.run(&fs);
                debug!("  {} findings", findings.len());
                all_findings.extend(findings);
            }
        }

        // Run IoT-specific checks
        let iot_checks = self.build_iot_checks();
        total_checks += iot_checks.len();
        let is_local = self.scan_mode == IotScanMode::Local;

        for check in &iot_checks {
            if check.requires_local() && !is_local {
                debug!(
                    "Skipping check {} (requires local mode)",
                    check.name()
                );
                continue;
            }
            debug!("Running IoT check: {} ({})", check.name(), check.id());
            let findings = check.run(&fs);
            debug!("  {} findings", findings.len());
            all_findings.extend(findings);
        }

        // Wrap all findings with IoT source info
        let device_type_str = device.device_type.to_string();
        let scan_mode_str = device.scan_mode.to_string();
        let tagged_findings: Vec<Finding> = all_findings
            .into_iter()
            .map(|mut f| {
                f.source = FindingSource::IoT {
                    device_name: self.name.clone(),
                    device_type: device_type_str.clone(),
                    scan_mode: scan_mode_str.clone(),
                    inner_source: Box::new(f.source),
                };
                f
            })
            .collect();

        // Build scan results
        let arch = platform::detect_architecture(&fs);
        let system_info = SystemInfo {
            os_name: device
                .os_info
                .as_ref()
                .map(|o| o.id.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            os_version: device
                .os_info
                .as_ref()
                .map(|o| o.version.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            hostname: self.name.clone(),
            architecture: arch,
            is_elevated: false,
            kernel_version: None,
        };

        let mut results = ScanResults::new(system_info);
        for finding in tagged_findings {
            results.add_finding(finding);
        }
        results.summary.total_checks = total_checks;
        results.summary.checks_passed = total_checks;
        results.complete();

        info!(
            "IoT scan complete: {} findings from {} checks",
            results.findings.len(),
            total_checks
        );

        IotScanResults {
            device,
            scan_results: results,
        }
    }

    fn build_container_checks(&self) -> Vec<Box<dyn ContainerCheck>> {
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

    fn build_iot_checks(&self) -> Vec<Box<dyn IotCheck>> {
        let mut checks: Vec<Box<dyn IotCheck>> = Vec::new();

        // Tier 1 — Critical
        if !self.skip_binary_integrity {
            checks.push(Box::new(BinaryIntegrityCheck));
        }
        if !self.skip_boot_integrity {
            checks.push(Box::new(BootIntegrityCheck));
        }
        if !self.skip_iot_rootkit {
            checks.push(Box::new(IotRootkitCheck));
        }
        if !self.skip_pam_audit {
            checks.push(Box::new(PamAuditCheck));
        }
        if !self.skip_udev_audit {
            checks.push(Box::new(UdevAuditCheck));
        }
        if !self.skip_motd_persistence {
            checks.push(Box::new(MotdPersistenceCheck));
        }

        // Tier 2 — Important (skip if tier1_only)
        if !self.tier1_only {
            if !self.skip_default_credentials {
                checks.push(Box::new(DefaultCredentialsCheck));
            }
            if !self.skip_network_services {
                checks.push(Box::new(NetworkServicesCheck));
            }
            if !self.skip_kernel_integrity {
                checks.push(Box::new(KernelIntegrityCheck));
            }
            if !self.skip_tmpfiles_persistence {
                checks.push(Box::new(TmpfilesPersistenceCheck));
            }

            // Tier 3 — Pi-specific
            if !self.skip_device_tree {
                checks.push(Box::new(DeviceTreeCheck));
            }
        }

        checks
    }
}
