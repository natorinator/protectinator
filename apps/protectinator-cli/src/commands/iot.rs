//! IoT / Raspberry Pi scanning commands
//!
//! Scan IoT devices for security issues, either locally on the device
//! or from a mounted SD card / sshfs mount.

use clap::{Args, Subcommand, ValueEnum};
use protectinator_core::Severity;
use protectinator_iot::{IotScanMode, IotScanner};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum IotCommands {
    /// Scan an IoT device for security issues
    ///
    /// Runs container checks (packages, rootkit, persistence, hardening, SUID, OS version)
    /// plus IoT-specific checks (binary integrity, boot partition, PAM audit, udev rules,
    /// MOTD persistence, IoT malware, default credentials, network services, kernel modules,
    /// tmpfiles persistence, device tree overlays).
    Scan(IotScanArgs),

    /// Detect device type and display info
    ///
    /// Identifies the Pi model, architecture, and OS without running security checks.
    Detect(IotDetectArgs),
}

#[derive(Args)]
pub struct IotScanArgs {
    /// Device name (for labeling results)
    #[arg(long, default_value = "iot-device")]
    name: String,

    /// Root filesystem path (omit for local scan, or /mnt/pi for mounted SD card)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Scan via SSH (e.g. pi@raspberrypi.local or just a hostname)
    #[arg(long)]
    ssh: Option<String>,

    /// SSH user (used with --ssh, default: pi)
    #[arg(long, default_value = "pi")]
    ssh_user: String,

    /// SSH port (used with --ssh, default: 22)
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

    /// SSH private key path (used with --ssh)
    #[arg(long)]
    ssh_key: Option<PathBuf>,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value_t = IotMinSeverity::Low)]
    min_severity: IotMinSeverity,

    /// Only run IoT-specific checks (skip reused container checks)
    #[arg(long)]
    iot_only: bool,

    /// Only run Tier 1 (critical) IoT checks
    #[arg(long)]
    tier1_only: bool,

    // Container check skip flags
    /// Skip package checks
    #[arg(long)]
    skip_packages: bool,

    /// Skip rootkit checks
    #[arg(long)]
    skip_rootkit: bool,

    /// Skip persistence checks
    #[arg(long)]
    skip_persistence: bool,

    /// Skip hardening checks
    #[arg(long)]
    skip_hardening: bool,

    /// Skip OS version checks
    #[arg(long)]
    skip_os_version: bool,

    /// Skip SUID/SGID binary audit
    #[arg(long)]
    skip_suid: bool,

    // IoT check skip flags
    /// Skip binary integrity verification
    #[arg(long)]
    skip_binary_integrity: bool,

    /// Skip boot partition integrity check
    #[arg(long)]
    skip_boot_integrity: bool,

    /// Skip PAM module audit
    #[arg(long)]
    skip_pam_audit: bool,

    /// Skip udev rule audit
    #[arg(long)]
    skip_udev_audit: bool,

    /// Skip MOTD persistence check
    #[arg(long)]
    skip_motd_persistence: bool,

    /// Skip IoT rootkit/malware check
    #[arg(long)]
    skip_iot_rootkit: bool,

    /// Skip network services audit
    #[arg(long)]
    skip_network_services: bool,

    /// Skip default credentials check
    #[arg(long)]
    skip_default_credentials: bool,

    /// Skip kernel module integrity check
    #[arg(long)]
    skip_kernel_integrity: bool,

    /// Skip tmpfiles.d persistence check
    #[arg(long)]
    skip_tmpfiles_persistence: bool,

    /// Skip device tree overlay validation
    #[arg(long)]
    skip_device_tree: bool,
}

#[derive(Args)]
pub struct IotDetectArgs {
    /// Root filesystem path (omit for local detection)
    #[arg(long)]
    root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum IotMinSeverity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl From<IotMinSeverity> for Severity {
    fn from(s: IotMinSeverity) -> Self {
        match s {
            IotMinSeverity::Info => Severity::Info,
            IotMinSeverity::Low => Severity::Low,
            IotMinSeverity::Medium => Severity::Medium,
            IotMinSeverity::High => Severity::High,
            IotMinSeverity::Critical => Severity::Critical,
        }
    }
}

pub fn run(cmd: IotCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        IotCommands::Scan(args) => run_scan(args, format),
        IotCommands::Detect(args) => run_detect(args, format),
    }
}

fn run_scan(args: IotScanArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";

    // Determine scan mode
    let (scan_mode, root_path) = if let Some(ref ssh_target) = args.ssh {
        // Parse user@host or just host
        let ssh_dest = if ssh_target.contains('@') {
            ssh_target.clone()
        } else {
            format!("{}@{}", args.ssh_user, ssh_target)
        };
        let mode = IotScanMode::Ssh {
            ssh_dest: ssh_dest.clone(),
        };
        (mode, PathBuf::from("/")) // root_path is placeholder for SSH mode
    } else {
        let root = args.root.clone().unwrap_or_else(|| PathBuf::from("/"));
        let mode = if args.root.is_some() {
            IotScanMode::Mounted
        } else {
            IotScanMode::Local
        };
        (mode, root)
    };

    // Validate root path for non-SSH modes
    if args.ssh.is_none() && !root_path.exists() {
        anyhow::bail!(
            "Root path '{}' does not exist. Provide a valid mount point with --root.",
            root_path.display()
        );
    }

    let scanner = IotScanner::new(args.name.clone(), scan_mode.clone(), root_path.clone())
        .iot_only(args.iot_only)
        .tier1_only(args.tier1_only)
        .skip_packages(args.skip_packages)
        .skip_rootkit(args.skip_rootkit)
        .skip_persistence(args.skip_persistence)
        .skip_hardening(args.skip_hardening)
        .skip_os_version(args.skip_os_version)
        .skip_suid(args.skip_suid)
        .skip_binary_integrity(args.skip_binary_integrity)
        .skip_boot_integrity(args.skip_boot_integrity)
        .skip_pam_audit(args.skip_pam_audit)
        .skip_udev_audit(args.skip_udev_audit)
        .skip_motd_persistence(args.skip_motd_persistence)
        .skip_iot_rootkit(args.skip_iot_rootkit)
        .skip_network_services(args.skip_network_services)
        .skip_default_credentials(args.skip_default_credentials)
        .skip_kernel_integrity(args.skip_kernel_integrity)
        .skip_tmpfiles_persistence(args.skip_tmpfiles_persistence)
        .skip_device_tree(args.skip_device_tree);

    let start = Instant::now();

    if !is_json {
        println!("IoT Security Scan");
        println!("=================");
        println!("  Device: {}", args.name);
        println!("  Mode:   {}", scan_mode);
        if args.ssh.is_some() {
            println!("  Target: {}", args.ssh.as_ref().unwrap());
        } else {
            println!("  Root:   {}", root_path.display());
        }
        println!();
    }

    let device_name = args.name.clone();
    let scan_results = if let Some(ref ssh_target) = args.ssh {
        // Build RemoteHost from SSH args
        let (user, hostname) = if ssh_target.contains('@') {
            let parts: Vec<&str> = ssh_target.splitn(2, '@').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (args.ssh_user.clone(), ssh_target.clone())
        };

        let mut host = protectinator_remote::RemoteHost::new(hostname)
            .with_user(user)
            .with_port(args.ssh_port);
        if let Some(ref key) = args.ssh_key {
            host = host.with_key(key);
        }

        scanner.scan_ssh(&host).map_err(|e| anyhow::anyhow!(e))?
    } else {
        scanner.scan()
    };
    let duration = start.elapsed();

    // Store scan results in history database
    let scan_key = format!("iot:{}", device_name);
    match protectinator_data::ScanStore::open(
        &protectinator_data::default_data_dir()
            .unwrap_or_default()
            .join("scan_history.db"),
    ) {
        Ok(db) => {
            if let Err(e) = db.store_scan(&scan_key, &scan_results.scan_results.findings, 0) {
                eprintln!("Warning: failed to save scan history: {}", e);
            }
        }
        Err(e) => eprintln!("Warning: failed to open scan history: {}", e),
    }

    let min_severity: Severity = args.min_severity.into();
    let filtered_findings: Vec<_> = scan_results
        .scan_results
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();

    if is_json {
        let json = serde_json::to_string_pretty(&scan_results)?;
        println!("{}", json);
    } else {
        // Print device info
        println!("  Device type: {}", scan_results.device.device_type);
        if let Some(ref os) = scan_results.device.os_info {
            println!("  OS: {}", os.pretty_name);
        }
        println!();

        if filtered_findings.is_empty() {
            println!("  No findings at {} severity or above.", min_severity);
        } else {
            let critical: Vec<_> = filtered_findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .collect();
            let high: Vec<_> = filtered_findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .collect();
            let medium: Vec<_> = filtered_findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .collect();
            let low: Vec<_> = filtered_findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .collect();
            let info: Vec<_> = filtered_findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .collect();

            print_severity_group("CRITICAL", &critical, "\x1b[91m");
            print_severity_group("HIGH", &high, "\x1b[93m");
            print_severity_group("MEDIUM", &medium, "\x1b[33m");
            print_severity_group("LOW", &low, "\x1b[36m");
            print_severity_group("INFO", &info, "\x1b[90m");
        }

        println!();
        println!(
            "  Summary: {} findings (C:{} H:{} M:{} L:{} I:{}) in {:?}",
            filtered_findings.len(),
            scan_results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Critical)
                .unwrap_or(&0),
            scan_results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::High)
                .unwrap_or(&0),
            scan_results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Medium)
                .unwrap_or(&0),
            scan_results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Low)
                .unwrap_or(&0),
            scan_results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Info)
                .unwrap_or(&0),
            duration
        );
        println!();
    }

    Ok(())
}

fn run_detect(args: IotDetectArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let root_path = args.root.clone().unwrap_or_else(|| PathBuf::from("/"));

    if !root_path.exists() {
        anyhow::bail!(
            "Root path '{}' does not exist.",
            root_path.display()
        );
    }

    let fs = protectinator_container::filesystem::ContainerFs::new(&root_path);
    let device_type = protectinator_iot::detect_device(&fs);
    let os_info = fs.detect_os();
    let arch = protectinator_iot::platform::detect_architecture(&fs);

    if is_json {
        let info = serde_json::json!({
            "device_type": format!("{}", device_type),
            "architecture": arch,
            "os": os_info,
            "root_path": root_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("IoT Device Detection");
        println!("====================");
        println!("  Device type:  {}", device_type);
        println!("  Architecture: {}", arch);
        if let Some(ref os) = os_info {
            println!("  OS:           {}", os.pretty_name);
            if let Some(eol) = os.eol {
                if eol {
                    println!("  EOL:          \x1b[91mYES - End of Life!\x1b[0m");
                } else {
                    println!("  EOL:          \x1b[32mNo\x1b[0m");
                }
            }
        } else {
            println!("  OS:           unknown");
        }
        println!("  Root:         {}", root_path.display());
    }

    Ok(())
}

fn print_severity_group(
    label: &str,
    findings: &[&&protectinator_core::Finding],
    color: &str,
) {
    if findings.is_empty() {
        return;
    }

    println!("  {}{}\x1b[0m ({}):", color, label, findings.len());
    for finding in findings {
        println!("    {} {}", color_bullet(label), finding.title);
        if let Some(ref resource) = finding.resource {
            println!("      Resource: {}", resource);
        }
        if let Some(ref remediation) = finding.remediation {
            println!("      Fix: {}", remediation);
        }
    }
    println!();
}

fn color_bullet(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "\x1b[91m●\x1b[0m",
        "HIGH" => "\x1b[93m●\x1b[0m",
        "MEDIUM" => "\x1b[33m●\x1b[0m",
        "LOW" => "\x1b[36m●\x1b[0m",
        _ => "\x1b[90m●\x1b[0m",
    }
}
