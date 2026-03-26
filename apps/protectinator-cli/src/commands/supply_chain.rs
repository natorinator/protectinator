//! Supply chain security scanning commands
//!
//! Scan developer workstations and CI/CD systems for software supply chain
//! compromises including known vulnerabilities, malicious packages, and
//! CI/CD misconfigurations.

use clap::{Args, Subcommand, ValueEnum};
use protectinator_core::Severity;
use protectinator_supply_chain::SupplyChainScanner;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum SupplyChainCommands {
    /// Scan for supply chain security issues
    ///
    /// Checks for known vulnerabilities (via OSV), malicious package indicators
    /// (.pth injection, shell profile tampering), and lock file integrity issues.
    Scan(SupplyChainScanArgs),

    /// Detect package ecosystems present
    ///
    /// Lists lock files and package ecosystems found without running security checks.
    Detect(SupplyChainDetectArgs),
}

#[derive(Args)]
pub struct SupplyChainScanArgs {
    /// Root filesystem path (default: current directory)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Run in offline mode (skip OSV API queries)
    #[arg(long)]
    offline: bool,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value_t = ScMinSeverity::Low)]
    min_severity: ScMinSeverity,

    /// Only scan a specific ecosystem
    #[arg(long, value_enum)]
    ecosystem: Option<ScEcosystem>,

    /// Skip OSV vulnerability scanning
    #[arg(long)]
    skip_osv: bool,

    /// Skip IOC detection (pth injection, shell profile, user systemd)
    #[arg(long)]
    skip_ioc: bool,

    /// Skip lock file discovery and parsing
    #[arg(long)]
    skip_lockfile: bool,

    /// Skip npm postinstall script audit
    #[arg(long)]
    skip_npm_postinstall: bool,

    /// Skip pip build hook inspection
    #[arg(long)]
    skip_pip_build_hooks: bool,

    /// Skip user systemd service audit
    #[arg(long)]
    skip_user_systemd: bool,

    /// Skip lock file git integrity check
    #[arg(long)]
    skip_lockfile_integrity: bool,

    /// Skip GitHub Actions security audit
    #[arg(long)]
    skip_cicd: bool,

    /// Skip known malware signature scanning
    #[arg(long)]
    skip_malware: bool,

    /// Skip package registry configuration audit
    #[arg(long)]
    skip_registry: bool,

    /// Skip CI/CD secrets exposure check
    #[arg(long)]
    skip_secrets: bool,
}

#[derive(Args)]
pub struct SupplyChainDetectArgs {
    /// Root filesystem path (default: current directory)
    #[arg(long)]
    root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScEcosystem {
    Python,
    Node,
    Rust,
}

impl ScEcosystem {
    fn as_str(&self) -> &str {
        match self {
            ScEcosystem::Python => "pypi",
            ScEcosystem::Node => "npm",
            ScEcosystem::Rust => "crates.io",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ScMinSeverity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl From<ScMinSeverity> for Severity {
    fn from(s: ScMinSeverity) -> Self {
        match s {
            ScMinSeverity::Info => Severity::Info,
            ScMinSeverity::Low => Severity::Low,
            ScMinSeverity::Medium => Severity::Medium,
            ScMinSeverity::High => Severity::High,
            ScMinSeverity::Critical => Severity::Critical,
        }
    }
}

pub fn run(cmd: SupplyChainCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        SupplyChainCommands::Scan(args) => run_scan(args, format),
        SupplyChainCommands::Detect(args) => run_detect(args, format),
    }
}

fn run_scan(args: SupplyChainScanArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let root = args
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

    if !root.exists() {
        anyhow::bail!("Root path '{}' does not exist.", root.display());
    }

    let scanner = SupplyChainScanner::new(root.clone())
        .offline(args.offline)
        .skip_osv(args.skip_osv)
        .skip_ioc(args.skip_ioc)
        .skip_lockfile(args.skip_lockfile)
        .skip_npm_postinstall(args.skip_npm_postinstall)
        .skip_pip_build_hooks(args.skip_pip_build_hooks)
        .skip_user_systemd(args.skip_user_systemd)
        .skip_lockfile_integrity(args.skip_lockfile_integrity)
        .skip_cicd(args.skip_cicd)
        .skip_malware(args.skip_malware)
        .skip_registry(args.skip_registry)
        .skip_secrets(args.skip_secrets)
        .ecosystem(args.ecosystem.map(|e| e.as_str().to_string()));

    let start = Instant::now();

    if !is_json {
        println!("Supply Chain Security Scan");
        println!("=========================");
        println!("  Root:    {}", root.display());
        println!("  Online:  {}", !args.offline);
        println!();
    }

    let results = scanner.scan();
    let duration = start.elapsed();

    let min_severity: Severity = args.min_severity.into();
    let filtered_findings: Vec<_> = results
        .scan_results
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();

    if is_json {
        let json = serde_json::to_string_pretty(&results)?;
        println!("{}", json);
    } else {
        if !results.ecosystems.is_empty() {
            println!(
                "  Ecosystems: {}",
                results.ecosystems.join(", ")
            );
        }
        println!(
            "  Lock files: {}, Packages: {}",
            results.lock_files_found, results.packages_scanned
        );
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
            results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Critical)
                .unwrap_or(&0),
            results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::High)
                .unwrap_or(&0),
            results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Medium)
                .unwrap_or(&0),
            results
                .scan_results
                .summary
                .findings_by_severity
                .get(&Severity::Low)
                .unwrap_or(&0),
            results
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

fn run_detect(args: SupplyChainDetectArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let root = args
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

    if !root.exists() {
        anyhow::bail!("Root path '{}' does not exist.", root.display());
    }

    let fs = protectinator_container::filesystem::ContainerFs::new(&root);
    let lock_files = protectinator_supply_chain::lockfile::discover_lock_files(&fs);

    if is_json {
        let info: Vec<serde_json::Value> = lock_files
            .iter()
            .map(|lf| {
                serde_json::json!({
                    "path": lf.path.display().to_string(),
                    "ecosystem": lf.ecosystem.to_string(),
                    "format": format!("{:?}", lf.format),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("Supply Chain Detection");
        println!("=====================");
        println!("  Root: {}", root.display());
        println!();

        if lock_files.is_empty() {
            println!("  No lock files found.");
        } else {
            println!(
                "  {:<12} {:<20} {}",
                "ECOSYSTEM", "FORMAT", "PATH"
            );
            println!(
                "  {:<12} {:<20} {}",
                "────────────",
                "────────────────────",
                "────────────────────────────────"
            );
            for lf in &lock_files {
                println!(
                    "  {:<12} {:<20} {}",
                    lf.ecosystem,
                    format!("{:?}", lf.format),
                    lf.path.display()
                );
            }
            println!();
            println!("  {} lock file(s) found", lock_files.len());
        }
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
