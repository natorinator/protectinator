//! Remote host scanning commands

use clap::{Args, Subcommand, ValueEnum};
use protectinator_core::Severity;
use protectinator_remote::{RemoteHost, RemoteScanner, ScanMode};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum RemoteCommands {
    /// Scan a remote host for security issues
    ///
    /// Connects via SSH and checks for CVE vulnerabilities, rootkit
    /// indicators, persistence mechanisms, and hardening issues.
    Scan(RemoteScanArgs),

    /// Test SSH connectivity to a remote host
    Test(RemoteTestArgs),
}

#[derive(Args)]
pub struct RemoteScanArgs {
    /// Remote host (hostname or IP)
    host: String,

    /// SSH user
    #[arg(long, short, default_value = "root")]
    user: String,

    /// SSH port
    #[arg(long, short, default_value_t = 22)]
    port: u16,

    /// Path to SSH private key
    #[arg(long, short = 'i')]
    key: Option<PathBuf>,

    /// Friendly name for this host
    #[arg(long)]
    name: Option<String>,

    /// Scan mode
    #[arg(long, value_enum, default_value_t = RemoteScanModeArg::Agentless)]
    mode: RemoteScanModeArg,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value_t = RemoteMinSeverity::Low)]
    min_severity: RemoteMinSeverity,

    /// Skip live CVE vulnerability scanning
    #[arg(long)]
    skip_vulnerability: bool,

    /// Offline mode (skip CVE scanning)
    #[arg(long)]
    offline: bool,

    /// Use sudo for privileged commands (when SSH user has passwordless sudo)
    #[arg(long)]
    sudo: bool,
}

#[derive(Args)]
pub struct RemoteTestArgs {
    /// Remote host (hostname or IP)
    host: String,

    /// SSH user
    #[arg(long, short, default_value = "root")]
    user: String,

    /// SSH port
    #[arg(long, short, default_value_t = 22)]
    port: u16,

    /// Path to SSH private key
    #[arg(long, short = 'i')]
    key: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RemoteScanModeArg {
    /// Run protectinator on remote host (must be installed)
    Agent,
    /// Gather data via SSH commands, analyze locally
    Agentless,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum RemoteMinSeverity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl From<RemoteMinSeverity> for Severity {
    fn from(s: RemoteMinSeverity) -> Self {
        match s {
            RemoteMinSeverity::Info => Severity::Info,
            RemoteMinSeverity::Low => Severity::Low,
            RemoteMinSeverity::Medium => Severity::Medium,
            RemoteMinSeverity::High => Severity::High,
            RemoteMinSeverity::Critical => Severity::Critical,
        }
    }
}

pub fn run(cmd: RemoteCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        RemoteCommands::Scan(args) => run_scan(args, format),
        RemoteCommands::Test(args) => run_test(args),
    }
}

fn build_host(hostname: &str, user: &str, port: u16, key: Option<PathBuf>, name: Option<String>) -> RemoteHost {
    let mut host = RemoteHost::new(hostname).with_user(user).with_port(port);
    if let Some(k) = key {
        host = host.with_key(k);
    }
    if let Some(n) = name {
        host = host.with_name(n);
    }
    host
}

fn run_test(args: RemoteTestArgs) -> anyhow::Result<()> {
    let host = build_host(&args.host, &args.user, args.port, args.key, None);

    print!("Testing SSH connection to {}...", host.display_name());

    match protectinator_remote::ssh::test_connection(&host) {
        Ok(()) => {
            println!(" \x1b[32mOK\x1b[0m");

            // Check if protectinator is available
            if protectinator_remote::ssh::has_protectinator(&host) {
                println!("  protectinator: \x1b[32minstalled\x1b[0m (agent mode available)");
            } else {
                println!("  protectinator: not installed (use --mode agentless)");
            }
        }
        Err(e) => {
            println!(" \x1b[91mFAILED\x1b[0m");
            println!("  {}", e);
        }
    }

    Ok(())
}

fn run_scan(args: RemoteScanArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let host = build_host(&args.host, &args.user, args.port, args.key, args.name)
        .with_sudo(args.sudo);

    let mode = match args.mode {
        RemoteScanModeArg::Agent => ScanMode::Agent,
        RemoteScanModeArg::Agentless => ScanMode::Agentless,
    };

    let min_severity: Severity = args.min_severity.into();

    if !is_json {
        println!("Scanning remote host: {} ({})", host.display_name(), mode);
        println!();
    }

    let start = Instant::now();

    let scanner = RemoteScanner::new(host, mode)
        .skip_vulnerability(args.skip_vulnerability || args.offline);

    let mut results = scanner
        .scan()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let duration = start.elapsed();

    // Apply suppressions
    let scan_key = format!("remote:{}", results.host.display_name());
    let suppressions = protectinator_core::suppress::Suppressions::load_default();
    results.scan_results.findings = suppressions.filter(
        std::mem::take(&mut results.scan_results.findings),
        Some(&scan_key),
    );

    // Store scan results in history database
    match protectinator_data::ScanStore::open(
        &protectinator_data::default_data_dir()
            .unwrap_or_default()
            .join("scan_history.db"),
    ) {
        Ok(db) => {
            if let Err(e) = db.store_scan(&scan_key, &results.scan_results.findings, 0) {
                eprintln!("Warning: failed to save scan history: {}", e);
            }
        }
        Err(e) => eprintln!("Warning: failed to open scan history: {}", e),
    }

    let filtered: Vec<_> = results
        .scan_results
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();

    if is_json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        if filtered.is_empty() {
            println!("  No findings at {} severity or above.", min_severity);
        } else {
            let critical: Vec<_> = filtered.iter().filter(|f| f.severity == Severity::Critical).collect();
            let high: Vec<_> = filtered.iter().filter(|f| f.severity == Severity::High).collect();
            let medium: Vec<_> = filtered.iter().filter(|f| f.severity == Severity::Medium).collect();
            let low: Vec<_> = filtered.iter().filter(|f| f.severity == Severity::Low).collect();

            print_group("CRITICAL", &critical, "\x1b[91m");
            print_group("HIGH", &high, "\x1b[93m");
            print_group("MEDIUM", &medium, "\x1b[33m");
            print_group("LOW", &low, "\x1b[36m");
        }

        println!();
        println!(
            "  Summary: {} findings (C:{} H:{} M:{} L:{} I:{}) in {:?}",
            filtered.len(),
            results.scan_results.summary.findings_by_severity.get(&Severity::Critical).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::High).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::Medium).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::Low).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::Info).unwrap_or(&0),
            duration,
        );
    }

    Ok(())
}

fn print_group(label: &str, findings: &[&&protectinator_core::Finding], color: &str) {
    if findings.is_empty() {
        return;
    }

    println!("  {}{}\x1b[0m ({}):", color, label, findings.len());
    for finding in findings {
        let bullet = match label {
            "CRITICAL" => "\x1b[91m●\x1b[0m",
            "HIGH" => "\x1b[93m●\x1b[0m",
            "MEDIUM" => "\x1b[33m●\x1b[0m",
            _ => "\x1b[36m●\x1b[0m",
        };
        println!("    {} {}", bullet, finding.title);
        if let Some(ref resource) = finding.resource {
            println!("      Resource: {}", resource);
        }
        if let Some(ref remediation) = finding.remediation {
            println!("      Fix: {}", remediation);
        }
    }
    println!();
}
