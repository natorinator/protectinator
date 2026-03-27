//! Container scanning commands
//!
//! List and scan nspawn and Docker containers for security issues.

use clap::{Args, Subcommand, ValueEnum};
use protectinator_container::{discover, Container, ContainerRuntime, ContainerScanner, ContainerState};
use protectinator_core::Severity;
use std::time::Instant;

#[derive(Subcommand)]
pub enum ContainerCommands {
    /// List discovered containers
    ///
    /// Enumerate nspawn and Docker containers on the system.
    List(ContainerListArgs),

    /// Scan a container for security issues
    ///
    /// Examines the container's filesystem from the host to check for
    /// rootkits, outdated packages, persistence mechanisms, and more.
    Scan(ContainerScanArgs),
}

#[derive(Args)]
pub struct ContainerListArgs {
    /// Filter by container runtime
    #[arg(long, value_enum)]
    runtime: Option<RuntimeFilter>,
}

#[derive(Args)]
pub struct ContainerScanArgs {
    /// Container name to scan (use --all to scan all containers)
    #[arg(group = "target")]
    name: Option<String>,

    /// Scan all discovered containers
    #[arg(long, group = "target")]
    all: bool,

    /// Filter by container runtime
    #[arg(long, value_enum)]
    runtime: Option<RuntimeFilter>,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value_t = ContainerMinSeverity::Low)]
    min_severity: ContainerMinSeverity,

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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RuntimeFilter {
    /// nspawn containers only
    Nspawn,
    /// Docker containers only
    Docker,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ContainerMinSeverity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl From<ContainerMinSeverity> for Severity {
    fn from(s: ContainerMinSeverity) -> Self {
        match s {
            ContainerMinSeverity::Info => Severity::Info,
            ContainerMinSeverity::Low => Severity::Low,
            ContainerMinSeverity::Medium => Severity::Medium,
            ContainerMinSeverity::High => Severity::High,
            ContainerMinSeverity::Critical => Severity::Critical,
        }
    }
}

pub fn run(cmd: ContainerCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        ContainerCommands::List(args) => run_list(args, format),
        ContainerCommands::Scan(args) => run_scan(args, format),
    }
}

/// Discover containers with optional runtime filter
fn discover_containers(runtime: Option<RuntimeFilter>) -> Vec<Container> {
    match runtime {
        Some(RuntimeFilter::Nspawn) => discover::list_nspawn_containers(),
        Some(RuntimeFilter::Docker) => discover::list_docker_containers(),
        None => discover::list_all_containers(),
    }
}

fn run_list(args: ContainerListArgs, format: &str) -> anyhow::Result<()> {
    let containers = discover_containers(args.runtime);
    let is_json = format == "json";

    if containers.is_empty() {
        if is_json {
            println!("[]");
        } else {
            println!("No containers found.");
            println!();
            match args.runtime {
                Some(RuntimeFilter::Nspawn) => {
                    println!("Searched: /var/lib/machines/");
                    println!("Tip: Ensure you have read access to /var/lib/machines/ (may require root).");
                }
                Some(RuntimeFilter::Docker) => {
                    println!("Tip: Ensure Docker is running and you have access to the Docker socket.");
                }
                None => {
                    println!("Searched: /var/lib/machines/ (nspawn), docker ps (Docker)");
                    println!("Tip: May require root or Docker group membership.");
                }
            }
        }
        return Ok(());
    }

    if is_json {
        let json = serde_json::to_string_pretty(&containers)?;
        println!("{}", json);
    } else {
        println!("Discovered Containers");
        println!("═══════════════════════════════════════════════════════════════");
        println!();
        println!(
            "  {:<30} {:<10} {:<10} {:<30}",
            "NAME", "RUNTIME", "STATE", "OS"
        );
        println!(
            "  {:<30} {:<10} {:<10} {:<30}",
            "──────────────────────────────",
            "──────────",
            "──────────",
            "──────────────────────────────"
        );

        for container in &containers {
            let os = container
                .os_info
                .as_ref()
                .map(|o| o.pretty_name.as_str())
                .unwrap_or("—");

            let state_colored = match container.state {
                ContainerState::Running => format!("\x1b[32m{}\x1b[0m", container.state),
                ContainerState::Stopped => format!("\x1b[33m{}\x1b[0m", container.state),
                ContainerState::Unknown => format!("\x1b[90m{}\x1b[0m", container.state),
            };

            println!(
                "  {:<30} {:<10} {:<20} {:<30}",
                container.name, container.runtime, state_colored, os
            );
        }

        println!();

        // Summary by runtime
        let nspawn_count = containers.iter().filter(|c| c.runtime == ContainerRuntime::Nspawn).count();
        let docker_count = containers.iter().filter(|c| c.runtime == ContainerRuntime::Docker).count();
        let running_count = containers.iter().filter(|c| c.state == ContainerState::Running).count();

        let mut parts = Vec::new();
        if nspawn_count > 0 {
            parts.push(format!("{} nspawn", nspawn_count));
        }
        if docker_count > 0 {
            parts.push(format!("{} docker", docker_count));
        }

        println!(
            "  {} container(s) found ({}, {} running)",
            containers.len(),
            parts.join(", "),
            running_count
        );
    }

    Ok(())
}

fn run_scan(args: ContainerScanArgs, format: &str) -> anyhow::Result<()> {
    let containers = discover_containers(args.runtime);
    let is_json = format == "json";

    if containers.is_empty() {
        anyhow::bail!(
            "No containers found. Ensure you have access to Docker or /var/lib/machines/."
        );
    }

    let targets: Vec<&Container> = if args.all {
        containers.iter().collect()
    } else if let Some(ref name) = args.name {
        let found = containers.iter().find(|c| c.name == *name);
        match found {
            Some(c) => vec![c],
            None => {
                let available: Vec<&str> = containers.iter().map(|c| c.name.as_str()).collect();
                anyhow::bail!(
                    "Container '{}' not found. Available containers: {}",
                    name,
                    available.join(", ")
                );
            }
        }
    } else {
        anyhow::bail!("Specify a container name or use --all to scan all containers");
    };

    let scanner = ContainerScanner::new()
        .skip_packages(args.skip_packages)
        .skip_rootkit(args.skip_rootkit)
        .skip_persistence(args.skip_persistence)
        .skip_hardening(args.skip_hardening)
        .skip_os_version(args.skip_os_version)
        .skip_suid(args.skip_suid);

    let min_severity: Severity = args.min_severity.into();

    for target in &targets {
        // Docker containers must be running to have an accessible merged filesystem
        if target.runtime == ContainerRuntime::Docker && target.state != ContainerState::Running {
            if !is_json {
                println!(
                    "Skipping {} ({}) — Docker container must be running to scan",
                    target.name, target.state
                );
                println!();
            }
            continue;
        }

        // Verify the root path is accessible
        if !target.root_path.is_dir() {
            if !is_json {
                println!(
                    "Skipping {} — filesystem not accessible at {}",
                    target.name,
                    target.root_path.display()
                );
                println!();
            }
            continue;
        }

        let start = Instant::now();

        if !is_json {
            println!("Scanning container: {} ({})", target.name, target.runtime);
            if let Some(ref os) = target.os_info {
                println!("  OS: {}", os.pretty_name);
            }
            println!("  Root: {}", target.root_path.display());
            println!();
        }

        let scan_results = scanner.scan(target);
        let duration = start.elapsed();

        // Filter by minimum severity
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
            if filtered_findings.is_empty() {
                println!("  No findings at {} severity or above.", min_severity);
            } else {
                // Group by severity
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
