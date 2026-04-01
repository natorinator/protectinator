//! Container scanning commands
//!
//! List and scan nspawn and Docker containers for security issues.

use clap::{Args, Subcommand, ValueEnum};
use protectinator_container::{discover, Container, ContainerRuntime, ContainerScanner, ContainerState};
use protectinator_container::filesystem::ContainerFs;
use protectinator_container::packages;
use protectinator_core::Severity;
use std::path::PathBuf;
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

    /// Generate SBOM for container packages
    ///
    /// Creates a CycloneDX 1.5 SBOM from packages installed in a container.
    /// Supports dpkg (Debian/Ubuntu) and apk (Alpine) package managers.
    Sbom(ContainerSbomArgs),
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

    /// Skip live CVE vulnerability scanning (requires network)
    #[arg(long)]
    skip_vulnerability: bool,

    /// Offline mode (skips CVE vulnerability scanning)
    #[arg(long)]
    offline: bool,
}

#[derive(Args)]
pub struct ContainerSbomArgs {
    /// Container name (use --all for all containers)
    #[arg(group = "target")]
    name: Option<String>,

    /// Generate SBOMs for all discovered containers
    #[arg(long, group = "target")]
    all: bool,

    /// Filter by container runtime
    #[arg(long, value_enum)]
    runtime: Option<RuntimeFilter>,

    /// Save SBOMs to default storage location for cross-repo queries
    #[arg(long)]
    save: bool,

    /// Custom output directory
    #[arg(long)]
    output: Option<PathBuf>,
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
        ContainerCommands::Sbom(args) => run_sbom(args, format),
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
        .skip_suid(args.skip_suid)
        .skip_vulnerability(args.skip_vulnerability || args.offline);

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

        // Store scan results in history database
        let scan_key = format!("container:{}", target.name);
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

fn run_sbom(args: ContainerSbomArgs, format: &str) -> anyhow::Result<()> {
    let containers = discover_containers(args.runtime);
    let is_json = format == "json";

    if containers.is_empty() {
        anyhow::bail!("No containers found.");
    }

    let targets: Vec<&Container> = if args.all {
        containers.iter().collect()
    } else if let Some(ref name) = args.name {
        match containers.iter().find(|c| c.name == *name) {
            Some(c) => vec![c],
            None => {
                let available: Vec<&str> = containers.iter().map(|c| c.name.as_str()).collect();
                anyhow::bail!(
                    "Container '{}' not found. Available: {}",
                    name,
                    available.join(", ")
                );
            }
        }
    } else {
        anyhow::bail!("Specify a container name or use --all");
    };

    // Determine save directory
    let save_dir = if args.save {
        let home = std::env::var("HOME")
            .map_err(|_| anyhow::anyhow!("HOME not set"))?;
        Some(PathBuf::from(home).join(".local/share/protectinator/sboms"))
    } else {
        args.output.clone()
    };

    if let Some(ref dir) = save_dir {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("Failed to create SBOM directory: {}", e))?;
    }

    for target in &targets {
        // Skip containers with inaccessible filesystems
        if !target.root_path.is_dir() {
            if !is_json {
                println!(
                    "  Skipping {} — filesystem not accessible",
                    target.name
                );
            }
            continue;
        }

        let fs = ContainerFs::new(&target.root_path);
        let pkgs = packages::extract_packages(&fs);

        let os_pretty = target
            .os_info
            .as_ref()
            .map(|o| o.pretty_name.as_str());

        let sbom = packages::generate_container_sbom(&pkgs, &target.name, os_pretty);

        if let Some(ref dir) = save_dir {
            let filename = format!("container-{}.cdx.json", target.name);
            let path = dir.join(&filename);
            let json_str = serde_json::to_string_pretty(&sbom)?;
            std::fs::write(&path, json_str)
                .map_err(|e| anyhow::anyhow!("Failed to write {}: {}", path.display(), e))?;

            if !is_json {
                println!(
                    "  \x1b[32m✓\x1b[0m {} — {} packages ({}), saved to {}",
                    target.name,
                    pkgs.len(),
                    target.runtime,
                    path.display()
                );
            }
        } else {
            // Print to stdout
            if !is_json {
                println!(
                    "  {} — {} packages ({})",
                    target.name,
                    pkgs.len(),
                    target.runtime
                );
            }
            println!("{}", serde_json::to_string_pretty(&sbom)?);
        }
    }

    Ok(())
}
