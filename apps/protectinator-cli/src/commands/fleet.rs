//! Fleet management commands

use clap::{Args, Subcommand};
use protectinator_fleet::{FleetConfig, FleetRunner, FleetScanResults};
use protectinator_fleet::runner::FleetScanOptions;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum FleetCommands {
    /// Scan the entire fleet (hosts, containers, repos)
    Scan(FleetScanArgs),

    /// Show fleet status from scan history
    Status,

    /// Generate a template fleet.toml config file
    Init(FleetInitArgs),
}

#[derive(Args)]
pub struct FleetScanArgs {
    /// Path to fleet config file (default: ~/.config/protectinator/fleet.toml)
    #[arg(long, short)]
    config: Option<PathBuf>,

    /// Only scan remote hosts
    #[arg(long)]
    hosts_only: bool,

    /// Only scan containers
    #[arg(long)]
    containers_only: bool,

    /// Only scan supply-chain repos
    #[arg(long)]
    repos_only: bool,

    /// Skip live CVE scanning (offline mode)
    #[arg(long)]
    offline: bool,
}

#[derive(Args)]
pub struct FleetInitArgs {
    /// Output path (default: ~/.config/protectinator/fleet.toml)
    #[arg(long, short)]
    output: Option<PathBuf>,
}

pub fn run(cmd: FleetCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        FleetCommands::Scan(args) => run_scan(args, format),
        FleetCommands::Status => run_status(format),
        FleetCommands::Init(args) => run_init(args),
    }
}

fn run_scan(args: FleetScanArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";

    let config_path = args.config.unwrap_or_else(|| {
        FleetConfig::default_path().unwrap_or_else(|_| PathBuf::from("fleet.toml"))
    });

    if !config_path.exists() {
        anyhow::bail!(
            "Fleet config not found at {}. Run 'protectinator fleet init' to create one.",
            config_path.display()
        );
    }

    let config = FleetConfig::load(&config_path)
        .map_err(|e| anyhow::anyhow!(e))?;

    if !is_json {
        println!("Fleet Security Scan");
        println!("===================");
        println!("  Config:     {}", config_path.display());
        println!("  Hosts:      {}", config.hosts.len());
        if config.containers.scan_all {
            println!("  Containers: all");
        } else if !config.containers.names.is_empty() {
            println!("  Containers: {}", config.containers.names.len());
        }
        println!("  Repos:      {}", config.repos.len());
        println!("  Parallel:   {}", config.settings.parallel);
        println!();
    }

    let runner = FleetRunner::new(config);
    let opts = FleetScanOptions {
        hosts_only: args.hosts_only,
        containers_only: args.containers_only,
        repos_only: args.repos_only,
        offline: args.offline,
    };

    let results = runner.scan(&opts);

    if is_json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print_results(&results);
    }

    Ok(())
}

fn run_status(format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let db_path = protectinator_data::default_data_dir()
        .map_err(|e| anyhow::anyhow!(e))?
        .join("scan_history.db");

    let store = protectinator_data::ScanStore::open(&db_path)
        .map_err(|e| anyhow::anyhow!(e))?;

    let hosts = store.list_hosts().map_err(|e| anyhow::anyhow!(e))?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&hosts)?);
        return Ok(());
    }

    println!("Fleet Status");
    println!("============");
    println!();

    if hosts.is_empty() {
        println!("  No scan data found. Run 'protectinator fleet scan' first.");
        return Ok(());
    }

    // Header
    println!(
        "  {:<35} {:>5} {:>5} {:>5} {:>5} {:>5}  {:<20}",
        "HOST", "C", "H", "M", "L", "I", "LAST SCAN"
    );
    println!("  {}", "-".repeat(90));

    for host in &hosts {
        let freshness = scan_freshness(&host.last_scanned);
        println!(
            "  {:<35} {:>5} {:>5} {:>5} {:>5} {:>5}  {} ({})",
            host.name,
            colorize_count(host.latest_critical, "\x1b[91m"),
            colorize_count(host.latest_high, "\x1b[93m"),
            colorize_count(host.latest_medium, "\x1b[33m"),
            host.latest_low,
            host.latest_info,
            format_date(&host.last_scanned),
            freshness,
        );
    }

    println!();
    println!("  {} hosts tracked, {} total scans",
        hosts.len(),
        hosts.iter().map(|h| h.scan_count).sum::<usize>(),
    );

    Ok(())
}

fn run_init(args: FleetInitArgs) -> anyhow::Result<()> {
    let output = args.output.unwrap_or_else(|| {
        FleetConfig::default_path().unwrap_or_else(|_| PathBuf::from("fleet.toml"))
    });

    if output.exists() {
        anyhow::bail!(
            "Config already exists at {}. Remove it first or use --output to write elsewhere.",
            output.display()
        );
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output, FleetConfig::template())?;
    println!("Created fleet config at {}", output.display());
    println!("Edit it to add your hosts, containers, and repos.");

    Ok(())
}

fn print_results(results: &FleetScanResults) {
    // Host results
    if !results.host_results.is_empty() {
        println!("Remote Hosts:");
        for r in &results.host_results {
            if let Some(ref err) = r.error {
                println!("  \x1b[91m{}\x1b[0m — FAILED: {}", r.name, err);
            } else {
                println!(
                    "  {} — {} findings (C:{} H:{} M:{} L:{}) in {}ms",
                    r.name, r.total_findings, r.critical, r.high, r.medium, r.low, r.duration_ms
                );
            }
        }
        println!();
    }

    // Container results
    if !results.container_results.is_empty() {
        println!("Containers:");
        for r in &results.container_results {
            println!(
                "  {} — {} findings (C:{} H:{} M:{} L:{}) in {}ms",
                r.name, r.total_findings, r.critical, r.high, r.medium, r.low, r.duration_ms
            );
        }
        println!();
    }

    // Repo results
    if !results.repo_results.is_empty() {
        println!("Supply Chain Repos:");
        for r in &results.repo_results {
            if let Some(ref err) = r.error {
                println!("  \x1b[91m{}\x1b[0m — FAILED: {}", r.name, err);
            } else {
                println!(
                    "  {} — {} findings (C:{} H:{} M:{} L:{}) in {}ms",
                    r.name, r.total_findings, r.critical, r.high, r.medium, r.low, r.duration_ms
                );
            }
        }
        println!();
    }

    // Summary
    let s = &results.summary;
    println!("Fleet Summary");
    println!("=============");
    println!(
        "  Scanned: {} hosts, {} containers, {} repos",
        s.hosts_scanned, s.containers_scanned, s.repos_scanned
    );
    if s.hosts_failed > 0 {
        println!("  Failed:  {} hosts", s.hosts_failed);
    }
    println!(
        "  Findings: {} total (C:{} H:{} M:{} L:{} I:{})",
        s.total_findings, s.total_critical, s.total_high, s.total_medium, s.total_low, s.total_info
    );
    println!("  Duration: {}ms", s.duration_ms);
}

fn colorize_count(count: usize, color: &str) -> String {
    if count > 0 {
        format!("{}{}\x1b[0m", color, count)
    } else {
        "0".to_string()
    }
}

fn format_date(date_str: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(date_str)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| date_str.to_string())
}

fn scan_freshness(date_str: &str) -> &'static str {
    let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) else {
        return "unknown";
    };
    let age = chrono::Utc::now().signed_duration_since(dt);
    if age.num_hours() < 24 {
        "\x1b[32mfresh\x1b[0m"
    } else if age.num_days() < 7 {
        "\x1b[33mrecent\x1b[0m"
    } else {
        "\x1b[91mstale\x1b[0m"
    }
}
