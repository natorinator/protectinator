//! Agent and rootkit detection commands

use clap::{Args, Subcommand, ValueEnum};
use protectinator_agents::{
    scan_agents, scan_rootkits, AgentCategory, AgentEntry, AgentSummary, RiskLevel, ScanFilter,
};
use serde::Serialize;
use std::time::Instant;

#[derive(Subcommand)]
pub enum AgentsCommands {
    /// Scan for agents, rootkits, and management software
    Scan(ScanArgs),

    /// Scan specifically for rootkit indicators
    Rootkit(RootkitArgs),

    /// List detection capabilities
    List(ListArgs),
}

/// Output format for agents results
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output
    Json,
}

/// Agent category filter
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CategoryFilter {
    /// Rootkit indicators
    Rootkit,
    /// MDM agents
    Mdm,
    /// Endpoint security / EDR
    Endpoint,
    /// Remote access tools
    Remote,
    /// Configuration management
    Config,
    /// RMM tools
    Rmm,
}

impl From<CategoryFilter> for AgentCategory {
    fn from(f: CategoryFilter) -> Self {
        match f {
            CategoryFilter::Rootkit => AgentCategory::Rootkit,
            CategoryFilter::Mdm => AgentCategory::Mdm,
            CategoryFilter::Endpoint => AgentCategory::EndpointSecurity,
            CategoryFilter::Remote => AgentCategory::RemoteAccess,
            CategoryFilter::Config => AgentCategory::ConfigManagement,
            CategoryFilter::Rmm => AgentCategory::Rmm,
        }
    }
}

#[derive(Args)]
pub struct ScanArgs {
    /// Only scan for rootkits
    #[arg(long)]
    rootkits_only: bool,

    /// Filter by category
    #[arg(long, value_enum)]
    category: Option<CategoryFilter>,

    /// Minimum risk level to report
    #[arg(long, default_value = "info")]
    min_risk: String,

    /// Quiet mode - only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Output format (text or json)
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Exit with non-zero code if rootkit indicators are found
    #[arg(long)]
    fail_on_rootkit: bool,
}

#[derive(Args)]
pub struct RootkitArgs {
    /// Quiet mode - only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Output format (text or json)
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Exit with non-zero code if rootkit indicators are found
    #[arg(long)]
    fail_on_rootkit: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Output format (text or json)
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

/// JSON output structure for scan results
#[derive(Serialize)]
struct ScanOutput {
    entries: Vec<AgentEntry>,
    summary: AgentSummary,
    duration_ms: u64,
}

pub fn run(cmd: AgentsCommands) -> anyhow::Result<()> {
    match cmd {
        AgentsCommands::Scan(args) => run_scan(args),
        AgentsCommands::Rootkit(args) => run_rootkit(args),
        AgentsCommands::List(args) => list_capabilities(args),
    }
}

fn parse_risk(s: &str) -> RiskLevel {
    match s.to_lowercase().as_str() {
        "critical" => RiskLevel::Critical,
        "high" => RiskLevel::High,
        "medium" => RiskLevel::Medium,
        "low" => RiskLevel::Low,
        _ => RiskLevel::Info,
    }
}

fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    let start = Instant::now();
    let is_json = matches!(args.output, OutputFormat::Json);

    if !is_json && !args.quiet {
        println!("Agent and Rootkit Detection Scanner");
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    // Build filter
    let mut filter = ScanFilter::new();

    if args.rootkits_only {
        filter = ScanFilter::rootkits_only();
    } else if let Some(cat) = args.category {
        filter = filter.with_category(cat.into());
    }

    let min_risk = parse_risk(&args.min_risk);
    filter = filter.with_min_risk(min_risk);

    // Run scan
    let entries = scan_agents(Some(&filter));
    let summary = AgentSummary::from_entries(&entries);
    let duration = start.elapsed();

    // JSON output
    if is_json {
        let output = ScanOutput {
            entries,
            summary: summary.clone(),
            duration_ms: duration.as_millis() as u64,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);

        if args.fail_on_rootkit && summary.has_rootkit_indicators() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Text output
    if !args.quiet {
        print_entries(&entries);
    }

    // Summary
    print_summary(&summary, duration);

    if summary.has_rootkit_indicators() {
        println!(
            "\n\x1b[91mWarning:\x1b[0m Rootkit indicators detected! Review findings above.",
        );
        if args.fail_on_rootkit {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn run_rootkit(args: RootkitArgs) -> anyhow::Result<()> {
    let start = Instant::now();
    let is_json = matches!(args.output, OutputFormat::Json);

    if !is_json && !args.quiet {
        println!("Rootkit Detection Scanner");
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    let entries = scan_rootkits();
    let summary = AgentSummary::from_entries(&entries);
    let duration = start.elapsed();

    // JSON output
    if is_json {
        let output = ScanOutput {
            entries,
            summary: summary.clone(),
            duration_ms: duration.as_millis() as u64,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);

        if args.fail_on_rootkit && summary.has_rootkit_indicators() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Text output
    if !args.quiet {
        if entries.is_empty() {
            println!("No rootkit indicators detected.\n");
        } else {
            print_entries(&entries);
        }
    }

    // Summary
    println!("═══════════════════════════════════════════════════════════════");
    println!("Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Rootkit indicators: {}", entries.len());
    println!("  Completed in {:?}", duration);

    if summary.has_rootkit_indicators() {
        println!(
            "\n\x1b[91mWarning:\x1b[0m {} rootkit indicator(s) detected!",
            entries.len()
        );
        if args.fail_on_rootkit {
            std::process::exit(1);
        }
    } else {
        println!("\n\x1b[92mNo rootkit indicators found.\x1b[0m");
    }

    Ok(())
}

fn print_entries(entries: &[AgentEntry]) {
    let mut current_category = None;

    for entry in entries {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                println!("└───────────────────────────────────────────────────────────────\n");
            }
            current_category = Some(entry.category);
            println!(
                "┌─ {} ─────────────────────────────────────────",
                entry.category.as_str().to_uppercase()
            );
        }

        let (color, symbol) = match entry.risk {
            RiskLevel::Critical => ("\x1b[91m", "!"),
            RiskLevel::High => ("\x1b[93m", "!"),
            RiskLevel::Medium => ("\x1b[33m", "?"),
            RiskLevel::Low => ("\x1b[37m", "-"),
            RiskLevel::Info => ("\x1b[36m", "i"),
        };
        let reset = "\x1b[0m";

        println!(
            "│ {}{}{}  {} \x1b[90m({})\x1b[0m",
            color,
            symbol,
            reset,
            entry.name,
            entry.agent_type.as_str()
        );

        println!("│     {}", entry.description);

        if !entry.paths.is_empty() {
            println!("│     \x1b[90mPaths: {}\x1b[0m",
                entry.paths.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    if current_category.is_some() {
        println!("└───────────────────────────────────────────────────────────────\n");
    }
}

fn print_summary(summary: &AgentSummary, duration: std::time::Duration) {
    println!("═══════════════════════════════════════════════════════════════");
    println!("Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Total findings: {}", summary.total_findings);
    println!("  \x1b[91mCritical:\x1b[0m  {}", summary.critical_count);
    println!("  \x1b[93mHigh:\x1b[0m      {}", summary.high_count);
    println!("  \x1b[33mMedium:\x1b[0m    {}", summary.medium_count);
    println!("  \x1b[37mLow:\x1b[0m       {}", summary.low_count);
    println!("  \x1b[36mInfo:\x1b[0m      {}", summary.info_count);
    println!();

    if !summary.by_category.is_empty() {
        println!("  By category:");
        for (cat, count) in &summary.by_category {
            println!("    {}: {}", cat, count);
        }
        println!();
    }

    println!("  Completed in {:?}", duration);
}

fn list_capabilities(args: ListArgs) -> anyhow::Result<()> {
    let capabilities = vec![
        serde_json::json!({
            "category": "Rootkit Detection",
            "checks": [
                {
                    "name": "Kernel Modules (Linux)",
                    "description": "Scans /proc/modules for known rootkit modules and suspicious names"
                },
                {
                    "name": "Hidden Modules (Linux)",
                    "description": "Compares /proc/modules with /sys/module to find hidden modules"
                },
                {
                    "name": "Deleted Binary Processes",
                    "description": "Finds processes whose executable has been deleted"
                },
                {
                    "name": "Hidden Processes",
                    "description": "Detects processes hidden from /proc listing"
                },
                {
                    "name": "LD_PRELOAD Hijacking",
                    "description": "Checks /etc/ld.so.preload for library preloading attacks"
                },
                {
                    "name": "Kernel Extensions (macOS)",
                    "description": "Scans kextstat for suspicious kernel extensions"
                }
            ]
        }),
        serde_json::json!({
            "category": "MDM Detection",
            "agents": ["Jamf Pro", "Kandji", "Mosyle", "Microsoft Intune", "SCCM", "Workspace ONE", "Apple MDM Profiles"]
        }),
        serde_json::json!({
            "category": "Endpoint Security",
            "agents": ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender", "Carbon Black", "Sophos", "McAfee", "Symantec", "Trend Micro", "Cylance", "Tanium", "osquery"]
        }),
        serde_json::json!({
            "category": "Remote Access",
            "agents": ["TeamViewer", "AnyDesk", "ScreenConnect", "LogMeIn", "Splashtop", "RustDesk", "VNC", "SSH"]
        }),
        serde_json::json!({
            "category": "Configuration Management",
            "agents": ["Puppet", "Chef", "Ansible", "Salt", "CFEngine"]
        }),
        serde_json::json!({
            "category": "RMM Tools",
            "agents": ["Datto RMM", "NinjaRMM", "ConnectWise Automate", "Atera", "Kaseya VSA"]
        }),
    ];

    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&capabilities)?);
        return Ok(());
    }

    println!("Agent Detection Capabilities");
    println!("═══════════════════════════════════════════════════════════════\n");

    println!("ROOTKIT DETECTION:");
    println!("  - Kernel Modules (Linux): Scans for known rootkit modules");
    println!("  - Hidden Modules (Linux): Detects modules hidden from /proc/modules");
    println!("  - Deleted Binary Processes: Finds processes with deleted executables");
    println!("  - Hidden Processes: Detects processes hidden from /proc");
    println!("  - LD_PRELOAD Hijacking: Checks for library preloading attacks");
    println!("  - Kernel Extensions (macOS): Scans for suspicious kexts");
    println!();

    println!("MDM AGENTS:");
    println!("  Jamf Pro, Kandji, Mosyle, Microsoft Intune, SCCM,");
    println!("  VMware Workspace ONE, Apple MDM Profiles");
    println!();

    println!("ENDPOINT SECURITY:");
    println!("  CrowdStrike, SentinelOne, Microsoft Defender, Carbon Black,");
    println!("  Sophos, McAfee, Symantec, Trend Micro, Cylance, Tanium, osquery");
    println!();

    println!("REMOTE ACCESS:");
    println!("  TeamViewer, AnyDesk, ScreenConnect, LogMeIn, Splashtop,");
    println!("  RustDesk, VNC Server, SSH Server");
    println!();

    println!("CONFIGURATION MANAGEMENT:");
    println!("  Puppet, Chef, Ansible, Salt, CFEngine");
    println!();

    println!("RMM TOOLS:");
    println!("  Datto RMM, NinjaRMM, ConnectWise Automate, Atera, Kaseya VSA");
    println!();

    Ok(())
}
