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

    /// Pin GitHub Actions to commit SHAs
    ///
    /// Resolves mutable action references (tags/branches) to commit SHAs
    /// and rewrites workflow files in place. Prevents tag-rewriting attacks.
    Pin(SupplyChainPinArgs),

    /// Show scan history for a repo
    ///
    /// Lists previous scans with finding counts and timestamps.
    /// Use to track how findings change over time.
    History(SupplyChainHistoryArgs),
}

#[derive(Args)]
pub struct SupplyChainScanArgs {
    /// Root filesystem path (default: current directory)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Run in offline mode (skip OSV API queries)
    #[arg(long)]
    offline: bool,

    /// Show only new findings since the last scan (diff mode)
    #[arg(long)]
    diff: bool,

    /// Save scan results to history database (enabled automatically with --diff)
    #[arg(long)]
    save: bool,

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

#[derive(Args)]
pub struct SupplyChainPinArgs {
    /// Root filesystem path (default: current directory)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Dry run — show what would be pinned without modifying files
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
pub struct SupplyChainHistoryArgs {
    /// Root filesystem path (to identify the repo in history)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Number of scans to show
    #[arg(long, default_value_t = 20)]
    limit: usize,

    /// List all repos that have been scanned
    #[arg(long)]
    repos: bool,

    /// Prune old scans, keeping N most recent per repo
    #[arg(long)]
    prune: Option<usize>,
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
        SupplyChainCommands::Pin(args) => run_pin(args, format),
        SupplyChainCommands::History(args) => run_history(args, format),
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

    let repo_key = root.canonicalize().unwrap_or(root.clone())
        .display().to_string();
    let should_save = args.save || args.diff;
    let min_severity: Severity = args.min_severity.into();

    // Handle diff mode
    if args.diff {
        let db = protectinator_supply_chain::history::ScanHistory::open_default()
            .map_err(|e| anyhow::anyhow!("Failed to open history database: {}", e))?;

        let diff = db
            .diff(&repo_key, &results.scan_results.findings)
            .map_err(|e| anyhow::anyhow!("Failed to compute diff: {}", e))?;

        // Save current scan
        db.store_scan(
            &repo_key,
            &results.scan_results.findings,
            results.packages_scanned,
        )
        .map_err(|e| anyhow::anyhow!("Failed to save scan: {}", e))?;

        if is_json {
            let json = serde_json::json!({
                "has_baseline": diff.has_baseline,
                "baseline_timestamp": diff.baseline_timestamp,
                "new_findings": diff.new_findings.len(),
                "resolved_findings": diff.resolved_findings.len(),
                "total_findings": results.scan_results.findings.len(),
                "packages_scanned": results.packages_scanned,
                "new": diff.new_findings,
                "resolved": diff.resolved_findings,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        } else {
            if !results.ecosystems.is_empty() {
                println!("  Ecosystems: {}", results.ecosystems.join(", "));
            }
            println!(
                "  Lock files: {}, Packages: {}",
                results.lock_files_found, results.packages_scanned
            );

            if let Some(ref ts) = diff.baseline_timestamp {
                println!("  Baseline:   {}", ts);
            } else {
                println!("  Baseline:   none (first scan)");
            }
            println!();

            if diff.new_findings.is_empty() && diff.resolved_findings.is_empty() {
                println!("  No changes since last scan.");
            } else {
                if !diff.new_findings.is_empty() {
                    let new_filtered: Vec<_> = diff
                        .new_findings
                        .iter()
                        .filter(|f| f.severity >= min_severity)
                        .collect();

                    if !new_filtered.is_empty() {
                        println!(
                            "  \x1b[91mNEW FINDINGS\x1b[0m ({}):",
                            new_filtered.len()
                        );
                        for f in &new_filtered {
                            println!(
                                "    {} [{}] {}",
                                severity_bullet(f.severity),
                                f.severity,
                                f.title
                            );
                            if let Some(ref r) = f.resource {
                                println!("      Resource: {}", r);
                            }
                            if let Some(ref rem) = f.remediation {
                                println!("      Fix: {}", rem);
                            }
                        }
                        println!();
                    }
                }

                if !diff.resolved_findings.is_empty() {
                    println!(
                        "  \x1b[32mRESOLVED\x1b[0m ({}):",
                        diff.resolved_findings.len()
                    );
                    for f in &diff.resolved_findings {
                        println!("    \x1b[32m✓\x1b[0m [{}] {}", f.severity, f.title);
                    }
                    println!();
                }
            }

            println!(
                "  Total: {} findings ({} new, {} resolved) in {:?}",
                results.scan_results.findings.len(),
                diff.new_findings.len(),
                diff.resolved_findings.len(),
                duration
            );
            println!();
        }

        return Ok(());
    }

    // Save if requested (without diff)
    if should_save {
        match protectinator_supply_chain::history::ScanHistory::open_default() {
            Ok(db) => {
                if let Err(e) = db.store_scan(
                    &repo_key,
                    &results.scan_results.findings,
                    results.packages_scanned,
                ) {
                    eprintln!("Warning: failed to save scan history: {}", e);
                }
            }
            Err(e) => eprintln!("Warning: failed to open history database: {}", e),
        }
    }

    // Normal output (non-diff)
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
            results.scan_results.summary.findings_by_severity.get(&Severity::Critical).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::High).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::Medium).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::Low).unwrap_or(&0),
            results.scan_results.summary.findings_by_severity.get(&Severity::Info).unwrap_or(&0),
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

fn run_pin(args: SupplyChainPinArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let root = args
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if !root.exists() {
        anyhow::bail!("Root path '{}' does not exist.", root.display());
    }

    // Pick up GH_TOKEN or GITHUB_TOKEN from env for API auth
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .ok();

    if !is_json && !args.dry_run {
        println!("Pinning GitHub Actions to commit SHAs");
        println!("=====================================");
        println!("  Root: {}", root.display());
        if token.is_some() {
            println!("  Auth: using GH_TOKEN");
        } else {
            println!("  Auth: none (may hit rate limits — set GH_TOKEN for higher limits)");
        }
        println!();
    }

    if !is_json && args.dry_run {
        println!("Dry run — no files will be modified");
        println!("===================================");
        println!("  Root: {}", root.display());
        println!();
    }

    let summary = protectinator_supply_chain::pin::pin_workflow_actions(
        &root,
        args.dry_run,
        token.as_deref(),
    );

    if is_json {
        let json = serde_json::json!({
            "files_scanned": summary.files_scanned,
            "actions_found": summary.actions_found,
            "actions_pinned": summary.actions_pinned,
            "already_pinned": summary.already_pinned,
            "errors": summary.errors,
            "results": summary.results.iter().map(|r| {
                serde_json::json!({
                    "file": r.file.display().to_string(),
                    "action": r.action,
                    "old_ref": r.old_ref,
                    "new_sha": r.new_sha,
                    "was_already_pinned": r.was_already_pinned,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        for result in &summary.results {
            if result.was_already_pinned {
                println!(
                    "  \x1b[32m✓\x1b[0m {}@{} (already pinned)",
                    result.action, &result.new_sha[..12]
                );
            } else {
                let verb = if args.dry_run { "would pin" } else { "pinned" };
                println!(
                    "  \x1b[93m→\x1b[0m {} {}@{} -> {}",
                    verb, result.action, result.old_ref, &result.new_sha[..12]
                );
            }
        }

        for err in &summary.errors {
            println!("  \x1b[91m✗\x1b[0m {}", err);
        }

        println!();
        println!(
            "  {} files scanned, {} actions found, {} pinned, {} already pinned, {} errors",
            summary.files_scanned,
            summary.actions_found,
            summary.actions_pinned,
            summary.already_pinned,
            summary.errors.len()
        );

        if args.dry_run && summary.actions_pinned > 0 {
            println!();
            println!("  Run without --dry-run to apply changes.");
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

fn severity_bullet(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[91m●\x1b[0m",
        Severity::High => "\x1b[93m●\x1b[0m",
        Severity::Medium => "\x1b[33m●\x1b[0m",
        Severity::Low => "\x1b[36m●\x1b[0m",
        Severity::Info => "\x1b[90m●\x1b[0m",
    }
}

fn run_history(args: SupplyChainHistoryArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let db = protectinator_supply_chain::history::ScanHistory::open_default()
        .map_err(|e| anyhow::anyhow!("Failed to open history database: {}", e))?;

    // Handle prune
    if let Some(keep) = args.prune {
        let deleted = db
            .prune(keep)
            .map_err(|e| anyhow::anyhow!("Failed to prune: {}", e))?;
        if is_json {
            println!("{}", serde_json::json!({ "pruned": deleted }));
        } else {
            println!("Pruned {} old scan(s)", deleted);
        }
        return Ok(());
    }

    // List repos
    if args.repos {
        let repos = db
            .list_repos()
            .map_err(|e| anyhow::anyhow!("Failed to list repos: {}", e))?;

        if is_json {
            println!("{}", serde_json::to_string_pretty(&repos)?);
        } else {
            if repos.is_empty() {
                println!("No scan history found. Run a scan with --save or --diff first.");
            } else {
                println!("Scanned Repositories");
                println!("====================");
                for repo in &repos {
                    let latest = db.latest_scan(repo).ok().flatten();
                    if let Some(scan) = latest {
                        println!(
                            "  {} (last: {}, C:{} H:{} M:{} L:{})",
                            repo, scan.scanned_at, scan.critical, scan.high, scan.medium, scan.low
                        );
                    } else {
                        println!("  {}", repo);
                    }
                }
                println!();
                println!("  {} repo(s)", repos.len());
            }
        }
        return Ok(());
    }

    // List scans for a specific repo
    let root = args
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let repo_key = root
        .canonicalize()
        .unwrap_or(root.clone())
        .display()
        .to_string();

    let scans = db
        .list_scans(&repo_key, args.limit)
        .map_err(|e| anyhow::anyhow!("Failed to list scans: {}", e))?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&scans)?);
    } else {
        if scans.is_empty() {
            println!("No scan history for {}", repo_key);
            println!("Run a scan with --save or --diff to start tracking.");
        } else {
            println!("Scan History: {}", repo_key);
            println!("{}", "=".repeat(60));
            println!();
            println!(
                "  {:<24} {:<6} {:<4} {:<4} {:<4} {:<4} {:<6}",
                "TIMESTAMP", "PKGS", "C", "H", "M", "L", "TOTAL"
            );
            println!(
                "  {:<24} {:<6} {:<4} {:<4} {:<4} {:<4} {:<6}",
                "────────────────────────",
                "──────",
                "────",
                "────",
                "────",
                "────",
                "──────"
            );

            for scan in &scans {
                // Truncate timestamp for display
                let ts = if scan.scanned_at.len() > 19 {
                    &scan.scanned_at[..19]
                } else {
                    &scan.scanned_at
                };

                let c_str = if scan.critical > 0 {
                    format!("\x1b[91m{}\x1b[0m", scan.critical)
                } else {
                    "0".to_string()
                };
                let h_str = if scan.high > 0 {
                    format!("\x1b[93m{}\x1b[0m", scan.high)
                } else {
                    "0".to_string()
                };

                println!(
                    "  {:<24} {:<6} {:<14} {:<14} {:<4} {:<4} {:<6}",
                    ts,
                    scan.packages_scanned,
                    c_str,
                    h_str,
                    scan.medium,
                    scan.low,
                    scan.total_findings
                );
            }

            println!();
            println!("  {} scan(s) shown", scans.len());
        }
    }

    Ok(())
}
