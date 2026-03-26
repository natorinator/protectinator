//! Supply chain security scanning commands
//!
//! Scan developer workstations and CI/CD systems for software supply chain
//! compromises including known vulnerabilities, malicious packages, and
//! CI/CD misconfigurations.

use clap::{Args, Subcommand, ValueEnum};
use protectinator_core::Severity;
use protectinator_supply_chain::SupplyChainScanner;
use std::path::{Path, PathBuf};
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

    /// Evaluate a package in gaol's sandbox before installing
    ///
    /// Runs `gaol eval-dep` to install a package in an isolated sandbox,
    /// monitors for suspicious behavior (network connections, filesystem
    /// writes, process spawning), and reports findings.
    /// Requires gaol to be installed (PATH or ~/.local/bin/gaol).
    Eval(SupplyChainEvalArgs),

    /// Install project dependencies in gaol's sandbox
    ///
    /// Runs `gaol dev-install` to install dependencies with network
    /// restricted to package registries only. Reports any behavioral
    /// findings from the sandboxed installation.
    /// Requires gaol to be installed (PATH or ~/.local/bin/gaol).
    Install(SupplyChainInstallArgs),
}

#[derive(Args)]
pub struct SupplyChainScanArgs {
    /// Root filesystem path (default: current directory)
    #[arg(long, group = "target")]
    root: Option<PathBuf>,

    /// File containing repo paths to scan (one per line)
    #[arg(long, group = "target")]
    repos_file: Option<PathBuf>,

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

#[derive(Args)]
pub struct SupplyChainEvalArgs {
    /// Package name to evaluate
    package: String,

    /// Package ecosystem
    #[arg(long, value_enum, default_value_t = ScEcosystem::Python)]
    ecosystem: ScEcosystem,

    /// Package version (optional)
    #[arg(long = "pkg-version")]
    pkg_version: Option<String>,
}

#[derive(Args)]
pub struct SupplyChainInstallArgs {
    /// Project directory to install dependencies for (default: current directory)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Package ecosystem (auto-detected if not specified)
    #[arg(long, value_enum)]
    ecosystem: Option<ScEcosystem>,
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

    /// Ecosystem name as gaol expects it
    fn gaol_str(&self) -> &str {
        match self {
            ScEcosystem::Python => "python",
            ScEcosystem::Node => "node",
            ScEcosystem::Rust => "rust",
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
        SupplyChainCommands::Eval(args) => run_eval(args, format),
        SupplyChainCommands::Install(args) => run_install(args, format),
    }
}

fn run_scan(args: SupplyChainScanArgs, format: &str) -> anyhow::Result<()> {
    // Multi-repo mode
    if let Some(ref repos_file) = args.repos_file {
        return run_multi_scan(&args, repos_file, format);
    }

    let is_json = format == "json";
    let root = args
        .root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

    if !root.exists() {
        anyhow::bail!("Root path '{}' does not exist.", root.display());
    }

    let scanner = build_scanner(root.clone(), &args);

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

fn build_scanner(root: PathBuf, args: &SupplyChainScanArgs) -> SupplyChainScanner {
    SupplyChainScanner::new(root)
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
        .ecosystem(args.ecosystem.map(|e| e.as_str().to_string()))
}

fn run_multi_scan(
    args: &SupplyChainScanArgs,
    repos_file: &Path,
    format: &str,
) -> anyhow::Result<()> {
    let is_json = format == "json";
    let content = std::fs::read_to_string(repos_file)
        .map_err(|e| anyhow::anyhow!("Failed to read repos file: {}", e))?;

    let repos: Vec<PathBuf> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            // Expand ~ to home directory
            if l.starts_with("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    return PathBuf::from(format!("{}{}", home, &l[1..]));
                }
            }
            PathBuf::from(l)
        })
        .collect();

    if repos.is_empty() {
        anyhow::bail!("No repos found in {}", repos_file.display());
    }

    let min_severity: Severity = args.min_severity.into();
    let should_diff = args.diff;
    let should_save = args.save || args.diff;

    let db = if should_save || should_diff {
        Some(
            protectinator_supply_chain::history::ScanHistory::open_default()
                .map_err(|e| anyhow::anyhow!("Failed to open history database: {}", e))?,
        )
    } else {
        None
    };

    let start = Instant::now();

    if !is_json {
        println!("Multi-Repo Supply Chain Scan");
        println!("===========================");
        println!("  Repos file: {}", repos_file.display());
        println!("  Repos:      {}", repos.len());
        println!("  Online:     {}", !args.offline);
        if should_diff {
            println!("  Mode:       diff (only new findings)");
        }
        println!();
    }

    // Aggregate stats
    let mut total_repos_scanned = 0usize;
    let mut total_packages = 0usize;
    let mut total_findings = 0usize;
    let mut total_new = 0usize;
    let mut total_resolved = 0usize;
    let mut repos_with_new_findings = 0usize;
    let mut json_results: Vec<serde_json::Value> = Vec::new();

    for repo_path in &repos {
        if !repo_path.exists() {
            if !is_json {
                eprintln!(
                    "  \x1b[91mSkipping\x1b[0m {} (does not exist)",
                    repo_path.display()
                );
            }
            continue;
        }

        let repo_name = repo_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let scanner = build_scanner(repo_path.clone(), args);
        let results = scanner.scan();
        total_repos_scanned += 1;
        total_packages += results.packages_scanned;
        total_findings += results.scan_results.findings.len();

        let repo_key = repo_path
            .canonicalize()
            .unwrap_or(repo_path.clone())
            .display()
            .to_string();

        if should_diff {
            let db = db.as_ref().unwrap();
            let diff = db
                .diff(&repo_key, &results.scan_results.findings)
                .map_err(|e| anyhow::anyhow!("Diff failed for {}: {}", repo_name, e))?;

            db.store_scan(
                &repo_key,
                &results.scan_results.findings,
                results.packages_scanned,
            )
            .map_err(|e| anyhow::anyhow!("Save failed for {}: {}", repo_name, e))?;

            let new_filtered: Vec<_> = diff
                .new_findings
                .iter()
                .filter(|f| f.severity >= min_severity)
                .collect();

            total_new += diff.new_findings.len();
            total_resolved += diff.resolved_findings.len();

            if is_json {
                json_results.push(serde_json::json!({
                    "repo": repo_key,
                    "name": repo_name,
                    "packages": results.packages_scanned,
                    "total_findings": results.scan_results.findings.len(),
                    "new_findings": diff.new_findings.len(),
                    "resolved_findings": diff.resolved_findings.len(),
                    "new": diff.new_findings,
                    "resolved": diff.resolved_findings,
                }));
            } else if !new_filtered.is_empty() || !diff.resolved_findings.is_empty() {
                repos_with_new_findings += 1;
                println!(
                    "  \x1b[1m{}\x1b[0m ({} pkgs, {} total findings)",
                    repo_name, results.packages_scanned, results.scan_results.findings.len()
                );

                for f in &new_filtered {
                    println!(
                        "    {} \x1b[91mNEW\x1b[0m [{}] {}",
                        severity_bullet(f.severity),
                        f.severity,
                        f.title
                    );
                }
                for f in &diff.resolved_findings {
                    println!("    \x1b[32m✓ RESOLVED\x1b[0m [{}] {}", f.severity, f.title);
                }
                println!();
            } else if !is_json {
                println!(
                    "  \x1b[32m✓\x1b[0m {} — no changes ({} pkgs)",
                    repo_name, results.packages_scanned
                );
            }
        } else {
            // Non-diff mode
            let filtered: Vec<_> = results
                .scan_results
                .findings
                .iter()
                .filter(|f| f.severity >= min_severity)
                .collect();

            if should_save {
                if let Some(ref db) = db {
                    let _ = db.store_scan(
                        &repo_key,
                        &results.scan_results.findings,
                        results.packages_scanned,
                    );
                }
            }

            if is_json {
                json_results.push(serde_json::json!({
                    "repo": repo_key,
                    "name": repo_name,
                    "packages": results.packages_scanned,
                    "ecosystems": results.ecosystems,
                    "findings": results.scan_results.findings,
                }));
            } else {
                let c = filtered.iter().filter(|f| f.severity == Severity::Critical).count();
                let h = filtered.iter().filter(|f| f.severity == Severity::High).count();
                let m = filtered.iter().filter(|f| f.severity == Severity::Medium).count();
                let l = filtered.iter().filter(|f| f.severity == Severity::Low).count();

                let status = if c > 0 || h > 0 {
                    format!("\x1b[91mC:{} H:{}\x1b[0m M:{} L:{}", c, h, m, l)
                } else if m > 0 {
                    format!("C:0 H:0 \x1b[33mM:{}\x1b[0m L:{}", m, l)
                } else {
                    format!("\x1b[32m✓\x1b[0m C:0 H:0 M:{} L:{}", m, l)
                };

                println!(
                    "  {:<30} {:>5} pkgs  {}",
                    repo_name, results.packages_scanned, status
                );
            }
        }
    }

    let duration = start.elapsed();

    if is_json {
        let json = serde_json::json!({
            "repos_scanned": total_repos_scanned,
            "total_packages": total_packages,
            "total_findings": total_findings,
            "total_new": total_new,
            "total_resolved": total_resolved,
            "duration_ms": duration.as_millis(),
            "repos": json_results,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!();
        println!("  ─────────────────────────────────────────");
        if should_diff {
            println!(
                "  {} repos scanned, {} packages, {} total findings",
                total_repos_scanned, total_packages, total_findings
            );
            println!(
                "  {} new, {} resolved across {} repo(s) with changes",
                total_new, total_resolved, repos_with_new_findings
            );
        } else {
            println!(
                "  {} repos scanned, {} packages, {} findings in {:?}",
                total_repos_scanned, total_packages, total_findings, duration
            );
        }
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

fn run_eval(args: SupplyChainEvalArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let ecosystem = args.ecosystem.gaol_str();

    if !is_json {
        println!("Sandboxed Package Evaluation (via gaol)");
        println!("=======================================");
        println!("  Package:   {}", args.package);
        println!("  Ecosystem: {}", ecosystem);
        if let Some(ref v) = args.pkg_version {
            println!("  Version:   {}", v);
        }
        println!();
    }

    let findings = protectinator_supply_chain::gaol::eval_dep(
        &args.package,
        ecosystem,
        args.pkg_version.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        println!("  \x1b[32m✓\x1b[0m No suspicious behavior detected");
        println!();
        println!("  Package appears safe to install.");
    } else {
        for f in &findings {
            println!(
                "  {} [{}] {}",
                severity_bullet(f.severity),
                f.severity,
                f.title
            );
            // Truncate long descriptions
            let desc = if f.description.len() > 200 {
                format!("{}...", &f.description[..200])
            } else {
                f.description.clone()
            };
            println!("    {}", desc);
            if let Some(ref r) = f.resource {
                println!("    Resource: {}", r);
            }
        }

        println!();
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        if critical > 0 || high > 0 {
            println!(
                "  \x1b[91mWARNING: {} critical, {} high severity — do NOT install without investigation\x1b[0m",
                critical, high
            );
        } else {
            println!(
                "  {} finding(s) — review before installing",
                findings.len()
            );
        }
    }

    Ok(())
}

fn run_install(args: SupplyChainInstallArgs, format: &str) -> anyhow::Result<()> {
    let is_json = format == "json";
    let root = args
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if !root.exists() {
        anyhow::bail!(
            "Project directory '{}' does not exist.",
            root.display()
        );
    }

    let ecosystem_str = args.ecosystem.map(|e| e.gaol_str().to_string());

    if !is_json {
        println!("Sandboxed Dependency Installation (via gaol)");
        println!("=============================================");
        println!("  Project:   {}", root.display());
        if let Some(ref eco) = ecosystem_str {
            println!("  Ecosystem: {}", eco);
        } else {
            println!("  Ecosystem: auto-detect");
        }
        println!();
    }

    let findings = protectinator_supply_chain::gaol::dev_install(
        &root,
        ecosystem_str.as_deref(),
    )
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        println!("  \x1b[32m✓\x1b[0m Dependencies installed successfully with no findings");
    } else {
        for f in &findings {
            println!(
                "  {} [{}] {}",
                severity_bullet(f.severity),
                f.severity,
                f.title
            );
        }

        println!();
        println!(
            "  {} finding(s) (C:{} H:{} M:{} L:{})",
            findings.len(),
            findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            findings.iter().filter(|f| f.severity == Severity::High).count(),
            findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            findings.iter().filter(|f| f.severity == Severity::Low).count(),
        );
    }

    Ok(())
}
