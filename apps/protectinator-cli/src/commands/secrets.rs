//! Secrets and credential scanning commands

use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum SecretsCommands {
    /// Scan for leaked secrets and credentials
    ///
    /// Scans configuration files, shell history, environment variables,
    /// and git history for API keys, tokens, passwords, and other credentials.
    Scan(SecretsScanArgs),

    /// List available detection patterns
    ///
    /// Shows all built-in secret patterns with their ID, name, severity,
    /// and confidence tier.
    Patterns(SecretsPatternsArgs),
}

#[derive(Args)]
pub struct SecretsScanArgs {
    /// Root directory to scan (default: current directory)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Scan git commit history for committed secrets
    #[arg(long)]
    git: bool,

    /// Scan environment variables and systemd service files
    #[arg(long)]
    env: bool,

    /// Scan shell history files (bash, zsh, fish)
    #[arg(long)]
    history: bool,

    /// Enable all scan types (filesystem + git + env + history)
    #[arg(long)]
    all: bool,

    /// Minimum entropy threshold for entropy-based detection (default: 4.5)
    #[arg(long)]
    min_entropy: Option<f64>,

    /// Skip pattern-based detection (only use entropy)
    #[arg(long)]
    skip_patterns: bool,

    /// Skip entropy-based detection (only use patterns)
    #[arg(long)]
    skip_entropy: bool,

    /// Path to custom patterns TOML file
    #[arg(long)]
    custom_patterns: Option<PathBuf>,

    /// Maximum git commits to scan (default: 1000)
    #[arg(long, default_value_t = 1000)]
    max_commits: usize,

    /// Save results to scan history database
    #[arg(long)]
    save: bool,
}

#[derive(Args)]
pub struct SecretsPatternsArgs {
    /// Filter patterns by secret type
    #[arg(long)]
    filter: Option<String>,
}

pub fn run(cmd: SecretsCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        SecretsCommands::Scan(args) => run_scan(args, format),
        SecretsCommands::Patterns(args) => run_patterns(args, format),
    }
}

fn run_scan(args: SecretsScanArgs, format: &str) -> anyhow::Result<()> {
    let start = Instant::now();
    let root = args
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let mut all_findings = Vec::new();

    let scan_git = args.git || args.all;
    let scan_env = args.env || args.all;
    let scan_history = args.history || args.all;
    // Filesystem scan always runs unless ONLY git/env/history is specified
    let scan_fs = !args.git && !args.env && !args.history || args.all;

    // Build pattern set
    let mut patterns = protectinator_secrets::PatternSet::builtin();
    if let Some(ref custom_path) = args.custom_patterns {
        match patterns.load_custom(custom_path) {
            Ok(n) => {
                if format == "text" {
                    eprintln!("Loaded {} custom patterns from {}", n, custom_path.display());
                }
            }
            Err(e) => eprintln!("\x1b[93mWarning:\x1b[0m Failed to load custom patterns: {}", e),
        }
    }

    // Filesystem scan
    if scan_fs {
        if format == "text" {
            eprintln!("Scanning {} for secrets...", root.display());
        }
        let mut scanner = protectinator_secrets::SecretsScanner::new(&root)
            .skip_patterns(args.skip_patterns)
            .skip_entropy(args.skip_entropy);
        if let Some(entropy) = args.min_entropy {
            scanner = scanner.min_entropy(entropy);
        }
        if let Some(ref path) = args.custom_patterns {
            scanner = scanner.custom_patterns(path);
        }
        let findings = scanner.scan();
        all_findings.extend(findings);
    }

    // Git history scan
    if scan_git {
        if format == "text" {
            eprintln!(
                "Scanning git history (last {} commits)...",
                args.max_commits
            );
        }
        let findings = protectinator_secrets::checks::git_history::scan_git_history(
            &root,
            &patterns,
            Some(args.max_commits),
        );
        all_findings.extend(findings);
    }

    // Environment scan
    if scan_env {
        if format == "text" {
            eprintln!("Scanning environment variables and service files...");
        }
        let findings = protectinator_secrets::checks::env_vars::scan_environment(&patterns);
        all_findings.extend(findings);
    }

    // Shell history scan
    if scan_history {
        if format == "text" {
            eprintln!("Scanning shell history...");
        }
        let user_homes = get_user_homes();
        let findings =
            protectinator_secrets::checks::shell_history::scan_shell_history(&user_homes, &patterns);
        all_findings.extend(findings);
    }

    // Apply suppressions
    let suppressions = protectinator_core::suppress::Suppressions::load_default();
    all_findings = suppressions.filter(all_findings, None);

    let duration = start.elapsed();

    // Save to DB if requested
    if args.save {
        if let Ok(store) = protectinator_data::DataStore::open_default() {
            let scan_key = format!("secrets:{}", root.display());
            if let Err(e) = store.scans.store_scan(&scan_key, &all_findings, 0) {
                eprintln!("\x1b[93mWarning:\x1b[0m Failed to save scan: {}", e);
            }
        }
    }

    // Output
    if format == "json" {
        let output = serde_json::json!({
            "findings": all_findings,
            "summary": {
                "total": all_findings.len(),
                "critical": all_findings.iter().filter(|f| f.severity == protectinator_core::Severity::Critical).count(),
                "high": all_findings.iter().filter(|f| f.severity == protectinator_core::Severity::High).count(),
                "medium": all_findings.iter().filter(|f| f.severity == protectinator_core::Severity::Medium).count(),
                "low": all_findings.iter().filter(|f| f.severity == protectinator_core::Severity::Low).count(),
            },
            "duration_ms": duration.as_millis(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if all_findings.is_empty() {
            println!(
                "\x1b[92m✓\x1b[0m No secrets found ({:.1}s)",
                duration.as_secs_f64()
            );
        } else {
            // Group by severity
            let critical: Vec<_> = all_findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Critical)
                .collect();
            let high: Vec<_> = all_findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::High)
                .collect();
            let medium: Vec<_> = all_findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Medium)
                .collect();
            let low: Vec<_> = all_findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Low)
                .collect();

            println!();
            for finding in &all_findings {
                let color = match finding.severity {
                    protectinator_core::Severity::Critical => "\x1b[91m",
                    protectinator_core::Severity::High => "\x1b[93m",
                    protectinator_core::Severity::Medium => "\x1b[33m",
                    protectinator_core::Severity::Low => "\x1b[36m",
                    _ => "\x1b[0m",
                };
                println!(
                    "  {}[{}]\x1b[0m {}",
                    color, finding.severity, finding.title
                );
                if let Some(ref resource) = finding.resource {
                    println!("         {}", resource);
                }
                if let Some(ref remediation) = finding.remediation {
                    println!("         \x1b[90m→ {}\x1b[0m", truncate(remediation, 100));
                }
                println!();
            }

            println!(
                "Found \x1b[1m{}\x1b[0m secrets: {} critical, {} high, {} medium, {} low ({:.1}s)",
                all_findings.len(),
                critical.len(),
                high.len(),
                medium.len(),
                low.len(),
                duration.as_secs_f64(),
            );
        }
    }

    // Exit code 1 if critical findings
    if all_findings
        .iter()
        .any(|f| f.severity == protectinator_core::Severity::Critical)
    {
        std::process::exit(1);
    }

    Ok(())
}

fn run_patterns(args: SecretsPatternsArgs, format: &str) -> anyhow::Result<()> {
    let patterns = protectinator_secrets::PatternSet::builtin();
    let mut infos = patterns.list_patterns();

    if let Some(ref filter) = args.filter {
        let filter_lower = filter.to_lowercase();
        infos.retain(|p| {
            p.name.to_lowercase().contains(&filter_lower)
                || p.secret_type.to_lowercase().contains(&filter_lower)
                || p.id.to_lowercase().contains(&filter_lower)
        });
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&infos)?);
    } else {
        println!(
            "\x1b[1mSecret Detection Patterns\x1b[0m ({} total)",
            infos.len()
        );
        println!();
        for info in &infos {
            let sev_color = match info.severity {
                protectinator_core::Severity::Critical => "\x1b[91m",
                protectinator_core::Severity::High => "\x1b[93m",
                protectinator_core::Severity::Medium => "\x1b[33m",
                _ => "\x1b[36m",
            };
            let tier_label = match info.tier {
                protectinator_secrets::PatternTier::Structural => "structural",
                protectinator_secrets::PatternTier::KeywordAnchored => "keyword",
                protectinator_secrets::PatternTier::EntropyOnly => "entropy",
            };
            println!(
                "  {}[{}]\x1b[0m \x1b[1m{}\x1b[0m \x1b[90m({})\x1b[0m",
                sev_color, info.severity, info.name, tier_label,
            );
            println!(
                "         ID: {} | Type: {}",
                info.id, info.secret_type
            );
            if !info.description.is_empty() {
                println!("         {}", info.description);
            }
            println!();
        }
    }

    Ok(())
}

/// Get user home directories for history scanning
fn get_user_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        homes.push(PathBuf::from(home));
    }
    homes
}

/// Truncate a string for display
fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
