//! Package manager binary integrity monitoring commands

use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum PkgMonCommands {
    /// Scan package manager binaries for integrity issues
    ///
    /// Verifies binaries installed by apt and Homebrew against known-good
    /// hashes. Detects tampered system binaries, unauthorized package sources,
    /// and broken symlinks.
    Scan(PkgMonScanArgs),

    /// Create or update the binary baseline
    ///
    /// Hashes all binaries from detected package managers and stores the
    /// results. Subsequent scans compare against this baseline.
    Baseline(PkgMonBaselineArgs),

    /// List detected package managers and their binary counts
    Detect,

    /// Show baseline status and scan history
    Status,
}

#[derive(Args)]
pub struct PkgMonScanArgs {
    /// Filter to a specific package manager (apt, brew)
    #[arg(long)]
    manager: Option<String>,

    /// Root path for scanning (default: /)
    #[arg(long)]
    root: Option<PathBuf>,

    /// Auto-update baseline when package versions change
    #[arg(long)]
    update_baseline: bool,

    /// Save results to scan history database
    #[arg(long)]
    save: bool,

    /// Skip online checks (GitHub API tap reputation)
    #[arg(long)]
    offline: bool,
}

#[derive(Args)]
pub struct PkgMonBaselineArgs {
    /// Filter to a specific package manager (apt, brew)
    #[arg(long)]
    manager: Option<String>,

    /// Root path (default: /)
    #[arg(long)]
    root: Option<PathBuf>,
}

pub fn run(cmd: PkgMonCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        PkgMonCommands::Scan(args) => run_scan(args, format),
        PkgMonCommands::Baseline(args) => run_baseline(args, format),
        PkgMonCommands::Detect => run_detect(format),
        PkgMonCommands::Status => run_status(format),
    }
}

fn build_config(
    root: Option<PathBuf>,
    manager: Option<String>,
    update_baseline: bool,
    online: bool,
) -> protectinator_pkgmon::PkgMonConfig {
    let manager_filter = manager.and_then(|m| m.parse().ok());

    protectinator_pkgmon::PkgMonConfig {
        root: root.unwrap_or_else(|| PathBuf::from("/")),
        manager_filter,
        update_baseline,
        baseline_db_path: None,
        online,
    }
}

fn run_scan(args: PkgMonScanArgs, format: &str) -> anyhow::Result<()> {
    let start = Instant::now();
    let config = build_config(args.root, args.manager, args.update_baseline, !args.offline);

    let mut scanner = protectinator_pkgmon::PkgMonScanner::new(config);

    // Phase 1: Binary integrity
    scanner.add_check(Box::new(protectinator_pkgmon::apt::AptIntegrityCheck));
    scanner.add_check(Box::new(protectinator_pkgmon::apt::AptSourceAudit));
    scanner.add_check(Box::new(protectinator_pkgmon::homebrew::BrewIntegrityCheck));

    // Phase 2: Package manager audit
    scanner.add_check(Box::new(protectinator_pkgmon::homebrew_audit::BrewTapAudit));
    scanner.add_check(Box::new(protectinator_pkgmon::homebrew_audit::BrewTapReputationCheck));
    scanner.add_check(Box::new(protectinator_pkgmon::flatpak::FlatpakPermissionAudit));
    scanner.add_check(Box::new(protectinator_pkgmon::flatpak::FlatpakRemoteAudit));
    scanner.add_check(Box::new(protectinator_pkgmon::flatpak::FlatpakOverrideAudit));

    if format == "text" {
        eprintln!("Scanning package manager binaries...");
    }

    let mut findings = scanner
        .scan()
        .map_err(|e| anyhow::anyhow!("Scan failed: {}", e))?;

    // Apply suppressions
    let suppressions = protectinator_core::suppress::Suppressions::load_default();
    findings = suppressions.filter(findings, None);

    let duration = start.elapsed();

    // Save to DB if requested
    if args.save {
        if let Ok(store) = protectinator_data::DataStore::open_default() {
            let scan_key = "pkgmon:local".to_string();
            if let Err(e) = store.scans.store_scan(&scan_key, &findings, 0) {
                eprintln!("\x1b[93mWarning:\x1b[0m Failed to save scan: {}", e);
            }
        }
    }

    // Output
    if format == "json" {
        let output = serde_json::json!({
            "findings": findings,
            "summary": {
                "total": findings.len(),
                "critical": findings.iter().filter(|f| f.severity == protectinator_core::Severity::Critical).count(),
                "high": findings.iter().filter(|f| f.severity == protectinator_core::Severity::High).count(),
                "medium": findings.iter().filter(|f| f.severity == protectinator_core::Severity::Medium).count(),
                "low": findings.iter().filter(|f| f.severity == protectinator_core::Severity::Low).count(),
                "info": findings.iter().filter(|f| f.severity == protectinator_core::Severity::Info).count(),
            },
            "duration_ms": duration.as_millis(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if findings.is_empty() {
            println!(
                "\x1b[92m✓\x1b[0m No package integrity issues found ({:.1}s)",
                duration.as_secs_f64()
            );
        } else {
            println!(
                "\n\x1b[1mPackage Monitor Results\x1b[0m ({:.1}s)\n",
                duration.as_secs_f64()
            );

            for finding in &findings {
                let (color, _label) = severity_style(finding.severity);
                println!(
                    "  {} [{}] {}",
                    color,
                    finding.id,
                    finding.title,
                );
                if let Some(ref resource) = finding.resource {
                    println!("    Resource: {}", resource);
                }
                if let Some(ref remediation) = finding.remediation {
                    println!("    Fix: {}", remediation);
                }
                println!();
            }

            // Summary
            let critical = findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Critical)
                .count();
            let high = findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::High)
                .count();
            let medium = findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Medium)
                .count();
            let low = findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Low)
                .count();
            let info = findings
                .iter()
                .filter(|f| f.severity == protectinator_core::Severity::Info)
                .count();

            print!("  Summary: {} findings (", findings.len());
            let mut parts = Vec::new();
            if critical > 0 {
                parts.push(format!("\x1b[91m{} critical\x1b[0m", critical));
            }
            if high > 0 {
                parts.push(format!("\x1b[93m{} high\x1b[0m", high));
            }
            if medium > 0 {
                parts.push(format!("\x1b[33m{} medium\x1b[0m", medium));
            }
            if low > 0 {
                parts.push(format!("{} low", low));
            }
            if info > 0 {
                parts.push(format!("\x1b[36m{} info\x1b[0m", info));
            }
            println!("{})", parts.join(", "));
        }
    }

    Ok(())
}

fn run_baseline(args: PkgMonBaselineArgs, format: &str) -> anyhow::Result<()> {
    use protectinator_pkgmon::baseline::BaselineDb;
    use protectinator_pkgmon::types::PackageManager;

    let config = build_config(args.root, args.manager, false, true);
    let detected = protectinator_pkgmon::types::detect_package_managers(&config.root);

    if detected.is_empty() {
        if format == "json" {
            println!("{{\"status\": \"no_managers_detected\"}}");
        } else {
            println!("No supported package managers detected.");
        }
        return Ok(());
    }

    let db_path = config.baseline_path();
    let mut db = BaselineDb::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to open baseline database: {}", e))?;

    let mut total_binaries = 0;

    for manager in &detected {
        if !config.should_scan(*manager) {
            continue;
        }

        match manager {
            PackageManager::Homebrew => {
                if let Some(prefix) = protectinator_pkgmon::types::brew_prefix(&config.root) {
                    if format == "text" {
                        eprintln!("Creating Homebrew baseline...");
                    }
                    match protectinator_pkgmon::homebrew::create_baseline(&prefix, &mut db) {
                        Ok(count) => {
                            total_binaries += count;
                            if format == "text" {
                                println!("  Homebrew: {} binaries baselined", count);
                            }
                        }
                        Err(e) => {
                            eprintln!("\x1b[93mWarning:\x1b[0m Homebrew baseline failed: {}", e);
                        }
                    }
                }
            }
            PackageManager::Apt => {
                // apt uses dpkg md5sums as its baseline — no explicit baseline needed
                if format == "text" {
                    println!("  apt: uses dpkg md5sums (no explicit baseline needed)");
                }
            }
            PackageManager::Flatpak => {
                if format == "text" {
                    println!("  Flatpak: not yet supported for baseline");
                }
            }
        }
    }

    if format == "json" {
        let output = serde_json::json!({
            "status": "ok",
            "binaries_baselined": total_binaries,
            "database_path": db_path.to_string_lossy(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "\nBaseline stored at: {}\nTotal binaries baselined: {}",
            db_path.display(),
            total_binaries
        );
    }

    Ok(())
}

fn run_detect(format: &str) -> anyhow::Result<()> {
    let root = std::path::Path::new("/");
    let detected = protectinator_pkgmon::types::detect_package_managers(root);

    // Gather extra info for detected managers
    let brew_taps = protectinator_pkgmon::types::brew_prefix(root)
        .map(|p| protectinator_pkgmon::homebrew_audit::discover_taps(&p))
        .unwrap_or_default();
    let flatpak_apps = protectinator_pkgmon::flatpak::discover_apps(root);

    if format == "json" {
        let managers: Vec<serde_json::Value> = detected
            .iter()
            .map(|m| {
                let mut info = serde_json::json!({"name": m.to_string()});
                match m {
                    protectinator_pkgmon::PackageManager::Homebrew => {
                        info["taps"] = serde_json::json!(brew_taps.len());
                        info["third_party_taps"] = serde_json::json!(
                            brew_taps.iter().filter(|t| !t.is_official).count()
                        );
                    }
                    protectinator_pkgmon::PackageManager::Flatpak => {
                        info["apps"] = serde_json::json!(flatpak_apps.len());
                    }
                    _ => {}
                }
                info
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&managers)?);
    } else {
        if detected.is_empty() {
            println!("No supported package managers detected.");
        } else {
            println!("\x1b[1mDetected Package Managers\x1b[0m\n");
            for manager in &detected {
                match manager {
                    protectinator_pkgmon::PackageManager::Apt => {
                        println!("  apt (dpkg)");
                    }
                    protectinator_pkgmon::PackageManager::Homebrew => {
                        let third_party = brew_taps.iter().filter(|t| !t.is_official).count();
                        println!(
                            "  homebrew (brew) — {} taps ({} third-party)",
                            brew_taps.len(),
                            third_party
                        );
                    }
                    protectinator_pkgmon::PackageManager::Flatpak => {
                        println!(
                            "  flatpak — {} apps installed",
                            flatpak_apps.len()
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn run_status(format: &str) -> anyhow::Result<()> {
    use protectinator_pkgmon::baseline::BaselineDb;
    use protectinator_pkgmon::types::PackageManager;

    let config = protectinator_pkgmon::PkgMonConfig::default();
    let db_path = config.baseline_path();

    if !db_path.exists() {
        if format == "json" {
            println!("{{\"status\": \"no_baseline\"}}");
        } else {
            println!("No baseline database found. Run 'protectinator pkgmon baseline' to create one.");
        }
        return Ok(());
    }

    let db = BaselineDb::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to open baseline: {}", e))?;

    if format == "json" {
        let mut managers = serde_json::Map::new();
        for pm in [PackageManager::Apt, PackageManager::Homebrew, PackageManager::Flatpak] {
            let count = db.count_by_manager(pm).unwrap_or(0);
            let pkgs = db.count_packages_by_manager(pm).unwrap_or(0);
            if count > 0 {
                managers.insert(
                    pm.to_string(),
                    serde_json::json!({"binaries": count, "packages": pkgs}),
                );
            }
        }
        let output = serde_json::json!({
            "database_path": db_path.to_string_lossy(),
            "last_scan": db.get_metadata("brew_baseline_created").unwrap_or(None),
            "managers": managers,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\x1b[1mPackage Monitor Status\x1b[0m\n");
        println!("  Database: {}", db_path.display());
        if let Ok(Some(last_scan)) = db.get_metadata("brew_baseline_created") {
            println!("  Last baseline: {}", last_scan);
        }
        println!();

        for pm in [PackageManager::Apt, PackageManager::Homebrew, PackageManager::Flatpak] {
            let count = db.count_by_manager(pm).unwrap_or(0);
            let pkgs = db.count_packages_by_manager(pm).unwrap_or(0);
            if count > 0 {
                println!("  {}: {} binaries across {} packages", pm, count, pkgs);
            }
        }
    }

    Ok(())
}

fn severity_style(severity: protectinator_core::Severity) -> (&'static str, &'static str) {
    match severity {
        protectinator_core::Severity::Critical => ("\x1b[91m●\x1b[0m", "CRITICAL"),
        protectinator_core::Severity::High => ("\x1b[93m●\x1b[0m", "HIGH"),
        protectinator_core::Severity::Medium => ("\x1b[33m●\x1b[0m", "MEDIUM"),
        protectinator_core::Severity::Low => ("\x1b[37m●\x1b[0m", "LOW"),
        protectinator_core::Severity::Info => ("\x1b[36m●\x1b[0m", "INFO"),
    }
}
