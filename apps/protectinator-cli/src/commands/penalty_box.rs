//! Penalty Box -- auto-sandbox vulnerable packages using Gaol/Landlock
//!
//! Creates, manages, and lifts sandboxing restrictions on packages
//! that have unpatchable CVEs.

use clap::{Args, Subcommand, ValueEnum};
use protectinator_penaltybox::{EnforcementLevel, PackageDiscovery, PenaltyBoxManager, profile};

#[derive(Subcommand)]
pub enum PenaltyBoxCommands {
    /// Sandbox a package with known vulnerabilities
    ///
    /// Creates a Gaol sandbox profile restricting the package's binaries
    /// based on the CVE type (RCE -> block network, privesc -> restrict filesystem).
    Apply(PenaltyBoxApplyArgs),

    /// Auto-sandbox all high/critical unpatchable CVEs
    ///
    /// Scans recent findings for high/critical severity vulnerabilities
    /// that are waiting on upstream fixes, and creates sandbox profiles
    /// for each affected package.
    Auto(PenaltyBoxAutoArgs),

    /// List active penalty box restrictions
    ///
    /// Shows all packages currently under sandbox restrictions,
    /// including CVEs, enforcement level, and auto-lift versions.
    List(PenaltyBoxListArgs),

    /// Remove sandbox restrictions from a package
    ///
    /// Lifts the penalty box by deactivating or removing the profile.
    /// Use after the package has been patched.
    Lift(PenaltyBoxLiftArgs),

    /// Check if any sandboxed packages now have fixes available
    ///
    /// Cross-references active penalty box profiles against installed
    /// package versions to find packages that have been upgraded
    /// past their fix version.
    Status(PenaltyBoxStatusArgs),
}

#[derive(Clone, ValueEnum)]
pub enum CliEnforcementLevel {
    /// Log access but don't block (audit mode)
    Monitor,
    /// Apply Landlock restrictions, allow known-needed paths
    Restrict,
    /// Full isolation -- no network, minimal filesystem
    Quarantine,
}

impl From<CliEnforcementLevel> for EnforcementLevel {
    fn from(level: CliEnforcementLevel) -> Self {
        match level {
            CliEnforcementLevel::Monitor => EnforcementLevel::Monitor,
            CliEnforcementLevel::Restrict => EnforcementLevel::Restrict,
            CliEnforcementLevel::Quarantine => EnforcementLevel::Quarantine,
        }
    }
}

#[derive(Args)]
pub struct PenaltyBoxApplyArgs {
    /// Package name to sandbox
    package: String,

    /// CVE IDs that trigger this sandbox (comma-separated)
    #[arg(long, value_delimiter = ',')]
    cves: Vec<String>,

    /// CVSS v3 vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")
    #[arg(long)]
    cvss: Option<String>,

    /// Package version that will auto-lift this sandbox
    #[arg(long)]
    lift_version: Option<String>,

    /// Enforcement level
    #[arg(long, value_enum, default_value_t = CliEnforcementLevel::Restrict)]
    level: CliEnforcementLevel,
}

#[derive(Args)]
pub struct PenaltyBoxAutoArgs {
    /// Enforcement level for auto-generated profiles
    #[arg(long, value_enum, default_value_t = CliEnforcementLevel::Restrict)]
    level: CliEnforcementLevel,

    /// Actually apply the profiles (default is dry-run)
    #[arg(long)]
    apply: bool,
}

#[derive(Args)]
pub struct PenaltyBoxListArgs {
    /// Show only active profiles
    #[arg(long)]
    active_only: bool,
}

#[derive(Args)]
pub struct PenaltyBoxLiftArgs {
    /// Package name to lift restrictions from
    package: String,

    /// Permanently remove the profile (instead of just deactivating)
    #[arg(long)]
    remove: bool,
}

#[derive(Args)]
pub struct PenaltyBoxStatusArgs {}

pub fn run(cmd: PenaltyBoxCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        PenaltyBoxCommands::Apply(args) => run_apply(args, format),
        PenaltyBoxCommands::Auto(args) => run_auto(args, format),
        PenaltyBoxCommands::List(args) => run_list(args, format),
        PenaltyBoxCommands::Lift(args) => run_lift(args, format),
        PenaltyBoxCommands::Status(args) => run_status(args, format),
    }
}

fn run_apply(args: PenaltyBoxApplyArgs, format: &str) -> anyhow::Result<()> {
    // Check gaol availability
    if !PackageDiscovery::gaol_available() {
        eprintln!(
            "\x1b[93mWarning:\x1b[0m gaol not found. Profiles will be generated but cannot be enforced."
        );
        eprintln!("Install gaol for active sandboxing: https://github.com/erewhon/gaol-rs");
    }

    let enforcement: EnforcementLevel = args.level.into();

    // Create profile
    let profile = PenaltyBoxManager::create_profile(
        &args.package,
        args.cvss.as_deref(),
        None, // no description from CLI
        if args.cves.is_empty() {
            vec!["manual".to_string()]
        } else {
            args.cves
        },
        args.lift_version,
        enforcement,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&profile)?);
        return Ok(());
    }

    // Show what will be sandboxed
    println!("\x1b[1mPenalty Box: {}\x1b[0m", profile.package);
    println!();
    println!("  Binaries:");
    for binary in &profile.binaries {
        println!("    {}", binary.display());
    }
    println!();
    println!("  CVEs: {}", profile.cves.join(", "));
    println!("  Enforcement: {:?}", profile.restrictions.enforcement);
    println!("  Network: {:?}", profile.restrictions.network);
    println!(
        "  Read paths: {}",
        profile
            .restrictions
            .read_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  Write paths: {}",
        profile
            .restrictions
            .write_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !profile.restrictions.deny_paths.is_empty() {
        println!(
            "  Deny paths: {}",
            profile
                .restrictions
                .deny_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(ref ver) = profile.auto_lift_version {
        println!("  Auto-lift when: {} >= {}", profile.package, ver);
    }

    // Apply
    let path = PenaltyBoxManager::apply_profile(&profile).map_err(|e| anyhow::anyhow!(e))?;
    println!();
    println!("\x1b[92m✓\x1b[0m Profile saved to {}", path.display());

    // Show example gaol command
    if let Some(first_binary) = profile.binaries.first() {
        let cmd = profile.gaol_command(first_binary);
        println!();
        println!("  Example command:");
        println!("    {}", cmd.join(" "));
    }

    Ok(())
}

fn run_auto(args: PenaltyBoxAutoArgs, format: &str) -> anyhow::Result<()> {
    // Load recent findings from scan history
    let store =
        protectinator_data::DataStore::open_default().map_err(|e| anyhow::anyhow!(e))?;

    let recent_scans = store
        .scans
        .list_scans(&protectinator_data::ScanQuery {
            host: None,
            limit: Some(5),
            offset: None,
        })
        .map_err(|e| anyhow::anyhow!(e))?;

    if recent_scans.is_empty() {
        println!("No recent scans found. Run a scan first.");
        return Ok(());
    }

    // Collect findings from recent scans that have actionability metadata
    let mut all_findings = Vec::new();
    for scan in &recent_scans {
        let findings = store
            .scans
            .scan_findings(scan.id)
            .map_err(|e| anyhow::anyhow!(e))?;
        all_findings.extend(findings);
    }

    // Convert StoredFinding to Finding for the manager
    // StoredFinding doesn't have full metadata, so we create synthetic findings
    let findings: Vec<protectinator_core::Finding> = all_findings
        .iter()
        .filter(|f| f.severity == "critical" || f.severity == "high")
        .filter(|f| f.check_category.as_deref() == Some("vulnerability"))
        .map(|f| {
            let severity = match f.severity.as_str() {
                "critical" => protectinator_core::Severity::Critical,
                "high" => protectinator_core::Severity::High,
                _ => protectinator_core::Severity::Medium,
            };
            let mut finding = protectinator_core::Finding::new(
                &f.finding_id,
                &f.title,
                &f.title,
                severity,
                protectinator_core::FindingSource::SupplyChain {
                    check_category: "vulnerability".to_string(),
                    ecosystem: None,
                },
            );
            if let Some(ref resource) = f.resource {
                finding = finding.with_resource(resource.as_str());
            }
            // Mark as waiting on upstream for auto-profile generation
            finding = finding.with_metadata(
                "actionability",
                serde_json::json!({"class": "waiting_on_upstream"}),
            );
            finding
        })
        .collect();

    if findings.is_empty() {
        println!("No high/critical vulnerability findings found in recent scans.");
        return Ok(());
    }

    let enforcement: EnforcementLevel = args.level.into();
    let results = PenaltyBoxManager::auto_profiles_from_findings(&findings, enforcement);

    let mut profiles = Vec::new();
    let mut errors = Vec::new();
    for result in results {
        match result {
            Ok(p) => profiles.push(p),
            Err(e) => errors.push(e),
        }
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&profiles)?);
        return Ok(());
    }

    if profiles.is_empty() {
        println!("No packages eligible for auto-sandboxing.");
        if !errors.is_empty() {
            for err in &errors {
                eprintln!("  \x1b[93mSkipped:\x1b[0m {}", err);
            }
        }
        return Ok(());
    }

    println!(
        "\x1b[1mAuto Penalty Box -- {} packages\x1b[0m",
        profiles.len()
    );
    println!();

    for p in &profiles {
        println!("  \x1b[1m{}\x1b[0m", p.package);
        println!("    CVEs: {}", p.cves.join(", "));
        println!("    Binaries: {}", p.binaries.len());
        println!("    Enforcement: {:?}", p.restrictions.enforcement);
    }

    if !errors.is_empty() {
        println!();
        for err in &errors {
            eprintln!("  \x1b[93mSkipped:\x1b[0m {}", err);
        }
    }

    if args.apply {
        println!();
        for p in &profiles {
            match PenaltyBoxManager::apply_profile(p) {
                Ok(path) => {
                    println!(
                        "  \x1b[92m✓\x1b[0m {} -> {}",
                        p.package,
                        path.display()
                    )
                }
                Err(e) => eprintln!("  \x1b[91m✗\x1b[0m {} -- {}", p.package, e),
            }
        }
    } else {
        println!();
        println!("  \x1b[93mDry run\x1b[0m -- use --apply to activate penalty boxes");
    }

    Ok(())
}

fn run_list(args: PenaltyBoxListArgs, format: &str) -> anyhow::Result<()> {
    let profiles = profile::list_profiles().map_err(|e| anyhow::anyhow!(e))?;

    let profiles: Vec<_> = if args.active_only {
        profiles.into_iter().filter(|p| p.active).collect()
    } else {
        profiles
    };

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&profiles)?);
        return Ok(());
    }

    if profiles.is_empty() {
        println!("No penalty box profiles found.");
        return Ok(());
    }

    println!("\x1b[1mPenalty Box Profiles\x1b[0m");
    println!();

    for p in &profiles {
        let status = if p.active {
            "\x1b[91m●\x1b[0m active"
        } else {
            "\x1b[90m○\x1b[0m inactive"
        };
        println!("  \x1b[1m{}\x1b[0m  {}", p.package, status);
        println!("    CVEs: {}", p.cves.join(", "));
        println!("    Enforcement: {:?}", p.restrictions.enforcement);
        println!(
            "    Binaries: {}",
            p.binaries
                .iter()
                .map(|b| b.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "    Created: {}",
            p.created_at.format("%Y-%m-%d %H:%M UTC")
        );
        if let Some(ref ver) = p.auto_lift_version {
            println!("    Auto-lift at: {}", ver);
        }
        println!();
    }

    Ok(())
}

fn run_lift(args: PenaltyBoxLiftArgs, format: &str) -> anyhow::Result<()> {
    if args.remove {
        let removed =
            PenaltyBoxManager::remove(&args.package).map_err(|e| anyhow::anyhow!(e))?;
        if format == "json" {
            println!(
                "{}",
                serde_json::json!({"package": args.package, "action": "removed", "success": removed})
            );
        } else if removed {
            println!(
                "\x1b[92m✓\x1b[0m Removed penalty box for {}",
                args.package
            );
        } else {
            println!("No penalty box profile found for {}", args.package);
        }
    } else {
        let lifted =
            PenaltyBoxManager::lift(&args.package).map_err(|e| anyhow::anyhow!(e))?;
        if format == "json" {
            println!(
                "{}",
                serde_json::json!({"package": args.package, "action": "lifted", "success": lifted})
            );
        } else if lifted {
            println!(
                "\x1b[92m✓\x1b[0m Lifted penalty box for {} (profile retained, marked inactive)",
                args.package
            );
        } else {
            println!("No penalty box profile found for {}", args.package);
        }
    }

    Ok(())
}

fn run_status(_args: PenaltyBoxStatusArgs, format: &str) -> anyhow::Result<()> {
    let active = PenaltyBoxManager::list_active().map_err(|e| anyhow::anyhow!(e))?;

    if active.is_empty() {
        if format == "json" {
            println!(
                "{}",
                serde_json::json!({"active": 0, "liftable": []})
            );
        } else {
            println!("No active penalty box profiles.");
        }
        return Ok(());
    }

    let liftable = PenaltyBoxManager::check_liftable().map_err(|e| anyhow::anyhow!(e))?;

    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "active": active.len(),
                "liftable": liftable.iter().map(|(pkg, cur, fix)| {
                    serde_json::json!({"package": pkg, "current_version": cur, "fix_version": fix})
                }).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    println!("\x1b[1mPenalty Box Status\x1b[0m");
    println!();
    println!("  Active profiles: {}", active.len());
    println!();

    if liftable.is_empty() {
        println!("  No packages are ready to be unboxed.");
    } else {
        println!("  \x1b[92mReady to lift:\x1b[0m");
        for (pkg, current, fix) in &liftable {
            println!("    {} -- now at {} (fix version: {})", pkg, current, fix);
            println!("      Run: protectinator penalty-box lift {}", pkg);
        }
    }

    // Show packages still waiting
    let liftable_names: Vec<&str> = liftable.iter().map(|(p, _, _)| p.as_str()).collect();
    let still_waiting: Vec<_> = active
        .iter()
        .filter(|p| !liftable_names.contains(&p.package.as_str()))
        .collect();
    if !still_waiting.is_empty() {
        println!();
        println!("  Still sandboxed:");
        for p in still_waiting {
            println!(
                "    {} -- {} ({})",
                p.package,
                p.cves.join(", "),
                p.auto_lift_version.as_deref().unwrap_or("no auto-lift version")
            );
        }
    }

    Ok(())
}
