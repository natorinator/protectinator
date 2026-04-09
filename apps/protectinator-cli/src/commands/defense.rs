//! Defense audit commands

use clap::{Args, Subcommand};
use protectinator_data::DataStore;
use protectinator_defense::{execute_plan, generate_plan, DefenseAudit, HostContext, RemediationAction, RemediationPlan, PlanStatus};
use protectinator_fleet::config::HostEntry;
use protectinator_fleet::FleetConfig;
use protectinator_remote::types::RemoteHost;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum DefenseCommands {
    /// Audit defensive software on a host
    Audit(DefenseAuditArgs),

    /// Generate a remediation plan for a host
    Plan(DefensePlanArgs),

    /// Approve a pending remediation plan
    Approve(DefenseApproveArgs),

    /// Show remediation plan status
    Status(DefenseStatusArgs),

    /// Execute an approved remediation plan
    ///
    /// Runs the plan's actions via SSH on the target host.
    /// Dry-run by default — use --execute to actually apply changes.
    Remediate(DefenseRemediateArgs),
}

#[derive(Args)]
pub struct DefenseAuditArgs {
    /// Remote host to audit (omit for local audit)
    host: Option<String>,

    /// SSH user
    #[arg(long, default_value = "erewhon")]
    user: String,

    /// Use sudo for privileged commands
    #[arg(long)]
    sudo: bool,

    /// Host tags for severity (comma-separated, e.g. "external,production")
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,
}

#[derive(Args)]
pub struct DefensePlanArgs {
    /// Host to generate plan for (uses most recent scan findings)
    host: String,
}

#[derive(Args)]
pub struct DefenseApproveArgs {
    /// Plan ID to approve
    plan_id: i64,
}

#[derive(Args)]
pub struct DefenseStatusArgs {
    /// Filter by host
    #[arg(long)]
    host: Option<String>,
}

#[derive(Args)]
pub struct DefenseRemediateArgs {
    /// Plan ID to execute
    plan_id: i64,

    /// Actually execute the plan (default is dry-run)
    #[arg(long)]
    execute: bool,
}

pub fn run(cmd: DefenseCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        DefenseCommands::Audit(args) => run_audit(args, format),
        DefenseCommands::Plan(args) => run_plan(args, format),
        DefenseCommands::Approve(args) => run_approve(args, format),
        DefenseCommands::Status(args) => run_status(args, format),
        DefenseCommands::Remediate(args) => run_remediate(args, format),
    }
}

fn run_audit(args: DefenseAuditArgs, format: &str) -> anyhow::Result<()> {
    let ctx = HostContext {
        name: args.host.clone().unwrap_or_else(|| "localhost".to_string()),
        tags: args.tags,
        allowed_services: vec![], // No port comparison in standalone mode
    };

    let result = if let Some(ref hostname) = args.host {
        let host = RemoteHost::new(hostname)
            .with_user(&args.user)
            .with_sudo(args.sudo);
        DefenseAudit::audit_remote(&host, &ctx)
    } else {
        DefenseAudit::audit_local(&ctx)
    };

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result.findings)?);
        return Ok(());
    }

    if result.findings.is_empty() {
        println!("\x1b[92m✓\x1b[0m Defense audit passed for {}", result.host);
    } else {
        println!("\x1b[1mDefense Audit: {}\x1b[0m\n", result.host);
        for f in &result.findings {
            let color = match f.severity {
                protectinator_core::Severity::Critical => "\x1b[91m",
                protectinator_core::Severity::High => "\x1b[93m",
                protectinator_core::Severity::Medium => "\x1b[33m",
                _ => "\x1b[36m",
            };
            println!("  {}[{}]\x1b[0m {}", color, f.severity, f.title);
            if let Some(ref rem) = f.remediation {
                println!("         \x1b[90m→ {}\x1b[0m", rem);
            }
            println!();
        }
        println!("Found {} defense issues", result.findings.len());
    }

    Ok(())
}

fn run_plan(args: DefensePlanArgs, format: &str) -> anyhow::Result<()> {
    // Load scan store to get recent findings
    let store = DataStore::open_default().map_err(|e| anyhow::anyhow!(e))?;

    // Find the most recent scan for this host (try bare name, then remote: prefix)
    let host_key = {
        let bare = store.scans.list_scans(&protectinator_data::ScanQuery {
            host: Some(args.host.clone()), limit: Some(1), offset: None,
        }).map_err(|e| anyhow::anyhow!(e))?;
        if !bare.is_empty() {
            args.host.clone()
        } else {
            format!("remote:{}", args.host)
        }
    };
    let scans = store
        .scans
        .list_scans(&protectinator_data::ScanQuery {
            host: Some(host_key.clone()),
            limit: Some(1),
            offset: None,
        })
        .map_err(|e| anyhow::anyhow!(e))?;

    let scan = scans
        .first()
        .ok_or_else(|| anyhow::anyhow!("No scan history found for host '{}' (also tried 'remote:{}')", args.host, args.host))?;

    // Load stored findings and convert to Finding objects for the planner
    let stored_findings = store
        .scans
        .scan_findings(scan.id)
        .map_err(|e| anyhow::anyhow!(e))?;

    let findings: Vec<protectinator_core::Finding> = stored_findings
        .iter()
        .filter(|f| f.finding_id.starts_with("defense-"))
        .map(|sf| {
            let severity = match sf.severity.to_lowercase().as_str() {
                "critical" => protectinator_core::Severity::Critical,
                "high" => protectinator_core::Severity::High,
                "medium" => protectinator_core::Severity::Medium,
                "low" => protectinator_core::Severity::Low,
                _ => protectinator_core::Severity::Info,
            };
            protectinator_core::Finding::new(
                &sf.finding_id,
                &sf.title,
                "",
                severity,
                protectinator_core::FindingSource::Defense {
                    check_category: sf.check_category.clone().unwrap_or_default(),
                    host: Some(args.host.clone()),
                },
            )
        })
        .collect();

    if findings.is_empty() {
        println!("No defense findings for host '{}' -- nothing to remediate.", args.host);
        return Ok(());
    }

    // Load allowed_services from fleet.toml
    let allowed_services = load_allowed_services(&args.host);

    // Generate plan
    let plan = match generate_plan(&args.host, &findings, &allowed_services) {
        Some(p) => p,
        None => {
            println!("No remediable findings for host '{}'.", args.host);
            return Ok(());
        }
    };

    // Store the plan
    let actions_json = serde_json::to_string(&plan.actions)?;
    let source_findings = plan.source_findings.join(",");
    let plan_id = store
        .scans
        .store_plan(&plan.host, &plan.status.to_string(), &actions_json, &source_findings)
        .map_err(|e| anyhow::anyhow!(e))?;

    if format == "json" {
        let mut plan_out = plan.clone();
        plan_out.id = Some(plan_id);
        println!("{}", serde_json::to_string_pretty(&plan_out)?);
        return Ok(());
    }

    // Display plan
    println!("\x1b[1mRemediation Plan #{} for {}\x1b[0m", plan_id, plan.host);
    println!("Status: \x1b[93m{}\x1b[0m", plan.status);
    println!("Source findings: {}", plan.source_findings.join(", "));
    println!();

    for (i, action) in plan.actions.iter().enumerate() {
        println!("  {}. {}", i + 1, action.describe());
        println!("     \x1b[90m$ {}\x1b[0m", action.to_command());
        println!();
    }

    println!(
        "To approve: \x1b[1mprotectinator defense approve {}\x1b[0m",
        plan_id
    );

    Ok(())
}

fn run_approve(args: DefenseApproveArgs, format: &str) -> anyhow::Result<()> {
    let store = DataStore::open_default().map_err(|e| anyhow::anyhow!(e))?;

    let plan = store
        .scans
        .get_plan(args.plan_id)
        .map_err(|e| anyhow::anyhow!(e))?
        .ok_or_else(|| anyhow::anyhow!("Plan #{} not found", args.plan_id))?;

    if plan.status != "pending" {
        return Err(anyhow::anyhow!(
            "Plan #{} is in '{}' status, can only approve 'pending' plans",
            args.plan_id,
            plan.status
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    store
        .scans
        .update_plan_status(args.plan_id, "approved", Some(("approved_at", &now)))
        .map_err(|e| anyhow::anyhow!(e))?;

    if format == "json" {
        println!(
            "{}",
            serde_json::json!({
                "id": args.plan_id,
                "status": "approved",
                "approved_at": now,
            })
        );
    } else {
        println!(
            "\x1b[92m✓\x1b[0m Plan #{} approved for host '{}'",
            args.plan_id, plan.host
        );
    }

    Ok(())
}

fn run_status(args: DefenseStatusArgs, format: &str) -> anyhow::Result<()> {
    let store = DataStore::open_default().map_err(|e| anyhow::anyhow!(e))?;

    let plans = store
        .scans
        .list_plans(args.host.as_deref(), None)
        .map_err(|e| anyhow::anyhow!(e))?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&plans)?);
        return Ok(());
    }

    if plans.is_empty() {
        println!("No remediation plans found.");
        return Ok(());
    }

    println!(
        "\x1b[1m{:<6} {:<20} {:<12} {:<8} {}\x1b[0m",
        "ID", "Host", "Status", "Actions", "Created"
    );

    for plan in &plans {
        let action_count: usize = serde_json::from_str::<Vec<serde_json::Value>>(&plan.actions_json)
            .map(|v| v.len())
            .unwrap_or(0);

        let status_color = match plan.status.as_str() {
            "pending" => "\x1b[93m",
            "approved" => "\x1b[92m",
            "executing" => "\x1b[96m",
            "done" => "\x1b[32m",
            "failed" => "\x1b[91m",
            _ => "\x1b[0m",
        };

        // Trim the timestamp to just the date+time
        let created = if plan.created_at.len() > 19 {
            &plan.created_at[..19]
        } else {
            &plan.created_at
        };

        println!(
            "{:<6} {:<20} {}{:<12}\x1b[0m {:<8} {}",
            plan.id, plan.host, status_color, plan.status, action_count, created
        );
    }

    Ok(())
}

fn run_remediate(args: DefenseRemediateArgs, format: &str) -> anyhow::Result<()> {
    let store = DataStore::open_default().map_err(|e| anyhow::anyhow!(e))?;

    // Load plan from DB
    let stored = store
        .scans
        .get_plan(args.plan_id)
        .map_err(|e| anyhow::anyhow!(e))?
        .ok_or_else(|| anyhow::anyhow!("Plan #{} not found", args.plan_id))?;

    // Verify status is approved
    if stored.status != "approved" {
        return Err(anyhow::anyhow!(
            "Plan #{} is in '{}' status — only 'approved' plans can be executed.\n\
             Use 'protectinator defense approve {}' to approve a pending plan.",
            args.plan_id,
            stored.status,
            args.plan_id,
        ));
    }

    // Parse actions from stored JSON
    let actions: Vec<RemediationAction> = serde_json::from_str(&stored.actions_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse plan actions: {}", e))?;

    // Look up host in fleet.toml for SSH details
    let host_entry = find_host_entry(&stored.host);
    let remote_host = if let Some(entry) = &host_entry {
        FleetConfig::host_to_remote(entry)
    } else {
        // Fall back to basic host config
        RemoteHost::new(&stored.host)
            .with_user("erewhon")
            .with_sudo(true)
    };

    // Build RemediationPlan from stored data
    let plan = RemediationPlan {
        id: Some(args.plan_id),
        host: stored.host.clone(),
        created_at: stored.created_at.clone(),
        status: PlanStatus::Approved,
        actions,
        source_findings: stored
            .source_findings
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    };

    let dry_run = !args.execute;
    let mode_label = if dry_run { "dry-run" } else { "EXECUTING" };

    // If actually executing, mark plan as executing
    if !dry_run {
        store
            .scans
            .update_plan_status(args.plan_id, "executing", None)
            .map_err(|e| anyhow::anyhow!(e))?;
    }

    // Execute the plan
    let result = execute_plan(&plan, args.plan_id, &remote_host, dry_run);

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
        if !dry_run {
            let result_json = serde_json::to_string(&result)?;
            let status = if result.success { "done" } else { "failed" };
            store
                .scans
                .update_plan_status(args.plan_id, status, Some(("result_json", &result_json)))
                .map_err(|e| anyhow::anyhow!(e))?;
            if result.success {
                let now = chrono::Utc::now().to_rfc3339();
                store
                    .scans
                    .update_plan_status(args.plan_id, status, Some(("executed_at", &now)))
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
        }
        return Ok(());
    }

    // Display results with colored output
    println!(
        "\n\x1b[1mRemediation Plan #{} — {} ({})\x1b[0m\n",
        args.plan_id, stored.host, mode_label
    );

    for ar in &result.action_results {
        let step = ar.action_index + 1;
        let total = result.actions_total;
        println!("  [{}/{}] {}", step, total, ar.description);
        println!("        \x1b[90m$ {}\x1b[0m", ar.command);

        if ar.success {
            if dry_run {
                println!("        \x1b[92m✓\x1b[0m (dry-run)");
            } else {
                let secs = ar.duration_ms as f64 / 1000.0;
                println!("        \x1b[92m✓\x1b[0m ({:.1}s)", secs);
            }
        } else {
            let err_msg = ar.error.as_deref().unwrap_or("unknown error");
            println!("        \x1b[91m✗\x1b[0m {}", err_msg);
        }
        println!();
    }

    if result.success {
        if dry_run {
            println!(
                "All {} actions completed successfully (dry-run).",
                result.actions_total
            );
            println!(
                "To apply: \x1b[1mprotectinator defense remediate {} --execute\x1b[0m",
                args.plan_id
            );
        } else {
            let secs = result.duration_ms as f64 / 1000.0;
            println!(
                "\x1b[92m✓\x1b[0m All {} actions completed successfully ({:.1}s)",
                result.actions_total, secs
            );

            // Build audit suggestion with user/sudo from fleet config
            let mut audit_cmd = format!("protectinator defense audit {}", stored.host);
            if let Some(entry) = &host_entry {
                if entry.user != "root" {
                    audit_cmd.push_str(&format!(" --user {}", entry.user));
                }
                if entry.sudo {
                    audit_cmd.push_str(" --sudo");
                }
            }
            println!("Run '{}' to verify fixes.", audit_cmd);
        }
    } else {
        println!(
            "\x1b[91m✗\x1b[0m Execution failed after {}/{} actions.",
            result.actions_completed, result.actions_total
        );
    }

    // Persist results if not dry-run
    if !dry_run {
        let result_json = serde_json::to_string(&result)?;
        let status = if result.success { "done" } else { "failed" };
        store
            .scans
            .update_plan_status(args.plan_id, status, Some(("result_json", &result_json)))
            .map_err(|e| anyhow::anyhow!(e))?;
        if result.success {
            let now = chrono::Utc::now().to_rfc3339();
            store
                .scans
                .update_plan_status(args.plan_id, status, Some(("executed_at", &now)))
                .map_err(|e| anyhow::anyhow!(e))?;
        }
    }

    Ok(())
}

/// Find a host entry in fleet.toml by name or hostname
fn find_host_entry(host: &str) -> Option<HostEntry> {
    let config_path = FleetConfig::default_path().ok()?;
    let config = FleetConfig::load(&config_path).ok()?;
    config
        .hosts
        .into_iter()
        .find(|h| h.name == host || h.host == host)
}

/// Load allowed_services for a host from fleet.toml, if available
fn load_allowed_services(host: &str) -> Vec<String> {
    let config_path = FleetConfig::default_path().unwrap_or_else(|_| PathBuf::from("fleet.toml"));
    let config = match FleetConfig::load(&config_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    config
        .hosts
        .iter()
        .find(|h| h.name == host || h.host == host)
        .map(|h| h.allowed_services.clone())
        .unwrap_or_default()
}
