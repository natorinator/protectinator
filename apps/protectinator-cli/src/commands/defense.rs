//! Defense audit commands

use clap::{Args, Subcommand};
use protectinator_defense::{DefenseAudit, HostContext};
use protectinator_remote::types::RemoteHost;

#[derive(Subcommand)]
pub enum DefenseCommands {
    /// Audit defensive software on a host
    Audit(DefenseAuditArgs),
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

pub fn run(cmd: DefenseCommands, format: &str) -> anyhow::Result<()> {
    match cmd {
        DefenseCommands::Audit(args) => run_audit(args, format),
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
