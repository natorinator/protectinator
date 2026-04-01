//! Report generation commands

use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ReportArgs {
    /// Scan ID to generate report for
    #[arg(long)]
    scan_id: i64,

    /// Output file path (default: protectinator-scan-{id}.pdf)
    #[arg(long, short)]
    output: Option<PathBuf>,
}

pub fn run(args: ReportArgs) -> anyhow::Result<()> {
    let db_path = protectinator_data::default_data_dir()
        .map_err(|e| anyhow::anyhow!(e))?
        .join("scan_history.db");

    let store = protectinator_data::ScanStore::open(&db_path)
        .map_err(|e| anyhow::anyhow!(e))?;

    let scan = store
        .get_scan(args.scan_id)
        .map_err(|e| anyhow::anyhow!(e))?
        .ok_or_else(|| anyhow::anyhow!("Scan #{} not found", args.scan_id))?;

    let findings = store
        .scan_findings(args.scan_id)
        .map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "Generating PDF report for scan #{} ({}, {} findings)...",
        scan.id, scan.repo_path, scan.total_findings
    );

    let pdf_bytes = protectinator_report::generate_pdf_report(&scan, &findings)
        .map_err(|e| anyhow::anyhow!(e))?;

    let output_path = args.output.unwrap_or_else(|| {
        PathBuf::from(format!("protectinator-scan-{}.pdf", args.scan_id))
    });

    std::fs::write(&output_path, &pdf_bytes)?;
    println!("Report saved to {}", output_path.display());

    Ok(())
}
