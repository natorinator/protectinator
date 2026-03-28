//! Agent mode: run protectinator on the remote host and collect results

use crate::ssh;
use crate::types::{RemoteHost, RemoteScanResults, ScanMode};
use protectinator_core::{FindingSource, ScanResults};
use tracing::info;

/// Run protectinator on the remote host and collect JSON results
pub fn scan(host: &RemoteHost) -> Result<RemoteScanResults, String> {
    info!("Starting agent scan of {}", host.display_name());

    // Test connectivity
    ssh::test_connection(host)?;

    // Check if protectinator is available
    if !ssh::has_protectinator(host) {
        return Err(format!(
            "protectinator not found on {}. Install it or use --mode agentless.",
            host.display_name()
        ));
    }

    // Run protectinator scan with JSON output
    let json_output = ssh::ssh_exec(
        host,
        "protectinator scan --format json --quiet 2>/dev/null",
    )?;

    if json_output.trim().is_empty() {
        return Err(format!(
            "protectinator on {} returned empty output",
            host.display_name()
        ));
    }

    // Parse the JSON results
    let mut scan_results: ScanResults = serde_json::from_str(json_output.trim())
        .map_err(|e| format!("Failed to parse remote protectinator output: {}", e))?;

    // Re-wrap findings with Remote source
    for finding in &mut scan_results.findings {
        let inner = finding.source.clone();
        finding.source = FindingSource::Remote {
            host: host.hostname.clone(),
            scan_mode: "agent".to_string(),
            inner_source: Box::new(inner),
        };
    }

    info!(
        "Agent scan complete: {} findings for {}",
        scan_results.findings.len(),
        host.display_name()
    );

    Ok(RemoteScanResults {
        host: host.clone(),
        scan_mode: ScanMode::Agent,
        scan_results,
    })
}
