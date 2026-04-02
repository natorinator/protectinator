//! Webhook notification delivery

use crate::config::WebhookConfig;
use crate::types::{FleetScanResults, NotifiableFindings};
use tracing::info;

/// Send a webhook notification about fleet scan results
pub fn send_webhook(
    config: &WebhookConfig,
    results: &FleetScanResults,
    notifiable: &NotifiableFindings,
) -> Result<(), String> {
    let should_notify_critical =
        config.on.iter().any(|e| e == "new_critical") && !notifiable.new_critical.is_empty();
    let should_notify_high =
        config.on.iter().any(|e| e == "new_high") && !notifiable.new_high.is_empty();

    if !should_notify_critical && !should_notify_high {
        return Ok(());
    }

    let payload = serde_json::json!({
        "event": "fleet_scan_complete",
        "timestamp": results.timestamp,
        "summary": {
            "hosts_scanned": results.summary.hosts_scanned,
            "containers_scanned": results.summary.containers_scanned,
            "repos_scanned": results.summary.repos_scanned,
            "total_findings": results.summary.total_findings,
            "total_new_findings": results.summary.total_new_findings,
            "total_resolved_findings": results.summary.total_resolved_findings,
            "duration_ms": results.summary.duration_ms,
        },
        "new_critical": notifiable.new_critical,
        "new_high": notifiable.new_high,
    });

    info!("Sending webhook notification to {}", config.url);

    ureq::post(&config.url)
        .set("Content-Type", "application/json")
        .send_json(&payload)
        .map_err(|e| format!("Webhook POST failed: {}", e))?;

    info!("Webhook notification sent successfully");
    Ok(())
}
