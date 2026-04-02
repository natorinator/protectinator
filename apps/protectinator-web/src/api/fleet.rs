//! Fleet summary API endpoint

use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

pub async fn fleet_summary(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let hosts = store
        .scans
        .list_hosts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_hosts = hosts.len();
    let total_critical: usize = hosts.iter().map(|h| h.latest_critical).sum();
    let total_high: usize = hosts.iter().map(|h| h.latest_high).sum();
    let total_medium: usize = hosts.iter().map(|h| h.latest_medium).sum();
    let total_low: usize = hosts.iter().map(|h| h.latest_low).sum();
    let total_info: usize = hosts.iter().map(|h| h.latest_info).sum();

    // Hosts needing attention (any critical or high findings)
    let needs_attention: Vec<&protectinator_data::HostSummary> = hosts
        .iter()
        .filter(|h| h.latest_critical > 0 || h.latest_high > 0)
        .collect();

    // Scan freshness
    let now = chrono::Utc::now();
    let mut fresh = 0usize; // <24h
    let mut recent = 0usize; // <7d
    let mut stale = 0usize; // >7d

    for host in &hosts {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&host.last_scanned) {
            let age = now.signed_duration_since(dt);
            if age.num_hours() < 24 {
                fresh += 1;
            } else if age.num_days() < 7 {
                recent += 1;
            } else {
                stale += 1;
            }
        } else {
            stale += 1;
        }
    }

    Ok(Json(serde_json::json!({
        "total_hosts": total_hosts,
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
        "total_info": total_info,
        "needs_attention": needs_attention,
        "freshness": {
            "fresh": fresh,
            "recent": recent,
            "stale": stale,
        },
    })))
}
