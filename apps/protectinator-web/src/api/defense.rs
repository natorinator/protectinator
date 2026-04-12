//! Defense remediation plan API endpoints

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

/// GET /api/defense/status — per-host defense posture summary
///
/// Queries the latest defense-category findings per host and returns
/// a summary of firewall, brute-force protection, open ports, and
/// auto-update status.
pub async fn defense_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Get remote hosts with their latest scan
    let hosts = store
        .scans
        .list_hosts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let defense_categories = ["firewall", "bruteforce_protection", "open_ports", "auto_updates"];

    let mut host_statuses = Vec::new();

    for host in &hosts {
        if !host.name.starts_with("remote:") {
            continue;
        }
        let host_name = host.name.strip_prefix("remote:").unwrap_or(&host.name);

        // Get the latest scan ID for this host
        let latest_scan_id = store
            .scans
            .get_latest_scan_id(&host.name)
            .unwrap_or(None);

        let Some(scan_id) = latest_scan_id else {
            continue;
        };

        // Query defense findings for this scan
        let all_findings = store
            .scans
            .query_findings(&protectinator_data::FindingQuery {
                scan_id: Some(scan_id),
                check_category: None,
                severity: None,
                actionability: None,
                limit: Some(500),
                offset: None,
            })
            .unwrap_or_default();

        // Build per-category status
        let mut categories = serde_json::Map::new();
        let mut total_issues = 0;

        for cat in &defense_categories {
            let cat_findings: Vec<_> = all_findings
                .iter()
                .filter(|f| f.check_category.as_deref() == Some(cat))
                .collect();

            let status = if cat_findings.is_empty() {
                "ok"
            } else if cat_findings.iter().any(|f| f.severity == "critical" || f.severity == "high") {
                "critical"
            } else {
                "warning"
            };

            total_issues += cat_findings.len();

            let details: Vec<serde_json::Value> = cat_findings
                .iter()
                .map(|f| serde_json::json!({
                    "title": f.title,
                    "severity": f.severity,
                    "resource": f.resource,
                    "remediation": f.remediation,
                }))
                .collect();

            categories.insert(cat.to_string(), serde_json::json!({
                "status": status,
                "findings": cat_findings.len(),
                "details": details,
            }));
        }

        host_statuses.push(serde_json::json!({
            "host": host_name,
            "scanned_at": host.last_scanned,
            "categories": categories,
            "total_issues": total_issues,
        }));
    }

    // Sort by total_issues descending (worst hosts first)
    host_statuses.sort_by(|a, b| {
        let a_issues = a["total_issues"].as_u64().unwrap_or(0);
        let b_issues = b["total_issues"].as_u64().unwrap_or(0);
        b_issues.cmp(&a_issues)
    });

    Ok(Json(serde_json::json!({
        "hosts": host_statuses,
        "total_hosts": host_statuses.len(),
    })))
}

/// GET /api/defense/plans — list all remediation plans
pub async fn list_plans(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<protectinator_data::StoredPlan>>, StatusCode> {
    let store = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let plans = store
        .scans
        .list_plans(None, None)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(plans))
}

/// GET /api/defense/plans/:id — get a single plan
pub async fn get_plan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let plan = store
        .scans
        .get_plan(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let actions: serde_json::Value =
        serde_json::from_str(&plan.actions_json).unwrap_or(serde_json::json!([]));

    Ok(Json(serde_json::json!({
        "id": plan.id,
        "host": plan.host,
        "created_at": plan.created_at,
        "status": plan.status,
        "actions": actions,
        "source_findings": plan.source_findings,
        "approved_at": plan.approved_at,
        "executed_at": plan.executed_at,
        "result": plan.result_json.and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok()),
    })))
}

/// POST /api/defense/plans/:id/approve — approve a pending plan
pub async fn approve_plan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
    })?;

    let plan = store
        .scans
        .get_plan(id)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to load plan"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "plan not found"})),
        ))?;

    if plan.status != "pending" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("plan is '{}', can only approve 'pending' plans", plan.status)
            })),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    store
        .scans
        .update_plan_status(id, "approved", Some(("approved_at", &now)))
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to update plan"})),
            )
        })?;

    Ok(Json(serde_json::json!({
        "id": id,
        "status": "approved",
        "approved_at": now,
    })))
}

/// POST /api/defense/plans/:id/status — update plan status (deny, ignore, remind)
pub async fn update_plan_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let new_status = body
        .get("status")
        .and_then(|s| s.as_str())
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing 'status' field"})),
        ))?;

    let allowed = ["denied", "ignored", "remind", "pending", "superseded"];
    if !allowed.contains(&new_status) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("status must be one of: {}", allowed.join(", "))
            })),
        ));
    }

    let store = state.store.lock().map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal error"})),
    ))?;

    let plan = store.scans.get_plan(id).map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "failed to load plan"})),
    ))?.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "plan not found"})),
    ))?;

    let changeable = ["pending", "remind", "denied", "ignored", "approved", "failed"];
    if !changeable.contains(&plan.status.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("cannot change status of '{}' plans", plan.status)
            })),
        ));
    }

    store.scans.update_plan_status(id, new_status, None).map_err(|_| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "failed to update plan"})),
    ))?;

    Ok(Json(serde_json::json!({
        "id": id,
        "status": new_status,
    })))
}
