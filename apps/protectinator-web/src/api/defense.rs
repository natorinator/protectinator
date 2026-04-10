//! Defense remediation plan API endpoints

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

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

    // Parse actions_json for the response
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

    // Only allow these transitions
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

    // Can only change status from these states (not done/executing)
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
