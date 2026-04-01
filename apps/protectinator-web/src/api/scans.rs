//! Scan-related API endpoints

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use protectinator_data::ScanQuery;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ListScansParams {
    host: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListScansParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let query = ScanQuery {
        host: params.host,
        limit: params.limit,
        offset: params.offset,
    };
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let scans = store.scans.list_scans(&query)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(scans).unwrap_or_default()))
}

pub async fn get_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let scan = store.scans.get_scan(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let findings = store.scans.scan_findings(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "scan": scan,
        "findings": findings,
    })))
}

pub async fn get_scan_findings(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let findings = store.scans.scan_findings(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(findings).unwrap_or_default()))
}

pub async fn diff_scans(
    State(state): State<Arc<AppState>>,
    Path((id, other_id)): Path<(i64, i64)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let diff = store.scans.diff_scans(id, other_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(diff).unwrap_or_default()))
}
