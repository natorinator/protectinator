//! Finding query endpoints

use crate::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use protectinator_data::FindingQuery;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct FindingParams {
    scan_id: Option<i64>,
    severity: Option<String>,
    check_category: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn query_findings(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let query = FindingQuery {
        scan_id: params.scan_id,
        severity: params.severity,
        check_category: params.check_category,
        limit: params.limit,
        offset: params.offset,
    };
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let findings = store.scans.query_findings(&query)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(findings).unwrap_or_default()))
}
