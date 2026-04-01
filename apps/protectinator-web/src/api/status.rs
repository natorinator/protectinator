//! Status and health check endpoints

use crate::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let status = store.status();
    Ok(Json(serde_json::to_value(status).unwrap_or_default()))
}

#[derive(Deserialize)]
pub struct AdvisoryParams {
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn list_advisories(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AdvisoryParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let advisories = store.vulns.list_advisories(limit, offset)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(advisories).unwrap_or_default()))
}
