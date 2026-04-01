//! Host-related API endpoints

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

pub async fn list_hosts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let hosts = store.scans.list_hosts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(hosts).unwrap_or_default()))
}

#[derive(Deserialize)]
pub struct TimelineParams {
    limit: Option<usize>,
}

pub async fn host_timeline(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<TimelineParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let limit = params.limit.unwrap_or(20);
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let scans = store.scans.host_timeline(&name, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(scans).unwrap_or_default()))
}

pub async fn host_trends(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<TimelineParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let limit = params.limit.unwrap_or(30);
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let scans = store.scans.host_trends(&name, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(scans).unwrap_or_default()))
}
