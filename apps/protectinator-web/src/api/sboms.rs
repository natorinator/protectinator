//! SBOM-related API endpoints

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

pub async fn list_sboms(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let names = store.sboms.list_names();
    Ok(Json(serde_json::to_value(names).unwrap_or_default()))
}

#[derive(Deserialize)]
pub struct SearchParams {
    q: String,
}

pub async fn search_packages(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let results = store.sboms.search_package(&params.q);
    Ok(Json(serde_json::to_value(results).unwrap_or_default()))
}

pub async fn get_sbom(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sbom = store.sboms.get_sbom(&name)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(sbom))
}
