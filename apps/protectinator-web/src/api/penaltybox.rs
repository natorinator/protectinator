//! Penalty box API endpoint

use axum::http::StatusCode;
use axum::Json;

pub async fn list_profiles() -> Result<Json<serde_json::Value>, StatusCode> {
    let profiles = protectinator_penaltybox::profile::list_profiles().unwrap_or_default();
    Ok(Json(
        serde_json::to_value(profiles).unwrap_or(serde_json::json!([])),
    ))
}
