//! REST API routes

mod findings;
mod hosts;
mod reports;
mod scans;
mod sboms;
mod status;

use crate::AppState;
use axum::{routing::get, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // Status
        .route("/api/status", get(status::get_status))
        // Scans
        .route("/api/scans", get(scans::list_scans))
        .route("/api/scans/{id}", get(scans::get_scan))
        .route("/api/scans/{id}/findings", get(scans::get_scan_findings))
        .route("/api/scans/{id}/diff/{other_id}", get(scans::diff_scans))
        // Findings
        .route("/api/findings", get(findings::query_findings))
        // Hosts
        .route("/api/hosts", get(hosts::list_hosts))
        .route("/api/hosts/{name}/timeline", get(hosts::host_timeline))
        .route("/api/hosts/{name}/trends", get(hosts::host_trends))
        // Reports (PDF)
        .route("/api/reports/{id}/pdf", get(reports::download_pdf))
        // SBOMs
        .route("/api/sboms", get(sboms::list_sboms))
        .route("/api/sboms/search", get(sboms::search_packages))
        .route("/api/sboms/{name}", get(sboms::get_sbom))
        // Advisories
        .route("/api/advisories", get(status::list_advisories))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
