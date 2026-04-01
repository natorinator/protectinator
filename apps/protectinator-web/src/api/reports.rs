//! PDF report generation endpoint

use crate::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

pub async fn download_pdf(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, StatusCode> {
    let store = state.store.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let scan = store
        .scans
        .get_scan(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let findings = store
        .scans
        .scan_findings(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Drop the lock before the potentially slow PDF generation
    drop(store);

    let pdf_bytes = protectinator_report::generate_pdf_report(&scan, &findings)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let filename = format!("protectinator-scan-{}.pdf", id);

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pdf".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        Body::from(pdf_bytes),
    )
        .into_response())
}
