//! Embedded frontend serving via rust-embed

use axum::http::{header, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "frontend/"]
struct FrontendAssets;

pub async fn serve_frontend(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try exact path first
    if let Some(content) = FrontendAssets::get(path) {
        let mime = mime_type(path);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime)],
            content.data.to_vec(),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for all non-API, non-asset routes
    if let Some(content) = FrontendAssets::get("index.html") {
        return Html(String::from_utf8_lossy(&content.data).to_string()).into_response();
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

fn mime_type(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".html") {
        "text/html"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}
