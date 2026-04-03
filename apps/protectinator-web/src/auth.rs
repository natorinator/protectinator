//! Authentication middleware for Tailscale identity headers
//!
//! When behind `tailscale serve`, Tailscale injects identity headers
//! into proxied requests. This middleware extracts those headers and
//! makes the user identity available to handlers via request extensions.
//!
//! Designed to be extensible for other identity providers in the future.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Header names injected by Tailscale serve
const TAILSCALE_USER_LOGIN: &str = "Tailscale-User-Login";
const TAILSCALE_USER_NAME: &str = "Tailscale-User-Name";
const TAILSCALE_USER_PROFILE_PIC: &str = "Tailscale-User-Profile-Pic";

/// Authenticated user identity extracted from Tailscale headers
#[derive(Debug, Clone, Serialize)]
pub struct UserIdentity {
    /// User email address (from Tailscale-User-Login)
    pub login: String,
    /// Display name (from Tailscale-User-Name)
    pub name: Option<String>,
    /// Profile picture URL (from Tailscale-User-Profile-Pic)
    pub profile_pic: Option<String>,
}

/// Auth middleware that checks for Tailscale identity headers
///
/// Paths exempt from auth: /metrics (Prometheus scraping), /api/status (health checks)
pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, Response> {
    let path = req.uri().path().to_string();

    // Skip auth for health/metrics endpoints
    if path == "/metrics" || path == "/api/status" {
        return Ok(next.run(req).await);
    }

    // Extract Tailscale identity headers
    let login = req
        .headers()
        .get(TAILSCALE_USER_LOGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let Some(login) = login else {
        return Err(unauthorized_response(&path));
    };

    let name = req
        .headers()
        .get(TAILSCALE_USER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let profile_pic = req
        .headers()
        .get(TAILSCALE_USER_PROFILE_PIC)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let identity = UserIdentity {
        login,
        name,
        profile_pic,
    };

    // Insert identity into request extensions for handlers
    req.extensions_mut().insert(identity);

    Ok(next.run(req).await)
}

/// Middleware that injects a dev user identity (for --no-auth mode)
pub async fn dev_auth(mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(UserIdentity {
        login: "dev@localhost".to_string(),
        name: Some("Developer".to_string()),
        profile_pic: None,
    });
    next.run(req).await
}

/// Generate appropriate 401 response based on request path
fn unauthorized_response(path: &str) -> Response {
    if path.starts_with("/api/") {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "unauthorized",
                "message": "Authentication required. Access this dashboard via Tailscale."
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::response::Html(
                r#"<!DOCTYPE html>
<html>
<head><title>Unauthorized</title></head>
<body style="background:#0a0a0a;color:#e5e5e5;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="color:#f87171;font-size:2rem">Unauthorized</h1>
<p style="color:#9ca3af;margin-top:1rem">Access this dashboard via your Tailscale network.</p>
</div>
</body>
</html>"#,
            ),
        )
            .into_response()
    }
}

/// Handler for GET /api/me — returns current user identity
pub async fn get_me(
    axum::extract::Extension(user): axum::extract::Extension<UserIdentity>,
) -> Json<UserIdentity> {
    Json(user)
}
