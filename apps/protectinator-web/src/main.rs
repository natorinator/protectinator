//! Protectinator Web Dashboard
//!
//! REST API and web frontend for viewing scan results, findings,
//! host status, and advisory feeds.

mod api;
mod auth;
mod frontend;
mod metrics;

use clap::Parser;
use protectinator_data::DataStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Protectinator Web Dashboard
#[derive(Parser)]
#[command(name = "protectinator-web")]
#[command(about = "Web dashboard for Protectinator scan results")]
struct Cli {
    /// Data directory (default: ~/.local/share/protectinator)
    #[arg(long)]
    db_path: Option<PathBuf>,

    /// Bind address
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,

    /// Enable verbose logging
    #[arg(long, short)]
    verbose: bool,

    /// Disable authentication (for local development)
    #[arg(long)]
    no_auth: bool,
}

/// Shared application state
pub struct AppState {
    pub store: Mutex<DataStore>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new(filter))
        .init();

    // Open data stores
    let data_dir = cli
        .db_path
        .unwrap_or_else(|| protectinator_data::default_data_dir().expect("HOME not set"));

    info!("Opening data stores from {}", data_dir.display());
    let store = DataStore::open(&data_dir).expect("Failed to open data stores");

    let status = store.status();
    info!(
        "Data loaded: {} scans, {} findings, {} SBOMs, {} cached advisories",
        status.scan_count, status.finding_count, status.sbom_count, status.vuln_cache_count
    );

    let state = Arc::new(AppState {
        store: Mutex::new(store),
    });

    // Build router
    let app = api::router(state.clone())
        .fallback(frontend::serve_frontend);

    // Apply auth middleware to ALL routes
    let app = if cli.no_auth {
        info!("Authentication disabled (--no-auth)");
        app.layer(axum::middleware::from_fn(auth::dev_auth))
    } else {
        info!("Authentication enabled (Tailscale identity headers)");
        app.layer(axum::middleware::from_fn(auth::require_auth))
    };

    // Start server
    let addr: SocketAddr = cli
        .bind
        .parse()
        .expect("Invalid bind address");

    info!("Starting Protectinator Web on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app).await.expect("Server error");
}
