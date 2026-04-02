//! Prometheus metrics endpoint
//!
//! Collects metrics from scan_history.db and exposes them in Prometheus
//! text exposition format at /metrics.

use crate::AppState;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use std::fmt::Write;
use std::sync::Arc;

/// Handler for GET /metrics
pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Response, StatusCode> {
    let store = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut output = String::with_capacity(4096);

    // Global metrics
    let status = store.status();

    write_metric(
        &mut output,
        "protectinator_total_scans",
        "Total number of scans stored",
        status.scan_count as f64,
    );
    write_metric(
        &mut output,
        "protectinator_total_findings",
        "Total number of findings across all scans",
        status.finding_count as f64,
    );
    write_metric(
        &mut output,
        "protectinator_sbom_count",
        "Number of SBOM files",
        status.sbom_count as f64,
    );
    write_metric(
        &mut output,
        "protectinator_vuln_cache_count",
        "Number of cached advisory classifications",
        status.vuln_cache_count as f64,
    );

    // Per-host metrics
    if let Ok(hosts) = store.scans.list_hosts() {
        write_metric_header(
            &mut output,
            "protectinator_host_findings_total",
            "gauge",
            "Total findings from latest scan per host",
        );
        for host in &hosts {
            write_labeled_metric(
                &mut output,
                "protectinator_host_findings_total",
                &[("host", &host.name)],
                (host.latest_critical + host.latest_high + host.latest_medium + host.latest_low + host.latest_info) as f64,
            );
        }

        write_metric_header(
            &mut output,
            "protectinator_host_findings",
            "gauge",
            "Findings by severity from latest scan per host",
        );
        for host in &hosts {
            write_labeled_metric(
                &mut output,
                "protectinator_host_findings",
                &[("host", &host.name), ("severity", "critical")],
                host.latest_critical as f64,
            );
            write_labeled_metric(
                &mut output,
                "protectinator_host_findings",
                &[("host", &host.name), ("severity", "high")],
                host.latest_high as f64,
            );
            write_labeled_metric(
                &mut output,
                "protectinator_host_findings",
                &[("host", &host.name), ("severity", "medium")],
                host.latest_medium as f64,
            );
            write_labeled_metric(
                &mut output,
                "protectinator_host_findings",
                &[("host", &host.name), ("severity", "low")],
                host.latest_low as f64,
            );
            write_labeled_metric(
                &mut output,
                "protectinator_host_findings",
                &[("host", &host.name), ("severity", "info")],
                host.latest_info as f64,
            );
        }

        write_metric_header(
            &mut output,
            "protectinator_host_last_scan_timestamp",
            "gauge",
            "Unix timestamp of last scan per host",
        );
        for host in &hosts {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&host.last_scanned) {
                write_labeled_metric(
                    &mut output,
                    "protectinator_host_last_scan_timestamp",
                    &[("host", &host.name)],
                    dt.timestamp() as f64,
                );
            }
        }

        write_metric(
            &mut output,
            "protectinator_total_hosts",
            "Number of hosts tracked",
            hosts.len() as f64,
        );
    }

    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
        .into_response())
}

fn write_metric(output: &mut String, name: &str, help: &str, value: f64) {
    let _ = writeln!(output, "# HELP {} {}", name, help);
    let _ = writeln!(output, "# TYPE {} gauge", name);
    let _ = writeln!(output, "{} {}", name, value);
}

fn write_metric_header(output: &mut String, name: &str, metric_type: &str, help: &str) {
    let _ = writeln!(output, "# HELP {} {}", name, help);
    let _ = writeln!(output, "# TYPE {} {}", name, metric_type);
}

fn write_labeled_metric(output: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    let label_str: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, v))
        .collect();
    let _ = writeln!(output, "{}{{{}}} {}", name, label_str.join(","), value);
}
