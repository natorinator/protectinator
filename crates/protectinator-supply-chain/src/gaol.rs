//! Gaol integration for sandboxed package evaluation
//!
//! Invokes `gaol eval-dep` and `gaol dev-install` to get behavioral
//! analysis of packages in a sandboxed environment, then converts
//! the findings to protectinator Finding format.

use protectinator_core::{Finding, FindingSource, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;
use tracing::debug;

/// Default gaol binary path
const GAOL_BINARY: &str = "gaol";

/// Check if gaol is available on the system
pub fn gaol_available() -> bool {
    Command::new(GAOL_BINARY)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Find the gaol binary, checking common locations
fn find_gaol() -> Option<String> {
    // Check PATH first
    if gaol_available() {
        return Some(GAOL_BINARY.to_string());
    }

    // Check ~/.local/bin/gaol
    if let Ok(home) = std::env::var("HOME") {
        let local_path = format!("{}/.local/bin/gaol", home);
        if Command::new(&local_path)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(local_path);
        }
    }

    None
}

/// Result from gaol eval-dep
#[derive(Debug, Deserialize)]
struct GaolResult {
    #[allow(dead_code)]
    tool: String,
    findings: Vec<GaolFinding>,
    #[allow(dead_code)]
    context: serde_json::Value,
}

/// A finding from gaol's JSON output
#[derive(Debug, Deserialize)]
struct GaolFinding {
    id: String,
    title: String,
    description: String,
    severity: String,
    source: serde_json::Value,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    remediation: Option<String>,
}

/// Evaluate a package dependency using gaol's sandbox
pub fn eval_dep(
    package: &str,
    ecosystem: &str,
    version: Option<&str>,
) -> Result<Vec<Finding>, String> {
    let gaol = find_gaol().ok_or("gaol binary not found (checked PATH and ~/.local/bin/gaol)")?;

    let mut cmd = Command::new(&gaol);
    cmd.arg("eval-dep")
        .arg(package)
        .arg("--ecosystem")
        .arg(ecosystem)
        .arg("--json");

    if let Some(v) = version {
        cmd.arg("--version").arg(v);
    }

    debug!("Running: {} eval-dep {} --ecosystem {} --json", gaol, package, ecosystem);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run gaol eval-dep: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gaol_output(&stdout, "eval-dep")
}

/// Run sandboxed package installation using gaol
pub fn dev_install(
    project_dir: &Path,
    ecosystem: Option<&str>,
) -> Result<Vec<Finding>, String> {
    let gaol = find_gaol().ok_or("gaol binary not found (checked PATH and ~/.local/bin/gaol)")?;

    let mut cmd = Command::new(&gaol);
    cmd.arg("dev-install")
        .arg(project_dir)
        .arg("--json");

    if let Some(eco) = ecosystem {
        cmd.arg("--ecosystem").arg(eco);
    }

    debug!(
        "Running: {} dev-install {} --json",
        gaol,
        project_dir.display()
    );

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run gaol dev-install: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gaol_output(&stdout, "dev-install")
}

/// Parse gaol JSON output and convert to protectinator Findings
fn parse_gaol_output(json_str: &str, tool: &str) -> Result<Vec<Finding>, String> {
    let result: GaolResult = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse gaol {} output: {}", tool, e))?;

    let findings = result
        .findings
        .into_iter()
        .map(|gf| convert_finding(gf))
        .collect();

    Ok(findings)
}

/// Convert a gaol finding to a protectinator Finding
fn convert_finding(gf: GaolFinding) -> Finding {
    let severity = match gf.severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    };

    // Extract the gaol source type for our check_category
    let check_category = gf
        .source
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("gaol_sandbox")
        .to_string();

    let mut finding = Finding::new(
        format!("gaol-{}", gf.id),
        gf.title,
        gf.description,
        severity,
        FindingSource::SupplyChain {
            check_category: format!("gaol_{}", check_category),
            ecosystem: None,
        },
    );

    if let Some(resource) = gf.resource {
        finding = finding.with_resource(resource);
    }
    if let Some(remediation) = gf.remediation {
        finding = finding.with_remediation(remediation);
    }
    if let Some(metadata) = gf.metadata {
        if let Some(obj) = metadata.as_object() {
            for (k, v) in obj {
                finding = finding.with_metadata(k, v.clone());
            }
        }
    }

    // Preserve the original gaol source info as metadata
    finding = finding.with_metadata("gaol_source", gf.source);

    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clean_eval_dep() {
        let json = r#"{
            "tool": "eval-dep",
            "started_at": "2026-03-26T17:32:37Z",
            "completed_at": "2026-03-26T17:32:39Z",
            "findings": [],
            "context": {
                "package": "requests",
                "ecosystem": "python",
                "exit_code": 0
            }
        }"#;

        let findings = parse_gaol_output(json, "eval-dep").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_findings_with_severity() {
        let json = r#"{
            "tool": "eval-dep",
            "started_at": "2026-03-26T17:32:37Z",
            "completed_at": "2026-03-26T17:32:39Z",
            "findings": [
                {
                    "id": "network-outbound",
                    "title": "Unexpected outbound connection during install",
                    "description": "Package made connection to 45.148.10.212:443 during pip install",
                    "severity": "critical",
                    "source": {"type": "sandbox_behavior", "observation_type": "network"},
                    "resource": "requests==2.31.0"
                },
                {
                    "id": "filesystem-write",
                    "title": "Write to ~/.bashrc during install",
                    "description": "Package modified shell profile",
                    "severity": "high",
                    "source": {"type": "sandbox_behavior", "observation_type": "filesystem"}
                }
            ],
            "context": {"package": "evil-pkg", "ecosystem": "python"}
        }"#;

        let findings = parse_gaol_output(json, "eval-dep").unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].id, "gaol-network-outbound");
        assert!(findings[0].resource.as_deref() == Some("requests==2.31.0"));
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn test_parse_dev_install_findings() {
        let json = r#"{
            "tool": "dev-install",
            "started_at": "2026-03-26T17:32:44Z",
            "completed_at": "2026-03-26T17:32:44Z",
            "findings": [
                {
                    "id": "gaol-firewall-failed",
                    "title": "Registry firewall failed to apply",
                    "description": "nftables firewall could not be applied",
                    "severity": "medium",
                    "source": {"type": "network_firewall", "rule_action": "apply"}
                }
            ],
            "context": {"ecosystem": "rust"}
        }"#;

        let findings = parse_gaol_output(json, "dev-install").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_parse_malformed_json() {
        let result = parse_gaol_output("not json", "eval-dep");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_finding_preserves_metadata() {
        let json = r#"{
            "tool": "eval-dep",
            "started_at": "2026-03-26T17:32:37Z",
            "completed_at": "2026-03-26T17:32:39Z",
            "findings": [
                {
                    "id": "test",
                    "title": "Test finding",
                    "description": "Test",
                    "severity": "low",
                    "source": {"type": "sandbox_behavior"},
                    "metadata": {"exit_code": 1, "signal": "SIGKILL"}
                }
            ],
            "context": {}
        }"#;

        let findings = parse_gaol_output(json, "eval-dep").unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].metadata.contains_key("exit_code"));
        assert!(findings[0].metadata.contains_key("gaol_source"));
    }
}
