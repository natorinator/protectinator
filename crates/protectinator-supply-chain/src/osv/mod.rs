//! OSV (Open Source Vulnerabilities) API client
//!
//! Queries the OSV.dev API for known vulnerabilities in project dependencies.
//! Uses batch queries to efficiently check large dependency sets.

use crate::types::{Ecosystem, PackageEntry};
use chrono::Utc;
use protectinator_core::Severity;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Maximum number of queries per OSV batch request
const OSV_BATCH_LIMIT: usize = 1000;

/// OSV API endpoint for batch queries
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// Request timeout in seconds
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// A vulnerability record from the OSV database, enriched with originating package info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    /// CWE IDs from database_specific (e.g., ["CWE-79", "CWE-89"])
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// Package name that triggered this vulnerability match
    pub package_name: String,
    /// Package version that triggered this vulnerability match
    pub package_version: String,
    /// Ecosystem of the matched package
    pub ecosystem: Ecosystem,
}

/// CVSS severity score from OSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

/// Errors from OSV API interactions
#[derive(Debug)]
pub enum OsvError {
    /// HTTP request failed
    Http(String),
    /// Response parsing failed
    Parse(String),
    /// Rate limited by the API
    RateLimit,
}

impl fmt::Display for OsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsvError::Http(msg) => write!(f, "OSV HTTP error: {}", msg),
            OsvError::Parse(msg) => write!(f, "OSV parse error: {}", msg),
            OsvError::RateLimit => write!(f, "OSV API rate limit exceeded"),
        }
    }
}

impl std::error::Error for OsvError {}

/// Synchronous client for the OSV.dev vulnerability database API
pub struct OsvClient {
    agent: ureq::Agent,
}

impl OsvClient {
    /// Create a new OSV client with default settings (10s timeout)
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build();
        Self { agent }
    }

    /// Query the OSV API for vulnerabilities affecting the given packages.
    ///
    /// Batches requests in groups of 1000 (OSV API limit) and returns a
    /// flattened list of vulnerabilities with originating package info attached.
    /// GHSA advisories are enriched with CVSS/CWE data from individual lookups.
    pub fn query_batch(
        &self,
        packages: &[PackageEntry],
    ) -> Result<Vec<OsvVulnerability>, OsvError> {
        let mut all_vulns = Vec::new();

        for chunk in packages.chunks(OSV_BATCH_LIMIT) {
            let vulns = self.query_batch_chunk(chunk)?;
            all_vulns.extend(vulns);
        }

        // Enrich GHSA advisories with CVSS/CWE classification data
        self.enrich_vulns(&mut all_vulns);

        Ok(all_vulns)
    }

    /// Fetch full details for GHSA advisories to get CVSS vectors and CWE IDs.
    /// Uses a SQLite cache to avoid redundant network requests.
    fn enrich_vulns(&self, vulns: &mut [OsvVulnerability]) {
        let to_enrich: Vec<usize> = vulns
            .iter()
            .enumerate()
            .filter(|(_, v)| v.severity.is_empty() && v.id.starts_with("GHSA-"))
            .map(|(i, _)| i)
            .collect();

        if to_enrich.is_empty() {
            return;
        }

        let cache = open_classification_cache();
        let mut to_fetch = Vec::new();

        // Check cache first
        for &idx in &to_enrich {
            if let Some(ref conn) = cache {
                if let Some((sev_type, sev_score, cwes)) = get_cached_classification(conn, &vulns[idx].id) {
                    if let (Some(t), Some(s)) = (&sev_type, &sev_score) {
                        vulns[idx].severity.push(OsvSeverity {
                            severity_type: t.clone(),
                            score: s.clone(),
                        });
                    }
                    vulns[idx].cwe_ids = cwes;
                    continue;
                }
            }
            to_fetch.push(idx);
        }

        for idx in to_fetch {
            let url = format!("https://api.osv.dev/v1/vulns/{}", vulns[idx].id);
            let resp = match self.agent.get(&url).call() {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body: serde_json::Value = match resp.into_json() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let mut sev_type = None;
            let mut sev_score = None;
            let mut cwes = Vec::new();

            if let Some(sev_arr) = body.get("severity").and_then(|v| v.as_array()) {
                if let Some(sev) = sev_arr.first() {
                    if let (Some(t), Some(s)) = (
                        sev.get("type").and_then(|v| v.as_str()),
                        sev.get("score").and_then(|v| v.as_str()),
                    ) {
                        sev_type = Some(t.to_string());
                        sev_score = Some(s.to_string());
                        vulns[idx].severity.push(OsvSeverity {
                            severity_type: t.to_string(),
                            score: s.to_string(),
                        });
                    }
                }
            }

            if let Some(cwe_arr) = body
                .get("database_specific")
                .and_then(|ds| ds.get("cwe_ids"))
                .and_then(|v| v.as_array())
            {
                for cwe in cwe_arr {
                    if let Some(s) = cwe.as_str() {
                        cwes.push(s.to_string());
                        vulns[idx].cwe_ids.push(s.to_string());
                    }
                }
            }

            if let Some(ref conn) = cache {
                set_cached_classification(conn, &vulns[idx].id, &sev_type, &sev_score, &cwes);
            }
        }
    }

    /// Send a single batch request for up to 1000 packages
    fn query_batch_chunk(
        &self,
        packages: &[PackageEntry],
    ) -> Result<Vec<OsvVulnerability>, OsvError> {
        let queries: Vec<serde_json::Value> = packages
            .iter()
            .map(|pkg| {
                serde_json::json!({
                    "package": {
                        "name": pkg.name,
                        "ecosystem": pkg.ecosystem.osv_name()
                    },
                    "version": pkg.version
                })
            })
            .collect();

        let body = serde_json::json!({ "queries": queries });

        let response = self
            .agent
            .post(OSV_BATCH_URL)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| {
                if let ureq::Error::Status(429, _) = e {
                    return OsvError::RateLimit;
                }
                OsvError::Http(e.to_string())
            })?;

        let response_body: BatchResponse = response
            .into_json()
            .map_err(|e| OsvError::Parse(format!("Failed to parse OSV response: {}", e)))?;

        let mut vulns = Vec::new();
        for (idx, result) in response_body.results.into_iter().enumerate() {
            if let Some(result_vulns) = result.vulns {
                let pkg = &packages[idx];
                for raw_vuln in result_vulns {
                    let cwe_ids = raw_vuln
                        .database_specific
                        .map(|ds| ds.cwe_ids)
                        .unwrap_or_default();
                    vulns.push(OsvVulnerability {
                        id: raw_vuln.id,
                        summary: raw_vuln.summary,
                        details: raw_vuln.details,
                        aliases: raw_vuln.aliases,
                        severity: raw_vuln.severity,
                        cwe_ids,
                        package_name: pkg.name.clone(),
                        package_version: pkg.version.clone(),
                        ecosystem: pkg.ecosystem,
                    });
                }
            }
        }

        Ok(vulns)
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Map CVSS severity scores to our Severity enum.
///
/// Parses CVSS v3 vector strings to extract the numeric base score,
/// then maps: 0-3.9=Low, 4.0-6.9=Medium, 7.0-8.9=High, 9.0+=Critical.
/// Falls back to Medium if no score can be parsed.
pub fn map_cvss_to_severity(severities: &[OsvSeverity]) -> Severity {
    // Prefer CVSS_V3 over CVSS_V2
    let cvss_v3 = severities
        .iter()
        .find(|s| s.severity_type == "CVSS_V3");
    let chosen = cvss_v3.or_else(|| severities.first());

    let Some(sev) = chosen else {
        return Severity::Medium;
    };

    match parse_cvss_score(&sev.score) {
        Some(score) if score >= 9.0 => Severity::Critical,
        Some(score) if score >= 7.0 => Severity::High,
        Some(score) if score >= 4.0 => Severity::Medium,
        Some(score) if score >= 0.0 => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Parse a numeric CVSS base score from a CVSS vector string or plain number.
///
/// Handles formats like:
/// - "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (vector string, needs scoring)
/// - "9.8" (plain numeric score)
fn parse_cvss_score(score_str: &str) -> Option<f64> {
    // Try plain numeric first
    if let Ok(score) = score_str.parse::<f64>() {
        return Some(score);
    }

    // Parse CVSS v3 vector string
    if score_str.starts_with("CVSS:3") {
        return score_cvss_v3_vector(score_str);
    }

    None
}

/// Compute an approximate CVSS v3 base score from a vector string.
///
/// This is a simplified scoring implementation that covers the most common
/// cases. For production use, a full CVSS calculator would be preferred,
/// but for severity bucketing (Low/Medium/High/Critical) this is sufficient.
fn score_cvss_v3_vector(vector: &str) -> Option<f64> {
    let mut metrics = std::collections::HashMap::new();
    for part in vector.split('/') {
        if let Some((key, value)) = part.split_once(':') {
            metrics.insert(key, value);
        }
    }

    // Base metrics
    let av: f64 = match metrics.get("AV")? {
        &"N" => 0.85,  // Network
        &"A" => 0.62,  // Adjacent
        &"L" => 0.55,  // Local
        &"P" => 0.20,  // Physical
        _ => return None,
    };

    let ac = match metrics.get("AC")? {
        &"L" => 0.77,  // Low
        &"H" => 0.44,  // High
        _ => return None,
    };

    let pr_scope_changed = metrics.get("S").map(|s| *s == "C").unwrap_or(false);
    let pr = match (metrics.get("PR")?, pr_scope_changed) {
        (&"N", _) => 0.85,
        (&"L", false) => 0.62,
        (&"L", true) => 0.68,
        (&"H", false) => 0.27,
        (&"H", true) => 0.50,
        _ => return None,
    };

    let ui = match metrics.get("UI")? {
        &"N" => 0.85,  // None
        &"R" => 0.62,  // Required
        _ => return None,
    };

    let c = match metrics.get("C")? {
        &"H" => 0.56,
        &"L" => 0.22,
        &"N" => 0.0,
        _ => return None,
    };

    let i = match metrics.get("I")? {
        &"H" => 0.56,
        &"L" => 0.22,
        &"N" => 0.0,
        _ => return None,
    };

    let a = match metrics.get("A")? {
        &"H" => 0.56,
        &"L" => 0.22,
        &"N" => 0.0,
        _ => return None,
    };

    // ISS = 1 - [(1 - C) * (1 - I) * (1 - A)]
    let iss: f64 = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);

    if iss <= 0.0 {
        return Some(0.0);
    }

    // Impact
    let impact = if pr_scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    // Exploitability
    let exploitability = 8.22 * av * ac * pr * ui;

    // Base score
    let base = if pr_scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };

    // Round up to nearest 0.1
    Some((base * 10.0).ceil() / 10.0)
}

/// Classify a vulnerability based on CVSS vector metrics and CWE IDs.
///
/// Returns a short tag string like "[Remote/RCE]", "[Local/DoS]", "[Remote/Injection]".
/// Returns empty string if no classification can be determined.
pub fn classify_vulnerability(severities: &[OsvSeverity], cwe_ids: &[String]) -> String {
    let mut tags = Vec::new();

    // Extract CVSS vector metrics
    let vector = severities
        .iter()
        .find(|s| s.severity_type == "CVSS_V3" || s.severity_type == "CVSS_V4")
        .map(|s| &s.score);

    if let Some(vec_str) = vector {
        let metrics: std::collections::HashMap<&str, &str> = vec_str
            .split('/')
            .filter_map(|p| p.split_once(':'))
            .collect();

        // Attack vector
        match metrics.get("AV") {
            Some(&"N") => tags.push("Remote"),
            Some(&"A") => tags.push("Adjacent"),
            Some(&"L") => tags.push("Local"),
            Some(&"P") => tags.push("Physical"),
            _ => {}
        }

        // Impact type from C/I/A metrics (v3 or v4)
        let c = metrics.get("VC").or(metrics.get("C")).copied().unwrap_or("N");
        let i = metrics.get("VI").or(metrics.get("I")).copied().unwrap_or("N");
        let a = metrics.get("VA").or(metrics.get("A")).copied().unwrap_or("N");
        let scope_change = metrics.get("S").copied() == Some("C");

        let has_conf = c == "H" || c == "L";
        let has_integ = i == "H" || i == "L";
        let has_avail = a == "H" || a == "L";

        if !has_conf && !has_integ && has_avail {
            tags.push("DoS");
        } else if has_conf && has_integ && has_avail && scope_change {
            tags.push("RCE");
        } else if has_conf && has_integ && !has_avail {
            tags.push("Data");
        } else if !has_conf && has_integ && !has_avail {
            tags.push("Tampering");
        } else if has_conf && !has_integ && !has_avail {
            tags.push("InfoLeak");
        }
    }

    // CWE-based classification
    for cwe in cwe_ids {
        match cwe.as_str() {
            "CWE-78" | "CWE-94" | "CWE-77" | "CWE-917" | "CWE-502" => {
                if !tags.contains(&"RCE") { tags.push("RCE"); }
            }
            "CWE-89" | "CWE-79" | "CWE-91" | "CWE-611" => {
                if !tags.contains(&"Injection") { tags.push("Injection"); }
            }
            "CWE-269" | "CWE-250" | "CWE-266" | "CWE-732" => {
                if !tags.contains(&"PrivEsc") { tags.push("PrivEsc"); }
            }
            "CWE-287" | "CWE-306" | "CWE-862" | "CWE-863" | "CWE-284" => {
                if !tags.contains(&"AuthBypass") { tags.push("AuthBypass"); }
            }
            "CWE-400" | "CWE-770" | "CWE-674" | "CWE-835" => {
                if !tags.contains(&"DoS") { tags.push("DoS"); }
            }
            "CWE-119" | "CWE-120" | "CWE-122" | "CWE-125" | "CWE-787" | "CWE-416" | "CWE-190" => {
                if !tags.contains(&"MemCorrupt") { tags.push("MemCorrupt"); }
            }
            "CWE-22" | "CWE-23" | "CWE-36" => {
                if !tags.contains(&"PathTraversal") { tags.push("PathTraversal"); }
            }
            "CWE-200" | "CWE-209" | "CWE-532" => {
                if !tags.contains(&"InfoLeak") { tags.push("InfoLeak"); }
            }
            "CWE-295" | "CWE-326" | "CWE-327" | "CWE-328" | "CWE-330" => {
                if !tags.contains(&"Crypto") { tags.push("Crypto"); }
            }
            _ => {}
        }
    }

    if tags.is_empty() {
        return String::new();
    }

    format!("[{}]", tags.join("/"))
}

// --- Classification cache (shared SQLite) ---

fn open_classification_cache() -> Option<rusqlite::Connection> {
    let home = std::env::var("HOME").ok()?;
    let db_path = std::path::PathBuf::from(home)
        .join(".local/share/protectinator/vuln_cache.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    let conn = rusqlite::Connection::open(&db_path).ok()?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vuln_classification (
            advisory_id TEXT PRIMARY KEY,
            severity_type TEXT,
            severity_score TEXT,
            cwe_ids TEXT,
            cached_at TEXT NOT NULL
        )"
    ).ok()?;
    Some(conn)
}

fn get_cached_classification(
    conn: &rusqlite::Connection,
    advisory_id: &str,
) -> Option<(Option<String>, Option<String>, Vec<String>)> {
    let mut stmt = conn.prepare(
        "SELECT severity_type, severity_score, cwe_ids FROM vuln_classification WHERE advisory_id = ?1"
    ).ok()?;
    stmt.query_row(rusqlite::params![advisory_id], |row| {
        let cwe_str: Option<String> = row.get(2)?;
        let cwes = cwe_str
            .map(|s| s.split(',').filter(|c| !c.is_empty()).map(String::from).collect())
            .unwrap_or_default();
        Ok((row.get(0)?, row.get(1)?, cwes))
    }).ok()
}

fn set_cached_classification(
    conn: &rusqlite::Connection,
    advisory_id: &str,
    sev_type: &Option<String>,
    sev_score: &Option<String>,
    cwe_ids: &[String],
) {
    let cwe_str = cwe_ids.join(",");
    let now = chrono::Utc::now().to_rfc3339();
    let _ = conn.execute(
        "INSERT OR REPLACE INTO vuln_classification (advisory_id, severity_type, severity_score, cwe_ids, cached_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![advisory_id, sev_type, sev_score, cwe_str, now],
    );
}

// --- Internal deserialization types for OSV API responses ---

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    vulns: Option<Vec<RawVulnerability>>,
}

#[derive(Deserialize)]
struct RawVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<RawDatabaseSpecific>,
}

#[derive(Deserialize)]
struct RawDatabaseSpecific {
    #[serde(default)]
    cwe_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_cvss_critical() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "9.8".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Critical);
    }

    #[test]
    fn test_map_cvss_high() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "7.5".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::High);
    }

    #[test]
    fn test_map_cvss_medium() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "5.3".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Medium);
    }

    #[test]
    fn test_map_cvss_low() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "2.1".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Low);
    }

    #[test]
    fn test_map_cvss_empty_defaults_to_medium() {
        assert_eq!(map_cvss_to_severity(&[]), Severity::Medium);
    }

    #[test]
    fn test_map_cvss_prefers_v3_over_v2() {
        let severities = vec![
            OsvSeverity {
                severity_type: "CVSS_V2".to_string(),
                score: "2.0".to_string(), // Low
            },
            OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "9.1".to_string(), // Critical
            },
        ];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Critical);
    }

    #[test]
    fn test_map_cvss_falls_back_to_v2_if_no_v3() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V2".to_string(),
            score: "7.5".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::High);
    }

    #[test]
    fn test_map_cvss_unparseable_defaults_to_medium() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "not-a-score".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Medium);
    }

    #[test]
    fn test_cvss_v3_vector_critical() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Critical);
    }

    #[test]
    fn test_cvss_v3_vector_high() {
        // AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N ~ 8.1
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::High);
    }

    #[test]
    fn test_cvss_v3_vector_medium() {
        // AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N ~ 4.2-ish
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N".to_string(),
        }];
        let sev = map_cvss_to_severity(&severities);
        assert!(sev == Severity::Medium || sev == Severity::Low);
    }

    #[test]
    fn test_cvss_v3_vector_no_impact_is_zero() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N".to_string(),
        }];
        assert_eq!(map_cvss_to_severity(&severities), Severity::Low);
    }

    #[test]
    fn test_parse_cvss_score_plain_number() {
        assert_eq!(parse_cvss_score("9.8"), Some(9.8));
        assert_eq!(parse_cvss_score("0.0"), Some(0.0));
        assert_eq!(parse_cvss_score("5.5"), Some(5.5));
    }

    #[test]
    fn test_parse_cvss_score_invalid() {
        assert_eq!(parse_cvss_score("garbage"), None);
    }

    #[test]
    fn test_batch_response_deserialization() {
        let json = r#"{
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Test vulnerability",
                            "details": "Some details",
                            "aliases": ["CVE-2024-1234"],
                            "severity": [
                                {"type": "CVSS_V3", "score": "9.8"}
                            ]
                        }
                    ]
                },
                {
                    "vulns": []
                },
                {}
            ]
        }"#;

        let response: BatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.results.len(), 3);

        let vulns = response.results[0].vulns.as_ref().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(vulns[0].summary.as_deref(), Some("Test vulnerability"));
        assert_eq!(vulns[0].aliases, vec!["CVE-2024-1234"]);
        assert_eq!(vulns[0].severity.len(), 1);

        // Empty vulns array
        let vulns2 = response.results[1].vulns.as_ref().unwrap();
        assert!(vulns2.is_empty());

        // Missing vulns field
        assert!(response.results[2].vulns.is_none());
    }

    #[test]
    fn test_batch_response_minimal() {
        let json = r#"{
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2024-001"
                        }
                    ]
                }
            ]
        }"#;

        let response: BatchResponse = serde_json::from_str(json).unwrap();
        let vulns = response.results[0].vulns.as_ref().unwrap();
        assert_eq!(vulns[0].id, "PYSEC-2024-001");
        assert!(vulns[0].summary.is_none());
        assert!(vulns[0].aliases.is_empty());
        assert!(vulns[0].severity.is_empty());
    }
}
