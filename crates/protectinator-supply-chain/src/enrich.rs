//! CVE intelligence enrichment for vulnerability findings
//!
//! Enriches OSV findings with Debian Security Tracker data to classify
//! actionability and provide specific remediation guidance.

use protectinator_advisory::{
    classify::{build_intelligence, enrich_finding},
    AdvisoryCache, DebianTracker,
};
use protectinator_core::Finding;
use tracing::{debug, info, warn};

/// Default cache staleness threshold in hours
const DEFAULT_CACHE_MAX_AGE_HOURS: u64 = 6;

/// Enrich a set of vulnerability findings with Debian tracker intelligence
///
/// This fetches/refreshes the Debian tracker cache if stale, then looks up
/// each finding's CVE(s) and adds actionability metadata.
///
/// Returns the number of findings that were enriched.
pub fn enrich_findings_with_debian_intel(findings: &mut [Finding], release: Option<&str>) -> usize {
    // Detect release if not specified
    let release = release
        .map(|s| s.to_string())
        .or_else(|| protectinator_advisory::debian::detect_debian_release());

    let release = match release {
        Some(r) => r,
        None => {
            debug!("Could not detect Debian release, skipping enrichment");
            return 0;
        }
    };

    // Open cache
    let mut cache = match AdvisoryCache::open_default() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to open advisory cache: {}, skipping enrichment", e);
            return 0;
        }
    };

    // Refresh cache if stale
    if cache.is_stale(DEFAULT_CACHE_MAX_AGE_HOURS) {
        info!("Debian advisory cache is stale, refreshing...");
        match refresh_cache(&mut cache, &release) {
            Ok(count) => info!("Refreshed Debian advisory cache with {} entries", count),
            Err(e) => {
                warn!("Failed to refresh advisory cache: {}, using stale data", e);
            }
        }
    }

    let mut enriched_count = 0;

    for finding in findings.iter_mut() {
        // Extract CVE IDs from metadata
        let cve_ids: Vec<String> = finding
            .metadata
            .get("cve_aliases")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if cve_ids.is_empty() {
            continue;
        }

        // Look up each CVE in the cache, use the first one with data
        for cve_id in &cve_ids {
            match cache.lookup_cve(cve_id) {
                Ok(entries) => {
                    // Use the first matching entry
                    if let Some((source_pkg, entry)) = entries.into_iter().next() {
                        let intel = build_intelligence(&entry, None, &source_pkg);
                        enrich_finding(finding, &intel);
                        enriched_count += 1;
                        break; // Use first matching CVE's data
                    }
                }
                Err(e) => {
                    debug!("Failed to look up CVE {}: {}", cve_id, e);
                }
            }
        }
    }

    enriched_count
}

/// Refresh the advisory cache from the Debian tracker
fn refresh_cache(cache: &mut AdvisoryCache, release: &str) -> Result<usize, String> {
    let tracker = DebianTracker::new();

    // Get Last-Modified from previous fetch for conditional request
    let last_modified = cache.get_metadata("last_modified");

    // Fetch with conditional request
    let result = tracker
        .fetch_all(last_modified.as_deref())
        .map_err(|e| format!("Fetch failed: {}", e))?;

    let fetch_result = match result {
        Some(r) => r,
        None => {
            // 304 Not Modified — cache is still valid, reset staleness
            cache
                .set_metadata("last_checked", &chrono::Utc::now().to_rfc3339())
                .map_err(|e| format!("Failed to update metadata: {}", e))?;
            return Ok(0); // No new data
        }
    };

    let entries = DebianTracker::parse_for_release(&fetch_result.data, release);
    let count = entries.len();

    cache
        .clear()
        .map_err(|e| format!("Cache clear failed: {}", e))?;
    cache
        .store_entries(release, &entries)
        .map_err(|e| format!("Cache store failed: {}", e))?;

    // Store Last-Modified for future conditional requests
    if let Some(ref lm) = fetch_result.last_modified {
        cache
            .set_metadata("last_modified", lm)
            .map_err(|e| format!("Failed to store Last-Modified: {}", e))?;
    }

    Ok(count)
}

/// Filter findings to only actionable ones (PatchableNow)
pub fn filter_actionable(findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| {
            // If no actionability metadata, keep it (non-vulnerability findings)
            let Some(action) = f.metadata.get("actionability") else {
                return true;
            };

            // Keep PatchableNow findings
            action
                .get("class")
                .and_then(|v| v.as_str())
                .map(|c| c == "patchable_now")
                .unwrap_or(true) // Keep if we can't parse
        })
        .collect()
}

/// Generate an actionability summary from enriched findings
pub fn actionability_summary(findings: &[Finding]) -> ActionabilitySummary {
    let mut summary = ActionabilitySummary::default();

    for finding in findings {
        if let Some(action) = finding.metadata.get("actionability") {
            match action.get("class").and_then(|v| v.as_str()) {
                Some("patchable_now") => summary.patchable_now += 1,
                Some("waiting_on_upstream") => summary.waiting_on_upstream += 1,
                Some("accepted_risk") => summary.accepted_risk += 1,
                Some("disputed") => summary.disputed += 1,
                Some("unknown") | None => summary.unknown += 1,
                _ => summary.unknown += 1,
            }
        } else {
            summary.not_enriched += 1;
        }
    }

    summary
}

/// Summary of finding actionability breakdown
#[derive(Debug, Default)]
pub struct ActionabilitySummary {
    pub patchable_now: usize,
    pub waiting_on_upstream: usize,
    pub accepted_risk: usize,
    pub disputed: usize,
    pub unknown: usize,
    pub not_enriched: usize,
}

impl std::fmt::Display for ActionabilitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  Patchable now:        {:>3}", self.patchable_now)?;
        writeln!(
            f,
            "  Waiting on upstream:  {:>3}",
            self.waiting_on_upstream
        )?;
        writeln!(f, "  Accepted risk:        {:>3}", self.accepted_risk)?;
        if self.disputed > 0 {
            writeln!(f, "  Disputed:             {:>3}", self.disputed)?;
        }
        if self.unknown > 0 {
            writeln!(f, "  Unknown:              {:>3}", self.unknown)?;
        }
        Ok(())
    }
}
