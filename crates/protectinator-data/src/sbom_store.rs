//! Read-only access to SBOM (CycloneDX) JSON files

use crate::types::SbomPackage;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Read-only SBOM store
pub struct SbomStore {
    sbom_dir: PathBuf,
}

impl SbomStore {
    /// Create a new SBOM store pointing at the SBOMs directory
    pub fn new(sbom_dir: &Path) -> Self {
        Self {
            sbom_dir: sbom_dir.to_path_buf(),
        }
    }

    /// Count of SBOM files
    pub fn count(&self) -> usize {
        self.list_sboms().len()
    }

    /// List all SBOM files
    pub fn list_sboms(&self) -> Vec<PathBuf> {
        let pattern = self.sbom_dir.join("*.cdx.json");
        glob::glob(pattern.to_str().unwrap_or(""))
            .ok()
            .map(|paths| paths.filter_map(|p| p.ok()).collect())
            .unwrap_or_default()
    }

    /// List SBOM names (repo names extracted from filenames)
    pub fn list_names(&self) -> Vec<String> {
        self.list_sboms()
            .iter()
            .filter_map(|p| {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.trim_end_matches(".cdx").to_string())
            })
            .collect()
    }

    /// Search for a package across all SBOMs
    pub fn search_package(&self, query: &str) -> Vec<SbomPackage> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for sbom_path in self.list_sboms() {
            let sbom_name = sbom_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.trim_end_matches(".cdx").to_string())
                .unwrap_or_default();

            let content = match std::fs::read_to_string(&sbom_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let json: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if let Some(components) = json.get("components").and_then(|c| c.as_array()) {
                for component in components {
                    let name = component
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    let version = component
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let purl = component
                        .get("purl")
                        .and_then(|p| p.as_str())
                        .map(String::from);

                    if name.to_lowercase().contains(&query_lower)
                        || purl
                            .as_deref()
                            .map(|p| p.to_lowercase().contains(&query_lower))
                            .unwrap_or(false)
                    {
                        results.push(SbomPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            purl,
                            sbom_name: sbom_name.clone(),
                            sbom_path: sbom_path.display().to_string(),
                        });
                    }
                }
            }
        }

        debug!("SBOM search for '{}': {} matches", query, results.len());
        results
    }

    /// Get full SBOM content as parsed JSON
    pub fn get_sbom(&self, name: &str) -> Result<serde_json::Value, String> {
        let path = self.sbom_dir.join(format!("{}.cdx.json", name));
        if !path.exists() {
            return Err(format!("SBOM not found: {}", name));
        }
        let content =
            std::fs::read_to_string(&path).map_err(|e| format!("Failed to read SBOM: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse SBOM: {}", e))
    }
}
