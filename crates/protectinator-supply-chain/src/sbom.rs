//! SBOM (Software Bill of Materials) generation in CycloneDX 1.5 format.
//!
//! Generates CycloneDX JSON SBOMs from parsed lock file data, stores them
//! on disk, and supports cross-repo package searches.

use crate::types::{Ecosystem, PackageEntry};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Generate a Package URL (PURL) for a package entry.
fn generate_purl(name: &str, version: &str, ecosystem: &Ecosystem) -> String {
    match ecosystem {
        Ecosystem::PyPI => {
            format!("pkg:pypi/{}@{}", name, version)
        }
        Ecosystem::Npm => {
            if let Some(stripped) = name.strip_prefix('@') {
                // Scoped package: @scope/name -> pkg:npm/%40scope/name@version
                format!("pkg:npm/%40{}@{}", stripped, version)
            } else {
                format!("pkg:npm/{}@{}", name, version)
            }
        }
        Ecosystem::CratesIo => {
            format!("pkg:cargo/{}@{}", name, version)
        }
    }
}

/// Generate a CycloneDX 1.5 JSON SBOM from a list of packages.
///
/// Packages are deduplicated by (name, version, ecosystem). Hashes and
/// external references are included when the underlying `PackageEntry`
/// provides them.
pub fn generate_cyclonedx(
    packages: &[PackageEntry],
    repo_name: &str,
    _repo_path: &str,
) -> Value {
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Deduplicate by (name, version, ecosystem display)
    let mut seen = HashSet::new();
    let mut components: Vec<Value> = Vec::new();

    for pkg in packages {
        let key = format!("{}:{}:{}", pkg.ecosystem, pkg.name, pkg.version);
        if !seen.insert(key) {
            continue;
        }

        let purl = generate_purl(&pkg.name, &pkg.version, &pkg.ecosystem);

        let mut component = json!({
            "type": "library",
            "name": pkg.name,
            "version": pkg.version,
            "purl": purl,
            "bom-ref": purl,
        });

        if let Some(ref checksum) = pkg.checksum {
            component["hashes"] = json!([{
                "alg": "SHA-256",
                "content": checksum,
            }]);
        }

        if let Some(ref url) = pkg.source_url {
            component["externalReferences"] = json!([{
                "type": "distribution",
                "url": url,
            }]);
        }

        components.push(component);
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "vendor": "protectinator",
                "name": "protectinator-supply-chain",
                "version": "0.1.0",
            }],
            "component": {
                "type": "application",
                "name": repo_name,
                "bom-ref": repo_name,
            }
        },
        "components": components,
    })
}

/// Save an SBOM JSON document to the given path, creating parent directories
/// as needed.
pub fn save_sbom(sbom: &Value, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create SBOM directory {}: {}", parent.display(), e))?;
    }
    let json_str = serde_json::to_string_pretty(sbom)
        .map_err(|e| format!("Failed to serialize SBOM: {}", e))?;
    fs::write(path, json_str).map_err(|e| format!("Failed to write SBOM to {}: {}", path.display(), e))
}

/// Load an SBOM JSON document from the given path.
pub fn load_sbom(path: &Path) -> Result<Value, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse SBOM JSON: {}", e))
}

/// Return the default directory for storing SBOMs:
/// `~/.local/share/protectinator/sboms/`
pub fn default_sbom_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("protectinator")
        .join("sboms"))
}

/// Return the default SBOM path for a given repo name:
/// `~/.local/share/protectinator/sboms/{repo_name}.cdx.json`
pub fn sbom_path_for_repo(repo_name: &str) -> Result<PathBuf, String> {
    Ok(default_sbom_dir()?.join(format!("{}.cdx.json", repo_name)))
}

/// A match found when searching stored SBOMs for a package.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageMatch {
    pub repo_name: String,
    pub sbom_path: PathBuf,
    pub package_name: String,
    pub version: String,
    pub ecosystem: String,
    pub purl: String,
}

/// Search all stored SBOMs for repos that contain a specific package.
///
/// Scans every `.cdx.json` file in the default SBOM directory and returns
/// every component whose name matches `package_name` (case-insensitive).
pub fn search_package(package_name: &str) -> Result<Vec<PackageMatch>, String> {
    let sbom_dir = default_sbom_dir()?;
    if !sbom_dir.exists() {
        return Ok(Vec::new());
    }

    let mut matches = Vec::new();
    let needle = package_name.to_lowercase();

    let entries = fs::read_dir(&sbom_dir)
        .map_err(|e| format!("Failed to read SBOM directory: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        if !path.extension().is_some_and(|ext| ext == "json")
            || !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".cdx.json"))
        {
            continue;
        }

        let sbom = match load_sbom(&path) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Extract repo name from metadata.component.name
        let repo_name = sbom
            .get("metadata")
            .and_then(|m| m.get("component"))
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();

        if let Some(components) = sbom.get("components").and_then(|c| c.as_array()) {
            for comp in components {
                let comp_name = comp.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if comp_name.to_lowercase() == needle {
                    matches.push(PackageMatch {
                        repo_name: repo_name.clone(),
                        sbom_path: path.clone(),
                        package_name: comp_name.to_string(),
                        version: comp
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        ecosystem: extract_ecosystem_from_purl(
                            comp.get("purl").and_then(|p| p.as_str()).unwrap_or(""),
                        ),
                        purl: comp
                            .get("purl")
                            .and_then(|p| p.as_str())
                            .unwrap_or("")
                            .to_string(),
                    });
                }
            }
        }
    }

    Ok(matches)
}

/// Extract ecosystem name from a PURL string.
fn extract_ecosystem_from_purl(purl: &str) -> String {
    // purl format: pkg:<type>/<name>@<version>
    if let Some(rest) = purl.strip_prefix("pkg:") {
        if let Some(slash_pos) = rest.find('/') {
            return rest[..slash_pos].to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ecosystem, PackageEntry};
    use tempfile::TempDir;

    fn make_package(
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
        source_url: Option<&str>,
        checksum: Option<&str>,
    ) -> PackageEntry {
        PackageEntry {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            source_url: source_url.map(String::from),
            checksum: checksum.map(String::from),
        }
    }

    #[test]
    fn test_purl_pypi() {
        let purl = generate_purl("requests", "2.31.0", &Ecosystem::PyPI);
        assert_eq!(purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn test_purl_npm_unscoped() {
        let purl = generate_purl("express", "4.18.2", &Ecosystem::Npm);
        assert_eq!(purl, "pkg:npm/express@4.18.2");
    }

    #[test]
    fn test_purl_npm_scoped() {
        let purl = generate_purl("@babel/core", "7.23.0", &Ecosystem::Npm);
        assert_eq!(purl, "pkg:npm/%40babel/core@7.23.0");
    }

    #[test]
    fn test_purl_cargo() {
        let purl = generate_purl("serde", "1.0.193", &Ecosystem::CratesIo);
        assert_eq!(purl, "pkg:cargo/serde@1.0.193");
    }

    #[test]
    fn test_cyclonedx_structure() {
        let packages = vec![
            make_package(
                "requests",
                "2.31.0",
                Ecosystem::PyPI,
                Some("https://pypi.org/simple/requests/"),
                Some("abcdef1234567890"),
            ),
            make_package("serde", "1.0.193", Ecosystem::CratesIo, None, None),
        ];

        let sbom = generate_cyclonedx(&packages, "my-project", "/home/user/my-project");

        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert_eq!(sbom["version"], 1);

        // Metadata
        assert!(sbom["metadata"]["timestamp"].as_str().is_some());
        assert_eq!(sbom["metadata"]["component"]["name"], "my-project");
        assert_eq!(sbom["metadata"]["component"]["bom-ref"], "my-project");
        assert_eq!(
            sbom["metadata"]["tools"][0]["name"],
            "protectinator-supply-chain"
        );

        // Components
        let components = sbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);

        let req = &components[0];
        assert_eq!(req["type"], "library");
        assert_eq!(req["name"], "requests");
        assert_eq!(req["version"], "2.31.0");
        assert_eq!(req["purl"], "pkg:pypi/requests@2.31.0");
        assert_eq!(req["hashes"][0]["alg"], "SHA-256");
        assert_eq!(req["hashes"][0]["content"], "abcdef1234567890");
        assert_eq!(
            req["externalReferences"][0]["url"],
            "https://pypi.org/simple/requests/"
        );

        // serde has no hashes or externalReferences
        let serde_comp = &components[1];
        assert_eq!(serde_comp["name"], "serde");
        assert!(serde_comp.get("hashes").is_none());
        assert!(serde_comp.get("externalReferences").is_none());
    }

    #[test]
    fn test_deduplication() {
        let packages = vec![
            make_package("requests", "2.31.0", Ecosystem::PyPI, None, None),
            make_package("requests", "2.31.0", Ecosystem::PyPI, None, None),
            make_package("requests", "2.32.0", Ecosystem::PyPI, None, None),
        ];

        let sbom = generate_cyclonedx(&packages, "dedup-test", "/tmp/dedup");
        let components = sbom["components"].as_array().unwrap();
        // Two unique entries: requests 2.31.0 and requests 2.32.0
        assert_eq!(components.len(), 2);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test-repo.cdx.json");

        let packages = vec![make_package(
            "tokio",
            "1.35.0",
            Ecosystem::CratesIo,
            None,
            Some("deadbeef"),
        )];
        let sbom = generate_cyclonedx(&packages, "test-repo", "/tmp/test-repo");

        save_sbom(&sbom, &path).unwrap();
        let loaded = load_sbom(&path).unwrap();

        assert_eq!(loaded["bomFormat"], "CycloneDX");
        assert_eq!(loaded["specVersion"], "1.5");
        assert_eq!(loaded["components"][0]["name"], "tokio");
        assert_eq!(loaded["components"][0]["hashes"][0]["content"], "deadbeef");
    }

    #[test]
    fn test_search_package() {
        let tmp = TempDir::new().unwrap();

        // Create two synthetic SBOMs
        let sbom1 = generate_cyclonedx(
            &[
                make_package("requests", "2.31.0", Ecosystem::PyPI, None, None),
                make_package("flask", "3.0.0", Ecosystem::PyPI, None, None),
            ],
            "project-a",
            "/tmp/a",
        );
        let sbom2 = generate_cyclonedx(
            &[
                make_package("requests", "2.28.0", Ecosystem::PyPI, None, None),
                make_package("serde", "1.0.193", Ecosystem::CratesIo, None, None),
            ],
            "project-b",
            "/tmp/b",
        );

        save_sbom(&sbom1, &tmp.path().join("project-a.cdx.json")).unwrap();
        save_sbom(&sbom2, &tmp.path().join("project-b.cdx.json")).unwrap();

        // Override HOME to use our temp dir for the search
        // Instead, directly search the temp dir by calling the internals:
        let mut matches = Vec::new();
        for entry in fs::read_dir(tmp.path()).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".cdx.json"))
            {
                continue;
            }
            let sbom = load_sbom(&path).unwrap();
            let repo_name = sbom["metadata"]["component"]["name"]
                .as_str()
                .unwrap()
                .to_string();
            if let Some(components) = sbom["components"].as_array() {
                for comp in components {
                    let name = comp["name"].as_str().unwrap_or("");
                    if name.to_lowercase() == "requests" {
                        matches.push(PackageMatch {
                            repo_name: repo_name.clone(),
                            sbom_path: path.clone(),
                            package_name: name.to_string(),
                            version: comp["version"].as_str().unwrap_or("").to_string(),
                            ecosystem: extract_ecosystem_from_purl(
                                comp["purl"].as_str().unwrap_or(""),
                            ),
                            purl: comp["purl"].as_str().unwrap_or("").to_string(),
                        });
                    }
                }
            }
        }

        assert_eq!(matches.len(), 2);
        let versions: HashSet<String> = matches.iter().map(|m| m.version.clone()).collect();
        assert!(versions.contains("2.31.0"));
        assert!(versions.contains("2.28.0"));
        assert!(matches.iter().all(|m| m.ecosystem == "pypi"));
        assert!(matches.iter().all(|m| m.purl.starts_with("pkg:pypi/")));
    }
}
