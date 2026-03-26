//! uv.lock parser
//!
//! Parses Python uv lock files (TOML format) into normalized package entries.

use crate::types::{Ecosystem, PackageEntry};
use serde::Deserialize;

#[derive(Deserialize)]
struct UvLockFile {
    #[serde(default)]
    package: Vec<UvPackage>,
}

#[derive(Deserialize)]
struct UvPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<UvSource>,
}

#[derive(Deserialize)]
struct UvSource {
    registry: Option<String>,
    url: Option<String>,
    editable: Option<String>,
    #[serde(rename = "virtual")]
    virtual_field: Option<String>,
}

/// Normalize a Python package name: lowercase and replace `-` with `_`.
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Parse a uv.lock file content into package entries.
///
/// Filters out editable installs and virtual workspace members,
/// and maps remaining packages to `PackageEntry` with `Ecosystem::PyPI`.
pub fn parse(content: &str) -> Vec<PackageEntry> {
    let lock_file: UvLockFile = match toml::from_str(content) {
        Ok(lf) => lf,
        Err(e) => {
            tracing::warn!("Failed to parse uv.lock as TOML: {}", e);
            return Vec::new();
        }
    };

    lock_file
        .package
        .into_iter()
        .filter(|pkg| {
            // Skip editable installs and virtual workspace members
            if let Some(ref source) = pkg.source {
                if source.editable.is_some() || source.virtual_field.is_some() {
                    return false;
                }
            }
            true
        })
        .map(|pkg| {
            let source_url = pkg
                .source
                .and_then(|s| s.url.or(s.registry));
            PackageEntry {
                name: normalize_name(&pkg.name),
                version: pkg.version,
                ecosystem: Ecosystem::PyPI,
                source_url,
                checksum: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_UV_LOCK: &str = r#"
version = 1
requires-python = ">=3.12"

[[package]]
name = "my-project"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "Flask"
version = "3.0.2"

[[package]]
name = "my-editable"
version = "0.1.0"
source = { editable = "../my-editable" }
"#;

    #[test]
    fn test_parse_uv_lock() {
        let packages = parse(SAMPLE_UV_LOCK);
        assert_eq!(packages.len(), 2);

        let requests = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
        assert_eq!(requests.ecosystem, Ecosystem::PyPI);
        assert_eq!(
            requests.source_url.as_deref(),
            Some("https://pypi.org/simple")
        );

        let flask = packages.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.version, "3.0.2");
    }

    #[test]
    fn test_filters_virtual_and_editable() {
        let packages = parse(SAMPLE_UV_LOCK);
        assert!(
            packages.iter().all(|p| p.name != "my_project"),
            "virtual workspace members should be filtered out"
        );
        assert!(
            packages.iter().all(|p| p.name != "my_editable"),
            "editable installs should be filtered out"
        );
    }

    #[test]
    fn test_parse_malformed_toml() {
        let packages = parse("not valid toml {{{");
        assert!(packages.is_empty());
    }
}
