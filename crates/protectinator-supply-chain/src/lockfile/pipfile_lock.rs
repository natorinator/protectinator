//! Pipfile.lock parser
//!
//! Parses Python Pipfile.lock (JSON format) into normalized package entries.

use crate::types::{Ecosystem, PackageEntry};
use serde_json::Value;

/// Parse a Pipfile.lock file content into package entries.
///
/// Reads both the `default` and `develop` sections. Strips the leading `==`
/// from version strings and extracts the first hash if available.
pub fn parse(content: &str) -> Vec<PackageEntry> {
    let root: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse Pipfile.lock: {}", e);
            return Vec::new();
        }
    };

    let mut entries = Vec::new();

    for section in &["default", "develop"] {
        if let Some(packages) = root.get(section).and_then(|s| s.as_object()) {
            for (name, value) in packages {
                if let Some(entry) = parse_pipfile_package(name, value) {
                    entries.push(entry);
                }
            }
        }
    }

    entries
}

/// Parse a single package entry from a Pipfile.lock section.
fn parse_pipfile_package(name: &str, value: &Value) -> Option<PackageEntry> {
    let version_raw = value.get("version").and_then(|v| v.as_str())?;

    // Strip leading == from version string
    let version = version_raw.strip_prefix("==").unwrap_or(version_raw);

    if version.is_empty() {
        tracing::warn!("Empty version for package: {}", name);
        return None;
    }

    // Extract the first hash if available
    let checksum = value
        .get("hashes")
        .and_then(|h| h.as_array())
        .and_then(|arr| arr.first())
        .and_then(|h| h.as_str())
        .map(String::from);

    // Extract index URL if specified
    let source_url = value
        .get("index")
        .and_then(|i| i.as_str())
        .map(String::from);

    Some(PackageEntry {
        name: name.to_lowercase().replace('-', "_"),
        version: version.to_string(),
        ecosystem: Ecosystem::PyPI,
        source_url,
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PIPFILE_LOCK: &str = r#"{
    "_meta": {
        "hash": { "sha256": "abc123" },
        "pipfile-spec": 6,
        "requires": { "python_version": "3.11" },
        "sources": [
            { "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true }
        ]
    },
    "default": {
        "requests": {
            "hashes": [
                "sha256:abcdef1234567890",
                "sha256:1234567890abcdef"
            ],
            "version": "==2.31.0"
        },
        "flask": {
            "hashes": [
                "sha256:flask_hash_here"
            ],
            "index": "pypi",
            "version": "==2.3.3"
        }
    },
    "develop": {
        "pytest": {
            "hashes": [
                "sha256:pytest_hash"
            ],
            "version": "==7.4.3"
        }
    }
}"#;

    #[test]
    fn test_parse_default_section() {
        let packages = parse(SAMPLE_PIPFILE_LOCK);

        let requests = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
        assert_eq!(requests.ecosystem, Ecosystem::PyPI);
        assert_eq!(
            requests.checksum.as_deref(),
            Some("sha256:abcdef1234567890")
        );

        let flask = packages.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.version, "2.3.3");
        assert_eq!(flask.source_url.as_deref(), Some("pypi"));
    }

    #[test]
    fn test_parse_develop_section() {
        let packages = parse(SAMPLE_PIPFILE_LOCK);

        let pytest = packages.iter().find(|p| p.name == "pytest").unwrap();
        assert_eq!(pytest.version, "7.4.3");
        assert_eq!(pytest.checksum.as_deref(), Some("sha256:pytest_hash"));
    }

    #[test]
    fn test_strips_version_prefix() {
        let packages = parse(SAMPLE_PIPFILE_LOCK);
        for pkg in &packages {
            assert!(
                !pkg.version.starts_with("=="),
                "version should not start with ==: {}",
                pkg.version
            );
        }
    }

    #[test]
    fn test_total_package_count() {
        let packages = parse(SAMPLE_PIPFILE_LOCK);
        assert_eq!(packages.len(), 3, "should have 2 default + 1 develop");
    }

    #[test]
    fn test_parse_malformed_json() {
        let packages = parse("{invalid json");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_missing_sections() {
        let content = r#"{ "_meta": {} }"#;
        let packages = parse(content);
        assert!(packages.is_empty());
    }
}
