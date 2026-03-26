//! poetry.lock parser
//!
//! Parses Python Poetry lock files (TOML format) into normalized package entries.

use crate::types::{Ecosystem, PackageEntry};
use serde::Deserialize;

#[derive(Deserialize)]
struct PoetryLockFile {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<PoetrySource>,
}

#[derive(Deserialize)]
struct PoetrySource {
    #[serde(rename = "type")]
    source_type: Option<String>,
    url: Option<String>,
}

/// Normalize a Python package name: lowercase and replace `-` with `_`.
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Parse a poetry.lock file content into package entries.
///
/// Filters out local dependencies (source type "directory" or "file")
/// and maps remaining packages to `PackageEntry` with `Ecosystem::PyPI`.
pub fn parse(content: &str) -> Vec<PackageEntry> {
    let lock_file: PoetryLockFile = match toml::from_str(content) {
        Ok(lf) => lf,
        Err(e) => {
            tracing::warn!("Failed to parse poetry.lock as TOML: {}", e);
            return Vec::new();
        }
    };

    lock_file
        .package
        .into_iter()
        .filter(|pkg| {
            // Skip local dependencies (directory or file source types)
            if let Some(ref source) = pkg.source {
                if let Some(ref source_type) = source.source_type {
                    return source_type != "directory" && source_type != "file";
                }
            }
            true
        })
        .map(|pkg| {
            let source_url = pkg.source.and_then(|s| s.url);
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

    const SAMPLE_POETRY_LOCK: &str = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"

[[package]]
name = "Flask"
version = "3.0.2"
description = "A simple framework for building complex web applications."
optional = false
python-versions = ">=3.8"

[package.source]
type = "legacy"
url = "https://pypi.org/simple"

[[package]]
name = "my-local-package"
version = "0.1.0"
description = "A local package"
optional = false
python-versions = ">=3.10"

[package.source]
type = "directory"
url = "../my-local-package"

[[package]]
name = "another-local"
version = "0.2.0"
description = "Another local"
optional = false
python-versions = ">=3.10"

[package.source]
type = "file"
url = "./dist/another-local-0.2.0.tar.gz"
"#;

    #[test]
    fn test_parse_poetry_lock() {
        let packages = parse(SAMPLE_POETRY_LOCK);
        assert_eq!(packages.len(), 2);

        let requests = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
        assert_eq!(requests.ecosystem, Ecosystem::PyPI);
        assert!(requests.source_url.is_none());

        let flask = packages.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.version, "3.0.2");
        assert_eq!(
            flask.source_url.as_deref(),
            Some("https://pypi.org/simple")
        );
    }

    #[test]
    fn test_filters_local_dependencies() {
        let packages = parse(SAMPLE_POETRY_LOCK);
        assert!(
            packages.iter().all(|p| p.name != "my_local_package"),
            "directory source types should be filtered out"
        );
        assert!(
            packages.iter().all(|p| p.name != "another_local"),
            "file source types should be filtered out"
        );
    }

    #[test]
    fn test_normalizes_package_names() {
        let packages = parse(SAMPLE_POETRY_LOCK);
        // "Flask" should become "flask", dashes become underscores
        assert!(packages.iter().any(|p| p.name == "flask"));
        assert!(packages.iter().all(|p| p.name == p.name.to_lowercase()));
    }

    #[test]
    fn test_parse_malformed_toml() {
        let packages = parse("this is not valid toml {{{");
        assert!(packages.is_empty());
    }
}
