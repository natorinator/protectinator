//! package-lock.json parser
//!
//! Parses npm's package-lock.json (v2/v3 format) into normalized package entries.

use crate::types::{Ecosystem, PackageEntry};
use serde_json::Value;

/// Parse a package-lock.json file content into package entries.
///
/// Supports both v3 (`packages` key with `node_modules/` prefixed keys)
/// and v2 (`dependencies` key with bare package names).
pub fn parse(content: &str) -> Vec<PackageEntry> {
    let root: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse package-lock.json: {}", e);
            return Vec::new();
        }
    };

    // Try v3 format first (packages key)
    if let Some(packages) = root.get("packages").and_then(|p| p.as_object()) {
        return parse_v3_packages(packages);
    }

    // Fall back to v2 format (dependencies key)
    if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
        return parse_v2_dependencies(deps);
    }

    tracing::warn!("package-lock.json has neither 'packages' nor 'dependencies' key");
    Vec::new()
}

/// Parse v3 `packages` map where keys are like `node_modules/@scope/name`
fn parse_v3_packages(packages: &serde_json::Map<String, Value>) -> Vec<PackageEntry> {
    let mut entries = Vec::new();

    for (key, value) in packages {
        // Skip the root entry (empty string key)
        if key.is_empty() {
            continue;
        }

        let name = extract_package_name_from_path(key);
        if name.is_empty() {
            tracing::warn!("Could not extract package name from key: {}", key);
            continue;
        }

        let version = match value.get("version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => {
                tracing::warn!("Missing version for package: {}", name);
                continue;
            }
        };

        let source_url = value
            .get("resolved")
            .and_then(|v| v.as_str())
            .map(String::from);

        let checksum = value
            .get("integrity")
            .and_then(|v| v.as_str())
            .map(String::from);

        entries.push(PackageEntry {
            name,
            version,
            ecosystem: Ecosystem::Npm,
            source_url,
            checksum,
        });
    }

    entries
}

/// Parse v2 `dependencies` map where keys are bare package names
fn parse_v2_dependencies(deps: &serde_json::Map<String, Value>) -> Vec<PackageEntry> {
    let mut entries = Vec::new();

    for (name, value) in deps {
        let version = match value.get("version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => {
                tracing::warn!("Missing version for package: {}", name);
                continue;
            }
        };

        let source_url = value
            .get("resolved")
            .and_then(|v| v.as_str())
            .map(String::from);

        let checksum = value
            .get("integrity")
            .and_then(|v| v.as_str())
            .map(String::from);

        entries.push(PackageEntry {
            name: name.clone(),
            version,
            ecosystem: Ecosystem::Npm,
            source_url,
            checksum,
        });
    }

    entries
}

/// Extract the package name from a node_modules path.
///
/// Handles both regular packages (`node_modules/foo`) and scoped packages
/// (`node_modules/@scope/name`), as well as nested dependencies
/// (`node_modules/foo/node_modules/bar`).
fn extract_package_name_from_path(path: &str) -> String {
    // Find the last node_modules/ segment to handle nested deps
    let after_nm = match path.rfind("node_modules/") {
        Some(idx) => &path[idx + "node_modules/".len()..],
        None => path,
    };

    // Handle scoped packages: @scope/name
    if after_nm.starts_with('@') {
        // Take up to the second path component: @scope/name
        let parts: Vec<&str> = after_nm.splitn(3, '/').collect();
        if parts.len() >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else {
            after_nm.to_string()
        }
    } else {
        // Regular package: take just the first path component
        after_nm
            .split('/')
            .next()
            .unwrap_or(after_nm)
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_V3: &str = r#"{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-abc123"
    },
    "node_modules/@types/node": {
      "version": "20.11.5",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-20.11.5.tgz",
      "integrity": "sha512-def456"
    },
    "node_modules/express/node_modules/debug": {
      "version": "2.6.9",
      "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"
    }
  }
}"#;

    const SAMPLE_V2: &str = r#"{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDE"
    },
    "@babel/core": {
      "version": "7.23.7",
      "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.23.7.tgz"
    }
  }
}"#;

    #[test]
    fn test_parse_v3_packages() {
        let packages = parse(SAMPLE_V3);
        assert_eq!(packages.len(), 3);

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
        assert_eq!(express.ecosystem, Ecosystem::Npm);
        assert!(express.source_url.is_some());
        assert_eq!(express.checksum.as_deref(), Some("sha512-abc123"));

        let types_node = packages.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types_node.version, "20.11.5");

        // Nested dependency
        let debug = packages.iter().find(|p| p.name == "debug").unwrap();
        assert_eq!(debug.version, "2.6.9");
    }

    #[test]
    fn test_parse_v2_dependencies() {
        let packages = parse(SAMPLE_V2);
        assert_eq!(packages.len(), 2);

        let lodash = packages.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
        assert_eq!(lodash.ecosystem, Ecosystem::Npm);

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.23.7");
    }

    #[test]
    fn test_skips_root_entry() {
        let packages = parse(SAMPLE_V3);
        assert!(
            !packages.iter().any(|p| p.name == "my-app"),
            "root entry should be skipped"
        );
    }

    #[test]
    fn test_parse_malformed_json() {
        let packages = parse("not json at all");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_extract_scoped_package_name() {
        assert_eq!(
            extract_package_name_from_path("node_modules/@types/node"),
            "@types/node"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/@babel/core"),
            "@babel/core"
        );
        assert_eq!(
            extract_package_name_from_path("node_modules/express"),
            "express"
        );
    }
}
