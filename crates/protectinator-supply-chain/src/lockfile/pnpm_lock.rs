//! pnpm-lock.yaml parser
//!
//! Parses pnpm lock files (YAML format, v6+ and v9+) into normalized package entries.

use crate::types::{Ecosystem, PackageEntry};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PnpmLockFile {
    #[serde(default)]
    packages: HashMap<String, PnpmPackageEntry>,
}

#[derive(Deserialize)]
struct PnpmPackageEntry {
    #[serde(default)]
    resolution: Option<PnpmResolution>,
}

#[derive(Deserialize)]
struct PnpmResolution {
    integrity: Option<String>,
}

/// Parse a pnpm-lock.yaml file content into package entries.
///
/// Handles both v6 format (`/name@version` keys) and v9+ format (`name@version` keys).
/// Scoped packages appear as `/@scope/name@version` or `@scope/name@version`.
pub fn parse(content: &str) -> Vec<PackageEntry> {
    let lock_file: PnpmLockFile = match serde_yaml::from_str(content) {
        Ok(lf) => lf,
        Err(e) => {
            tracing::warn!("Failed to parse pnpm-lock.yaml as YAML: {}", e);
            return Vec::new();
        }
    };

    let mut packages = Vec::new();

    for (key, entry) in &lock_file.packages {
        match parse_package_key(key) {
            Some((name, version)) => {
                let checksum = entry
                    .resolution
                    .as_ref()
                    .and_then(|r| r.integrity.clone());

                packages.push(PackageEntry {
                    name,
                    version,
                    ecosystem: Ecosystem::Npm,
                    source_url: None,
                    checksum,
                });
            }
            None => {
                tracing::warn!("Could not parse pnpm package key: {}", key);
            }
        }
    }

    // Sort for deterministic output
    packages.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    packages
}

/// Parse a pnpm package key into (name, version).
///
/// Handles formats:
/// - `/package@1.0.0` (v6)
/// - `package@1.0.0` (v9)
/// - `/@scope/package@1.0.0` (v6, scoped)
/// - `@scope/package@1.0.0` (v9, scoped)
fn parse_package_key(key: &str) -> Option<(String, String)> {
    // Strip leading `/` if present (v6 format)
    let key = key.strip_prefix('/').unwrap_or(key);

    if key.is_empty() {
        return None;
    }

    // For scoped packages, the first `@` is part of the scope.
    // We need to find the last `@` that separates name from version.
    let search_start = if key.starts_with('@') { 1 } else { 0 };
    let rest = &key[search_start..];

    match rest.rfind('@') {
        Some(pos) => {
            let at_pos = search_start + pos;
            let name = &key[..at_pos];
            let version = &key[at_pos + 1..];

            if name.is_empty() || version.is_empty() {
                return None;
            }

            Some((name.to_string(), version.to_string()))
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pnpm_lock_v6() {
        let content = r#"
lockfileVersion: '6.0'

packages:
  /express@4.18.2:
    resolution: {integrity: sha512-abc123==}
    dependencies:
      accepts: 1.3.8

  /accepts@1.3.8:
    resolution: {integrity: sha512-def456==}

  /@babel/core@7.24.0:
    resolution: {integrity: sha512-ghi789==}
"#;
        let packages = parse(content);
        assert_eq!(packages.len(), 3);

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
        assert_eq!(express.ecosystem, Ecosystem::Npm);
        assert_eq!(express.checksum.as_deref(), Some("sha512-abc123=="));

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.24.0");
    }

    #[test]
    fn test_parse_pnpm_lock_v9() {
        let content = r#"
lockfileVersion: '9.0'

packages:
  express@4.18.2:
    resolution: {integrity: sha512-abc123==}

  "@babel/core@7.24.0":
    resolution: {integrity: sha512-ghi789==}

  lodash@4.17.21:
    resolution: {}
"#;
        let packages = parse(content);
        assert_eq!(packages.len(), 3);

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.24.0");

        let lodash = packages.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
        assert!(lodash.checksum.is_none());
    }

    #[test]
    fn test_parse_empty_pnpm_lock() {
        let content = r#"
lockfileVersion: '6.0'

packages: {}
"#;
        let packages = parse(content);
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_malformed_yaml() {
        let packages = parse(": : : [invalid yaml");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_package_key_formats() {
        assert_eq!(
            parse_package_key("/express@4.18.2"),
            Some(("express".to_string(), "4.18.2".to_string()))
        );
        assert_eq!(
            parse_package_key("express@4.18.2"),
            Some(("express".to_string(), "4.18.2".to_string()))
        );
        assert_eq!(
            parse_package_key("/@scope/pkg@1.0.0"),
            Some(("@scope/pkg".to_string(), "1.0.0".to_string()))
        );
        assert_eq!(
            parse_package_key("@scope/pkg@1.0.0"),
            Some(("@scope/pkg".to_string(), "1.0.0".to_string()))
        );
    }
}
