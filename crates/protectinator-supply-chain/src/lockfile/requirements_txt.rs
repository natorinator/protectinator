//! requirements.txt parser
//!
//! Parses Python requirements.txt files with pinned versions into package entries.

use crate::types::{Ecosystem, PackageEntry};

/// Parse a requirements.txt file content into package entries.
///
/// Recognizes lines in these forms:
/// - `package==version`
/// - `package==version ; python_version >= "3.8"`
/// - `package==version --hash=sha256:abcdef...`
///
/// Skips comments, blank lines, `-r` includes, `-e` editable installs,
/// `--index-url` directives, and any unpinned dependencies.
pub fn parse(content: &str) -> Vec<PackageEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip directives
        if line.starts_with("-r ")
            || line.starts_with("-c ")
            || line.starts_with("-e ")
            || line.starts_with("--index-url")
            || line.starts_with("--extra-index-url")
            || line.starts_with("--find-links")
            || line.starts_with("--trusted-host")
            || line.starts_with("--no-binary")
            || line.starts_with("--only-binary")
        {
            continue;
        }

        if let Some(entry) = parse_requirement_line(line) {
            entries.push(entry);
        }
    }

    entries
}

/// Parse a single requirements line into a PackageEntry, if it contains a pinned version.
fn parse_requirement_line(line: &str) -> Option<PackageEntry> {
    // Strip inline comments (but be careful: # in URLs is valid, so only strip
    // if preceded by whitespace)
    let line = if let Some(idx) = line.find(" #") {
        line[..idx].trim()
    } else {
        line
    };

    // Extract hashes: --hash=algorithm:value
    let (line, checksum) = extract_hash(line);

    // Strip environment markers: everything after ` ; `
    let line = if let Some(idx) = line.find(" ;") {
        line[..idx].trim()
    } else {
        line.trim()
    };

    // We only handle pinned versions with ==
    let (name, version) = line.split_once("==")?;

    let name = name.trim();
    let version = version.trim();

    if name.is_empty() || version.is_empty() {
        return None;
    }

    // Normalize package name: lowercase and replace hyphens with underscores
    let normalized_name = normalize_package_name(name);

    Some(PackageEntry {
        name: normalized_name,
        version: version.to_string(),
        ecosystem: Ecosystem::PyPI,
        source_url: None,
        checksum,
    })
}

/// Extract `--hash=sha256:...` from a line, returning the remaining line and the hash.
fn extract_hash(line: &str) -> (&str, Option<String>) {
    if let Some(idx) = line.find("--hash=") {
        let before = line[..idx].trim();
        let hash_part = &line[idx + "--hash=".len()..];
        // Take up to the next whitespace (there could be multiple --hash= entries)
        let hash_value = hash_part
            .split_whitespace()
            .next()
            .unwrap_or(hash_part)
            .to_string();
        (before, Some(hash_value))
    } else {
        (line, None)
    }
}

/// Normalize a Python package name: lowercase and replace hyphens with underscores.
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_REQUIREMENTS: &str = r#"
# This is a comment
Flask==2.3.3
requests==2.31.0
Django==4.2.7 ; python_version >= "3.8"
numpy==1.26.2 --hash=sha256:abcdef1234567890

-r base-requirements.txt
-e git+https://github.com/user/repo.git#egg=mypackage
--index-url https://pypi.org/simple/

Pillow==10.1.0
"#;

    #[test]
    fn test_parse_requirements_txt() {
        let packages = parse(SAMPLE_REQUIREMENTS);
        assert_eq!(packages.len(), 5);

        let flask = packages.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.version, "2.3.3");
        assert_eq!(flask.ecosystem, Ecosystem::PyPI);

        let requests = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
    }

    #[test]
    fn test_strips_environment_markers() {
        let packages = parse(SAMPLE_REQUIREMENTS);
        let django = packages.iter().find(|p| p.name == "django").unwrap();
        assert_eq!(django.version, "4.2.7");
    }

    #[test]
    fn test_extracts_hash() {
        let packages = parse(SAMPLE_REQUIREMENTS);
        let numpy = packages.iter().find(|p| p.name == "numpy").unwrap();
        assert_eq!(numpy.version, "1.26.2");
        assert_eq!(
            numpy.checksum.as_deref(),
            Some("sha256:abcdef1234567890")
        );
    }

    #[test]
    fn test_normalizes_package_names() {
        let content = "My-Package==1.0.0\nAnother_Package==2.0.0\n";
        let packages = parse(content);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "my_package");
        assert_eq!(packages[1].name, "another_package");
    }

    #[test]
    fn test_skips_directives() {
        let packages = parse(SAMPLE_REQUIREMENTS);
        assert!(
            !packages.iter().any(|p| p.name.contains("mypackage")),
            "editable installs should be skipped"
        );
    }

    #[test]
    fn test_skips_unpinned() {
        let content = "requests>=2.0\nflask\nnumpy~=1.26\n";
        let packages = parse(content);
        assert!(packages.is_empty(), "unpinned dependencies should be skipped");
    }

    #[test]
    fn test_parse_empty() {
        let packages = parse("");
        assert!(packages.is_empty());
    }
}
