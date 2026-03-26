//! Package registry configuration audit
//!
//! Checks package manager registry configurations for non-standard or
//! potentially malicious settings across npm, pip, and Cargo ecosystems.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};

/// Standard npm registry URL
const NPM_STANDARD_REGISTRY: &str = "https://registry.npmjs.org/";

/// Standard PyPI index URL
const PYPI_STANDARD_INDEX: &str = "https://pypi.org/simple/";

/// Checks package manager registry configurations for security issues
pub struct RegistryAuditCheck;

impl SupplyChainCheck for RegistryAuditCheck {
    fn id(&self) -> &str {
        "supply-chain-registry-audit"
    }

    fn name(&self) -> &str {
        "Package Registry Configuration Audit"
    }

    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_npmrc_files(fs, ctx, &mut findings);
        check_pip_configs(fs, ctx, &mut findings);
        check_cargo_configs(fs, ctx, &mut findings);

        findings
    }
}

// ---------------------------------------------------------------------------
// npm (.npmrc)
// ---------------------------------------------------------------------------

/// Check .npmrc files for security issues
fn check_npmrc_files(
    fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    let mut paths = Vec::new();

    // Project-level
    paths.push(format!("{}/.npmrc", ctx.root.display()));

    // User-level
    for home in &ctx.user_homes {
        paths.push(format!("{}/.npmrc", home.display()));
    }

    // System-level
    paths.push("/etc/npmrc".to_string());

    for path in &paths {
        let Ok(content) = fs.read_to_string(path) else {
            continue;
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Check for auth tokens in plaintext
            if trimmed.contains(":_authToken=") || trimmed.contains(":_auth=") {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-registry-npmrc-token-{}",
                            sanitize_path(path)
                        ),
                        format!("Registry auth token in .npmrc: {}", path),
                        format!(
                            "File {} line {} contains a plaintext registry auth token",
                            path,
                            line_num + 1
                        ),
                        Severity::High,
                        make_source(Some("npm")),
                    )
                    .with_resource(path)
                    .with_remediation(
                        "Use environment variable substitution (${NPM_TOKEN}) instead of \
                         hardcoding auth tokens in .npmrc files",
                    )
                    .with_metadata("line_number", serde_json::json!(line_num + 1)),
                );
            }

            // Check for non-standard registry
            if let Some(registry_url) = trimmed.strip_prefix("registry=") {
                let registry_url = registry_url.trim();
                if !registry_url.is_empty()
                    && !registry_url.starts_with(NPM_STANDARD_REGISTRY)
                {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-registry-npmrc-custom-{}",
                                sanitize_path(path)
                            ),
                            format!("Non-standard npm registry: {}", path),
                            format!(
                                "File {} configures non-standard npm registry: {} \
                                 (standard is {})",
                                path, registry_url, NPM_STANDARD_REGISTRY
                            ),
                            Severity::Medium,
                            make_source(Some("npm")),
                        )
                        .with_resource(path)
                        .with_metadata("registry_url", serde_json::json!(registry_url)),
                    );
                }
            }

            // Check for explicit ignore-scripts=false
            if trimmed == "ignore-scripts=false" {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-registry-npmrc-scripts-{}",
                            sanitize_path(path)
                        ),
                        format!("npm scripts explicitly enabled: {}", path),
                        format!(
                            "File {} explicitly sets ignore-scripts=false — npm lifecycle \
                             scripts will run on install",
                            path
                        ),
                        Severity::Low,
                        make_source(Some("npm")),
                    )
                    .with_resource(path),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// pip (pip.conf / pip.ini)
// ---------------------------------------------------------------------------

/// Check pip configuration files for security issues
fn check_pip_configs(
    fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    let mut paths = Vec::new();

    // Project-level
    paths.push(format!("{}/pip.conf", ctx.root.display()));

    // User-level
    for home in &ctx.user_homes {
        paths.push(format!("{}/.config/pip/pip.conf", home.display()));
        paths.push(format!("{}/.pip/pip.conf", home.display()));
    }

    // System-level
    paths.push("/etc/pip.conf".to_string());

    for path in &paths {
        let Ok(content) = fs.read_to_string(path) else {
            continue;
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
                continue;
            }

            let lower = trimmed.to_lowercase();

            // Check for non-standard index-url
            if lower.starts_with("index-url") {
                if let Some(url) = extract_ini_value(trimmed) {
                    if !url.starts_with(PYPI_STANDARD_INDEX) {
                        findings.push(
                            Finding::new(
                                format!(
                                    "supply-chain-registry-pip-index-{}",
                                    sanitize_path(path)
                                ),
                                format!("Non-standard PyPI index: {}", path),
                                format!(
                                    "File {} line {} configures non-standard PyPI index: {} \
                                     (standard is {})",
                                    path,
                                    line_num + 1,
                                    url,
                                    PYPI_STANDARD_INDEX
                                ),
                                Severity::Medium,
                                make_source(Some("pypi")),
                            )
                            .with_resource(path)
                            .with_metadata("index_url", serde_json::json!(url)),
                        );
                    }
                }
            }

            // Check for extra-index-url
            if lower.starts_with("extra-index-url") {
                if let Some(url) = extract_ini_value(trimmed) {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-registry-pip-extra-index-{}",
                                sanitize_path(path)
                            ),
                            format!("Extra PyPI index configured: {}", path),
                            format!(
                                "File {} line {} configures extra-index-url: {} — adds \
                                 additional package source which increases dependency confusion risk",
                                path,
                                line_num + 1,
                                url
                            ),
                            Severity::Low,
                            make_source(Some("pypi")),
                        )
                        .with_resource(path)
                        .with_metadata("extra_index_url", serde_json::json!(url)),
                    );
                }
            }

            // Check for trusted-host
            if lower.starts_with("trusted-host") {
                if let Some(host) = extract_ini_value(trimmed) {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-registry-pip-trusted-host-{}",
                                sanitize_path(path)
                            ),
                            format!("pip trusted-host configured: {}", path),
                            format!(
                                "File {} line {} sets trusted-host={} — allows insecure HTTP \
                                 connections to package index",
                                path,
                                line_num + 1,
                                host
                            ),
                            Severity::High,
                            make_source(Some("pypi")),
                        )
                        .with_resource(path)
                        .with_remediation(
                            "Remove trusted-host and use only HTTPS package indexes",
                        )
                        .with_metadata("trusted_host", serde_json::json!(host)),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cargo (.cargo/config.toml)
// ---------------------------------------------------------------------------

/// Check Cargo configuration files for security issues
fn check_cargo_configs(
    fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    let mut paths = Vec::new();

    // Project-level
    paths.push(format!("{}/.cargo/config.toml", ctx.root.display()));
    paths.push(format!("{}/.cargo/config", ctx.root.display()));

    // User-level
    for home in &ctx.user_homes {
        paths.push(format!("{}/.cargo/config.toml", home.display()));
        paths.push(format!("{}/.cargo/config", home.display()));
    }

    for path in &paths {
        let Ok(content) = fs.read_to_string(path) else {
            continue;
        };

        let Ok(doc) = content.parse::<toml::Value>() else {
            tracing::debug!("Failed to parse TOML: {}", path);
            continue;
        };

        // Check for custom registries
        if let Some(registries) = doc.get("registries").and_then(|r| r.as_table()) {
            for (name, _value) in registries {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-registry-cargo-custom-{}-{}",
                            sanitize(name),
                            sanitize_path(path)
                        ),
                        format!("Custom Cargo registry '{}': {}", name, path),
                        format!(
                            "File {} defines custom Cargo registry '{}' — verify this is an \
                             authorized package source",
                            path, name
                        ),
                        Severity::Low,
                        make_source(Some("crates.io")),
                    )
                    .with_resource(path)
                    .with_metadata("registry_name", serde_json::json!(name)),
                );
            }
        }

        // Check for source replacement (source.crates-io.replace-with)
        if let Some(source) = doc.get("source").and_then(|s| s.as_table()) {
            if let Some(crates_io) = source.get("crates-io").and_then(|c| c.as_table()) {
                if let Some(replace_with) =
                    crates_io.get("replace-with").and_then(|r| r.as_str())
                {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-registry-cargo-replace-{}",
                                sanitize_path(path)
                            ),
                            format!("crates.io source replaced: {}", path),
                            format!(
                                "File {} replaces crates.io with '{}' — all crate downloads \
                                 will come from this alternative source",
                                path, replace_with
                            ),
                            Severity::Medium,
                            make_source(Some("crates.io")),
                        )
                        .with_resource(path)
                        .with_metadata("replace_with", serde_json::json!(replace_with)),
                    );
                }
            }
        }
    }
}

/// Extract value from an INI-style `key = value` or `key=value` line
fn extract_ini_value(line: &str) -> Option<String> {
    let pos = line.find('=')?;
    let val = line[pos + 1..].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Create FindingSource for registry audit checks
fn make_source(ecosystem: Option<&str>) -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "environment".to_string(),
        ecosystem: ecosystem.map(|s| s.to_string()),
    }
}

/// Sanitize a string for use in finding IDs
fn sanitize(s: &str) -> String {
    s.replace('/', "-")
        .replace('.', "-")
        .replace(' ', "-")
        .trim_matches('-')
        .to_string()
}

/// Sanitize a file path for use in finding IDs
fn sanitize_path(path: &str) -> String {
    path.replace('/', "-").trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_ctx(tmp: &TempDir) -> SupplyChainContext {
        SupplyChainContext {
            root: tmp.path().to_path_buf(),
            user_homes: vec![std::path::PathBuf::from("/home/testuser")],
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        }
    }

    fn make_fs(tmp: &TempDir) -> ContainerFs {
        ContainerFs::new(tmp.path())
    }

    fn write_file(tmp: &TempDir, rel_path: &str, content: &str) {
        let path = tmp.path().join(rel_path.trim_start_matches('/'));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_npmrc_auth_token_high() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "home/testuser/.npmrc",
            "//registry.npmjs.org/:_authToken=npm_s3cr3tT0k3n\n",
        );

        let check = RegistryAuditCheck;
        let findings = check.run(&fs, &ctx);
        let token_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("auth token"))
            .collect();
        assert_eq!(token_findings.len(), 1);
        assert_eq!(token_findings[0].severity, Severity::High);
    }

    #[test]
    fn test_npmrc_custom_registry_medium() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "home/testuser/.npmrc",
            "registry=https://npm.internal.corp.com/\n",
        );

        let check = RegistryAuditCheck;
        let findings = check.run(&fs, &ctx);
        let registry_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Non-standard npm"))
            .collect();
        assert_eq!(registry_findings.len(), 1);
        assert_eq!(registry_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_pip_trusted_host_high() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "home/testuser/.config/pip/pip.conf",
            "[global]\ntrusted-host = pypi.internal.corp.com\nindex-url = http://pypi.internal.corp.com/simple/\n",
        );

        let check = RegistryAuditCheck;
        let findings = check.run(&fs, &ctx);
        let trusted_host: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("trusted-host"))
            .collect();
        assert_eq!(trusted_host.len(), 1);
        assert_eq!(trusted_host[0].severity, Severity::High);
    }

    #[test]
    fn test_cargo_source_replacement_medium() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "home/testuser/.cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"internal-mirror\"\n\n[source.internal-mirror]\nregistry = \"https://crates.internal.corp.com/index\"\n",
        );

        let check = RegistryAuditCheck;
        let findings = check.run(&fs, &ctx);
        let replace_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("source replaced"))
            .collect();
        assert_eq!(replace_findings.len(), 1);
        assert_eq!(replace_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_pip_extra_index_url_low() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "etc/pip.conf",
            "[global]\nextra-index-url = https://private.pypi.corp.com/simple/\n",
        );

        let check = RegistryAuditCheck;
        let findings = check.run(&fs, &ctx);
        let extra_index: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Extra PyPI"))
            .collect();
        assert_eq!(extra_index.len(), 1);
        assert_eq!(extra_index[0].severity, Severity::Low);
    }

    #[test]
    fn test_clean_configs_no_findings() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        // Standard npm registry
        write_file(
            &tmp,
            "home/testuser/.npmrc",
            "registry=https://registry.npmjs.org/\n",
        );

        // Standard pip index
        write_file(
            &tmp,
            "home/testuser/.config/pip/pip.conf",
            "[global]\nindex-url = https://pypi.org/simple/\n",
        );

        let check = RegistryAuditCheck;
        let findings = check.run(&fs, &ctx);
        assert!(
            findings.is_empty(),
            "Standard configs should produce no findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}
