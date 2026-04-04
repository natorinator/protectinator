//! Filesystem scanner for secrets detection
//!
//! Walks a directory tree, reads text files, and applies the two-pass
//! pattern engine plus optional entropy detection to find leaked secrets.

use crate::entropy::is_high_entropy;
use crate::patterns::{PatternSet, PatternTier};
use crate::redact::redact_secret;
use protectinator_core::{Finding, FindingSource};
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};
use walkdir::WalkDir;

/// Maximum file size to scan (default 1MB)
const DEFAULT_MAX_FILE_SIZE: u64 = 1_048_576;

/// File extensions to prioritize
const PRIORITY_EXTENSIONS: &[&str] = &[
    "env", "yml", "yaml", "toml", "json", "cfg", "ini", "conf",
    "properties", "xml", "sh", "bash", "zsh", "py", "rb", "js",
    "ts", "go", "rs", "java", "php", "tf", "tfvars", "hcl",
];

/// File names that are always scanned regardless of extension
const PRIORITY_FILENAMES: &[&str] = &[
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test", "credentials", "secrets",
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".pgpass",
    "docker-compose.yml", "docker-compose.yaml",
];

/// Directories to skip
const SKIP_DIRS: &[&str] = &[
    ".git", ".jj", ".hg", ".svn", "node_modules", "vendor",
    "target", "__pycache__", ".venv", "venv", ".tox",
    "dist", "build", ".next", ".nuxt",
];

/// Lock files to skip (high false positive rate)
const SKIP_FILES: &[&str] = &[
    "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
    "Cargo.lock", "poetry.lock", "Pipfile.lock", "composer.lock",
    "Gemfile.lock", "go.sum", "uv.lock",
];

/// Scanner configuration
pub struct SecretsScanner {
    root: PathBuf,
    patterns: PatternSet,
    skip_patterns: bool,
    skip_entropy: bool,
    min_entropy: Option<f64>,
    max_file_size: u64,
    scan_hidden: bool,
}

impl SecretsScanner {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            patterns: PatternSet::builtin(),
            skip_patterns: false,
            skip_entropy: false,
            min_entropy: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            scan_hidden: false,
        }
    }

    pub fn skip_patterns(mut self, skip: bool) -> Self {
        self.skip_patterns = skip;
        self
    }

    pub fn skip_entropy(mut self, skip: bool) -> Self {
        self.skip_entropy = skip;
        self
    }

    pub fn min_entropy(mut self, threshold: f64) -> Self {
        self.min_entropy = Some(threshold);
        self
    }

    pub fn max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn scan_hidden(mut self, scan: bool) -> Self {
        self.scan_hidden = scan;
        self
    }

    pub fn custom_patterns(mut self, path: &Path) -> Self {
        if let Err(e) = self.patterns.load_custom(path) {
            warn!("Failed to load custom patterns from {}: {}", path.display(), e);
        }
        self
    }

    /// Run the filesystem scan and return findings
    pub fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for entry in WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !self.should_skip_entry(e))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();

            // Check file size
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.len() > self.max_file_size {
                    debug!("Skipping large file: {}", path.display());
                    continue;
                }
            }

            // Skip lock files
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if SKIP_FILES.contains(&name) {
                    continue;
                }
            }

            // Check if this is a file type we should scan
            if !self.should_scan_file(path) {
                continue;
            }

            // Check if file is binary (read first 512 bytes)
            if is_binary_file(path) {
                continue;
            }

            self.scan_file(path, &mut findings);
        }

        findings
    }

    fn should_skip_entry(&self, entry: &walkdir::DirEntry) -> bool {
        let name = entry.file_name().to_str().unwrap_or("");

        // Never skip the root directory itself
        if entry.depth() == 0 {
            return false;
        }

        // Skip hidden directories (but not hidden files like .env)
        if entry.file_type().is_dir() {
            if SKIP_DIRS.contains(&name) {
                return true;
            }
            if !self.scan_hidden && name.starts_with('.') && name != "." {
                return true;
            }
        }

        false
    }

    fn should_scan_file(&self, path: &Path) -> bool {
        // Always scan priority filenames
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if PRIORITY_FILENAMES.contains(&name) {
                return true;
            }
            // .env variants
            if name.starts_with(".env") {
                return true;
            }
        }

        // Check extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            return PRIORITY_EXTENSIONS.contains(&ext);
        }

        // Files without extension in common config locations
        false
    }

    fn scan_file(&self, path: &Path, findings: &mut Vec<Finding>) {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Cannot open {}: {}", path.display(), e);
                return;
            }
        };

        let reader = BufReader::new(file);
        let is_config = is_config_file(path);
        let is_rust = path.extension().map_or(false, |e| e == "rs");
        let mut seen_patterns: HashSet<String> = HashSet::new();
        let mut in_test_block = false;

        for (line_num, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue, // binary content or encoding issue
            };

            // Skip empty lines and comments
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Track test context in Rust files to skip mock/test secrets
            if is_rust {
                if trimmed == "#[cfg(test)]" || trimmed.starts_with("mod tests") {
                    in_test_block = true;
                }
                if in_test_block {
                    continue;
                }
            }

            // Skip lines that are clearly test/example patterns in any language
            if is_test_line(trimmed) {
                continue;
            }

            // Pattern-based detection
            if !self.skip_patterns {
                let matches = self.patterns.scan_line(&line);
                for m in matches {
                    // For EntropyOnly tier, only apply in config files and verify entropy
                    if m.tier == PatternTier::EntropyOnly {
                        if !is_config {
                            continue;
                        }
                        if !self.skip_entropy && !is_high_entropy(&m.matched_value, self.min_entropy) {
                            continue;
                        }
                    }

                    // Deduplicate: same pattern+file, keep first occurrence
                    let dedup_key = format!("{}:{}", m.pattern_id, path.display());
                    if seen_patterns.contains(&dedup_key) {
                        continue;
                    }
                    seen_patterns.insert(dedup_key);

                    let redacted = redact_secret(&m.matched_value);
                    let title = format!("{} found in {}", m.pattern_name, path_display(path, &self.root));
                    let description = format!(
                        "{}: detected {} (redacted: {}) at line {}",
                        m.description,
                        m.secret_type,
                        redacted,
                        line_num + 1,
                    );

                    let mut finding = Finding::new(
                        format!("secrets-{}", m.pattern_id),
                        title,
                        description,
                        m.severity,
                        FindingSource::Secrets {
                            check_category: "pattern".to_string(),
                            secret_type: Some(m.secret_type.clone()),
                        },
                    )
                    .with_resource(path.display().to_string())
                    .with_metadata("line_number", serde_json::json!(line_num + 1))
                    .with_metadata("pattern_id", serde_json::json!(m.pattern_id))
                    .with_metadata("secret_type", serde_json::json!(m.secret_type))
                    .with_metadata("redacted_value", serde_json::json!(redacted));

                    // Check file permissions
                    if check_file_permissions(path).is_some() {
                        finding = finding.with_metadata("world_readable", serde_json::json!(true));
                    }

                    // Add remediation
                    finding = finding.with_remediation(format!(
                        "Remove or rotate this {}. If committed to version control, rotate immediately — the secret is in git history. \
                         Consider using environment variables or a secrets manager instead.",
                        m.pattern_name,
                    ));

                    findings.push(finding);
                }
            }
        }
    }
}

/// Check if a line looks like test/example code rather than a real secret
fn is_test_line(trimmed: &str) -> bool {
    // Common test/assertion patterns
    if trimmed.starts_with("assert") || trimmed.starts_with("expect(") {
        return true;
    }
    // String construction for tests (format!, concat!, vec![)
    if trimmed.starts_with("let ") && (trimmed.contains("format!(") || trimmed.contains("concat!(")) {
        return true;
    }
    // Comments describing patterns
    if trimmed.starts_with("//") || trimmed.starts_with("#") || trimmed.starts_with("*") {
        return true;
    }
    // Regex pattern definitions (the pattern itself, not a real secret)
    if trimmed.contains("Regex::new(") || trimmed.contains("r\"") || trimmed.contains("r#\"") {
        return true;
    }
    false
}

/// Display path relative to root
fn path_display(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Check if a file is likely binary by examining first 512 bytes
fn is_binary_file(path: &Path) -> bool {
    let mut buf = [0u8; 512];
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut reader = BufReader::new(file);
    let n = match std::io::Read::read(&mut reader, &mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    // Check for null bytes (common in binary files)
    buf[..n].contains(&0)
}

/// Check if a file is a config-type file (for Tier 3 entropy patterns)
fn is_config_file(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with(".env") || PRIORITY_FILENAMES.contains(&name) {
            return true;
        }
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some("env" | "yml" | "yaml" | "toml" | "json" | "cfg" | "ini" | "conf" | "properties" | "xml" | "tf" | "tfvars") => true,
        _ => false,
    }
}

/// Check if a file containing secrets has unsafe permissions
fn check_file_permissions(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o004 != 0 {
                return Some(format!(
                    "File {} is world-readable (mode {:o})",
                    path.display(),
                    mode & 0o777,
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_binary_file() {
        let dir = tempfile::tempdir().unwrap();
        let text_path = dir.path().join("test.txt");
        std::fs::write(&text_path, "hello world\n").unwrap();
        assert!(!is_binary_file(&text_path));

        let bin_path = dir.path().join("test.bin");
        std::fs::write(&bin_path, &[0u8, 1, 2, 3, 0, 5]).unwrap();
        assert!(is_binary_file(&bin_path));
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file(Path::new("/app/.env")));
        assert!(is_config_file(Path::new("/app/.env.production")));
        assert!(is_config_file(Path::new("/app/config.yml")));
        assert!(is_config_file(Path::new("/app/settings.toml")));
        assert!(!is_config_file(Path::new("/app/main.rs")));
    }

    #[test]
    fn test_scan_finds_secrets_in_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let stripe_key = format!("{}{}", "sk_live_", "TESTKEY000000000FAKEFAKE00");
        std::fs::write(&env_path, format!("STRIPE_KEY={}\nDEBUG=true\n", stripe_key)).unwrap();

        let scanner = SecretsScanner::new(dir.path());
        let findings = scanner.scan();
        assert!(!findings.is_empty(), "Should find Stripe key in .env");
        // Verify redaction
        let desc = &findings[0].description;
        assert!(!desc.contains(&stripe_key), "Full secret should be redacted");
    }

    #[test]
    fn test_scan_skips_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("package-lock.json");
        std::fs::write(&lock_path, r#"{"integrity": "sha512-AKIAIOSFODNN7EXAMPLExxxxxxxxxxxxxxxx"}"#).unwrap();

        let scanner = SecretsScanner::new(dir.path());
        let findings = scanner.scan();
        assert!(findings.is_empty(), "Should skip lock files");
    }

    #[test]
    fn test_scan_skips_binary_files() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("data.env");
        let mut content = format!("SECRET={}{}\n", "sk_live_", "TESTKEY000000000FAKEFAKE00").into_bytes();
        content.push(0); // null byte makes it binary
        std::fs::write(&bin_path, &content).unwrap();

        let scanner = SecretsScanner::new(dir.path());
        let findings = scanner.scan();
        assert!(findings.is_empty(), "Should skip binary files");
    }

    #[test]
    fn test_path_display_relative() {
        assert_eq!(
            path_display(Path::new("/home/user/project/src/main.rs"), Path::new("/home/user/project")),
            "src/main.rs"
        );
    }
}
