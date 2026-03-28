//! Cryptographic file trust via `nono trust`
//!
//! Provides file signing and verification using ECDSA P-256 signatures
//! as a stronger alternative to hash-only FIM. Shells out to the `nono`
//! CLI tool for key management, signing, and verification.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::debug;
use walkdir::WalkDir;

/// Status of a file's cryptographic trust verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustVerification {
    Verified,
    Unsigned,
    Tampered,
    Missing,
    #[serde(untagged)]
    Unknown(String),
}

impl TrustVerification {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "verified" => Self::Verified,
            "unsigned" => Self::Unsigned,
            "tampered" | "failed" => Self::Tampered,
            "missing" => Self::Missing,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// Trust status for a single file as reported by `nono trust list`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStatus {
    pub file: String,
    pub status: TrustVerification,
    pub signer: Option<String>,
    pub reason: Option<String>,
}

/// Result of a signing operation
pub struct SignResult {
    pub files_signed: usize,
    pub errors: Vec<String>,
}

/// Manages cryptographic file trust via the `nono` CLI
pub struct TrustManager {
    nono_path: String,
}

/// Check whether the `nono` binary is available on this system
pub fn nono_available() -> bool {
    find_nono().is_some()
}

/// Locate the `nono` binary, checking PATH first, then `~/.cargo/bin`
fn find_nono() -> Option<String> {
    // Check PATH
    if let Ok(output) = Command::new("which").arg("nono").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }

    // Check ~/.cargo/bin/nono
    if let Ok(home) = std::env::var("HOME") {
        let cargo_nono = PathBuf::from(home).join(".cargo/bin/nono");
        if cargo_nono.is_file() {
            return Some(cargo_nono.display().to_string());
        }
    }

    None
}

impl TrustManager {
    /// Create a new TrustManager, locating the `nono` binary
    pub fn new() -> Result<Self, String> {
        let nono_path =
            find_nono().ok_or_else(|| "nono binary not found (checked PATH and ~/.cargo/bin)".to_string())?;
        Ok(Self { nono_path })
    }

    /// Initialize a trust policy in a directory
    pub fn init(&self, dir: &Path, patterns: &[&str]) -> Result<(), String> {
        let mut cmd = Command::new(&self.nono_path);
        cmd.arg("trust").arg("init").arg("--silent");
        for pat in patterns {
            cmd.arg("--include").arg(pat);
        }
        cmd.current_dir(dir);

        let output = cmd.output().map_err(|e| format!("Failed to run nono: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nono trust init failed: {stderr}"));
        }
        Ok(())
    }

    /// Sign all files matching the trust policy
    pub fn sign_all(&self, dir: &Path) -> Result<SignResult, String> {
        let output = Command::new(&self.nono_path)
            .args(["trust", "sign", "--all", "--silent"])
            .current_dir(dir)
            .output()
            .map_err(|e| format!("Failed to run nono: {e}"))?;

        // nono writes all output to stderr
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        if !output.status.success() {
            return Err(format!("nono trust sign failed: {}", combined.trim()));
        }

        let files_signed = combined.lines().filter(|l| l.contains("SIGNED")).count();
        let errors: Vec<String> = combined
            .lines()
            .filter(|l| l.contains("ERROR") || l.contains("FAILED"))
            .map(|l| l.to_string())
            .collect();

        Ok(SignResult {
            files_signed,
            errors,
        })
    }

    /// Sign specific files
    pub fn sign_files(&self, dir: &Path, files: &[&str]) -> Result<SignResult, String> {
        let mut total_signed = 0;
        let mut errors = Vec::new();

        for file in files {
            let output = Command::new(&self.nono_path)
                .args(["trust", "sign", "--silent", file])
                .current_dir(dir)
                .output()
                .map_err(|e| format!("Failed to run nono: {e}"))?;

            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            if output.status.success() && combined.contains("SIGNED") {
                total_signed += 1;
            } else if !output.status.success() {
                errors.push(format!("{file}: {}", combined.trim()));
            }
        }

        Ok(SignResult {
            files_signed: total_signed,
            errors,
        })
    }

    /// Verify all files against the trust policy
    pub fn verify_all(&self, dir: &Path) -> Result<Vec<TrustStatus>, String> {
        // Use list --json which gives us structured output
        self.list(dir)
    }

    /// List trust status for all policy-matched files
    pub fn list(&self, dir: &Path) -> Result<Vec<TrustStatus>, String> {
        let output = Command::new(&self.nono_path)
            .args(["trust", "list", "--json", "--silent"])
            .current_dir(dir)
            .output()
            .map_err(|e| format!("Failed to run nono: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nono trust list failed: {stderr}"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_trust_list_json(&stdout)
    }

    /// Check if a trust policy exists in a directory
    pub fn has_policy(dir: &Path) -> bool {
        dir.join("trust-policy.json").is_file()
    }
}

/// Parse the JSON output from `nono trust list --json`
fn parse_trust_list_json(json_str: &str) -> Result<Vec<TrustStatus>, String> {
    // nono outputs: [{"file": "...", "status": "verified|unsigned|tampered|missing", "signer": "..."}]
    let raw: Vec<RawTrustEntry> =
        serde_json::from_str(json_str).map_err(|e| format!("Failed to parse nono JSON: {e}"))?;

    Ok(raw
        .into_iter()
        .map(|entry| TrustStatus {
            file: entry.file,
            status: TrustVerification::from_str(&entry.status),
            signer: entry.signer,
            reason: entry.reason,
        })
        .collect())
}

#[derive(Deserialize)]
struct RawTrustEntry {
    file: String,
    status: String,
    #[serde(default)]
    signer: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Supply chain check integration
// ---------------------------------------------------------------------------

/// Supply chain check that verifies cryptographic trust policies
pub struct TrustVerificationCheck;

impl SupplyChainCheck for TrustVerificationCheck {
    fn id(&self) -> &str {
        "supply-chain-trust-verification"
    }

    fn name(&self) -> &str {
        "Cryptographic Trust Verification"
    }

    fn run(&self, _fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let manager = match TrustManager::new() {
            Ok(m) => m,
            Err(e) => {
                debug!("Skipping trust verification: {e}");
                return Vec::new();
            }
        };

        let mut findings = Vec::new();

        // Walk the root looking for trust-policy.json (max depth 3)
        for entry in WalkDir::new(&ctx.root)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_name() != "trust-policy.json" {
                continue;
            }

            let policy_dir = match entry.path().parent() {
                Some(d) => d,
                None => continue,
            };

            debug!("Found trust policy in {}", policy_dir.display());

            let statuses = match manager.list(policy_dir) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to list trust status in {}: {e}", policy_dir.display());
                    continue;
                }
            };

            for ts in statuses {
                let source = FindingSource::SupplyChain {
                    check_category: "trust".to_string(),
                    ecosystem: None,
                };

                match &ts.status {
                    TrustVerification::Tampered => {
                        findings.push(Finding::new(
                            format!("trust-tampered-{}", ts.file),
                            format!("Tampered file: {}", ts.file),
                            "File has been tampered with \u{2014} signature invalid",
                            Severity::Critical,
                            source,
                        ));
                    }
                    TrustVerification::Missing => {
                        findings.push(Finding::new(
                            format!("trust-missing-{}", ts.file),
                            format!("Missing signed file: {}", ts.file),
                            "Signed file is missing from filesystem",
                            Severity::High,
                            source,
                        ));
                    }
                    TrustVerification::Unsigned => {
                        findings.push(Finding::new(
                            format!("trust-unsigned-{}", ts.file),
                            format!("Unsigned file: {}", ts.file),
                            "File matches trust policy but is not signed",
                            Severity::Medium,
                            source,
                        ));
                    }
                    TrustVerification::Verified => {
                        // Verified files are not findings by default
                    }
                    TrustVerification::Unknown(s) => {
                        debug!("Unknown trust status '{}' for {}", s, ts.file);
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_trust_verification_from_str() {
        assert_eq!(TrustVerification::from_str("verified"), TrustVerification::Verified);
        assert_eq!(TrustVerification::from_str("VERIFIED"), TrustVerification::Verified);
        assert_eq!(TrustVerification::from_str("unsigned"), TrustVerification::Unsigned);
        assert_eq!(TrustVerification::from_str("tampered"), TrustVerification::Tampered);
        assert_eq!(TrustVerification::from_str("failed"), TrustVerification::Tampered);
        assert_eq!(TrustVerification::from_str("FAILED"), TrustVerification::Tampered);
        assert_eq!(TrustVerification::from_str("missing"), TrustVerification::Missing);
        assert_eq!(
            TrustVerification::from_str("something-else"),
            TrustVerification::Unknown("something-else".to_string())
        );
    }

    #[test]
    fn test_parse_trust_list_json() {
        let json = r#"[
            {"file": "/src/main.py", "status": "verified", "signer": "alice@example.com"},
            {"file": "/src/util.py", "status": "tampered", "signer": null},
            {"file": "/src/new.py", "status": "unsigned"},
            {"file": "/src/old.py", "status": "missing", "signer": "alice@example.com"}
        ]"#;

        let statuses = parse_trust_list_json(json).unwrap();
        assert_eq!(statuses.len(), 4);

        assert_eq!(statuses[0].status, TrustVerification::Verified);
        assert_eq!(statuses[0].signer.as_deref(), Some("alice@example.com"));

        assert_eq!(statuses[1].status, TrustVerification::Tampered);
        assert!(statuses[1].signer.is_none());

        assert_eq!(statuses[2].status, TrustVerification::Unsigned);
        assert!(statuses[2].signer.is_none());

        assert_eq!(statuses[3].status, TrustVerification::Missing);
    }

    #[test]
    fn test_has_policy() {
        let tmp = TempDir::new().unwrap();
        assert!(!TrustManager::has_policy(tmp.path()));

        std::fs::write(tmp.path().join("trust-policy.json"), "{}").unwrap();
        assert!(TrustManager::has_policy(tmp.path()));
    }

    #[test]
    fn test_find_nono() {
        // nono should be installed at ~/.cargo/bin/nono
        let result = find_nono();
        assert!(result.is_some(), "nono binary should be discoverable");
        assert!(result.unwrap().contains("nono"));
    }

    #[test]
    fn test_check_produces_findings_for_tampered() {
        // Test the parsing-to-findings logic directly
        let json = r#"[
            {"file": "app.py", "status": "tampered"},
            {"file": "lib.py", "status": "unsigned"},
            {"file": "gone.py", "status": "missing", "signer": "dev@co.com"},
            {"file": "ok.py", "status": "verified", "signer": "dev@co.com"}
        ]"#;

        let statuses = parse_trust_list_json(json).unwrap();

        // Simulate what the check does
        let mut findings = Vec::new();
        for ts in &statuses {
            let source = FindingSource::SupplyChain {
                check_category: "trust".to_string(),
                ecosystem: None,
            };
            match &ts.status {
                TrustVerification::Tampered => {
                    findings.push(Finding::new(
                        format!("trust-tampered-{}", ts.file),
                        format!("Tampered file: {}", ts.file),
                        "File has been tampered with",
                        Severity::Critical,
                        source,
                    ));
                }
                TrustVerification::Missing => {
                    findings.push(Finding::new(
                        format!("trust-missing-{}", ts.file),
                        format!("Missing signed file: {}", ts.file),
                        "Signed file is missing",
                        Severity::High,
                        source,
                    ));
                }
                TrustVerification::Unsigned => {
                    findings.push(Finding::new(
                        format!("trust-unsigned-{}", ts.file),
                        format!("Unsigned file: {}", ts.file),
                        "File not signed",
                        Severity::Medium,
                        source,
                    ));
                }
                _ => {}
            }
        }

        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::Critical);  // tampered
        assert_eq!(findings[1].severity, Severity::Medium);    // unsigned
        assert_eq!(findings[2].severity, Severity::High);      // missing
    }
}
