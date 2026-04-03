//! Environment variable and systemd service scanner
//!
//! Scans /proc/self/environ, systemd service files, and
//! system environment configs for leaked credentials.

use crate::patterns::PatternSet;
use crate::redact::redact_secret;
use protectinator_core::{Finding, FindingSource};
use std::io::{BufRead, BufReader};
use std::path::Path;
use tracing::debug;

/// Scan environment-related sources for secrets
pub fn scan_environment(patterns: &PatternSet) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Scan current process environment
    scan_proc_environ(patterns, &mut findings);

    // Scan systemd service files
    scan_systemd_services(patterns, &mut findings);

    // Scan /etc/environment
    scan_file_for_secrets(Path::new("/etc/environment"), "env_config", patterns, &mut findings);

    // Scan /etc/default/*
    if let Ok(entries) = std::fs::read_dir("/etc/default") {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                scan_file_for_secrets(&entry.path(), "env_config", patterns, &mut findings);
            }
        }
    }

    findings
}

fn scan_proc_environ(patterns: &PatternSet, findings: &mut Vec<Finding>) {
    // Read /proc/self/environ (null-delimited)
    let content = match std::fs::read("/proc/self/environ") {
        Ok(c) => c,
        Err(e) => {
            debug!("Cannot read /proc/self/environ: {}", e);
            return;
        }
    };

    for entry in content.split(|&b| b == 0) {
        let line = match std::str::from_utf8(entry) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if line.is_empty() {
            continue;
        }

        let matches = patterns.scan_line(line);
        for m in matches {
            let redacted = redact_secret(&m.matched_value);
            // Extract variable name (before =)
            let var_name = line.split('=').next().unwrap_or("unknown");

            findings.push(
                Finding::new(
                    format!("secrets-env-{}", m.pattern_id),
                    format!("{} in environment variable {}", m.pattern_name, var_name),
                    format!(
                        "Environment variable {} contains a {} (redacted: {}). \
                         Environment variables are inherited by child processes.",
                        var_name,
                        m.secret_type,
                        redacted,
                    ),
                    m.severity,
                    FindingSource::Secrets {
                        check_category: "env_var".to_string(),
                        secret_type: Some(m.secret_type),
                    },
                )
                .with_resource(format!("env:{}", var_name))
                .with_remediation(
                    "Use a secrets manager or load secrets from a protected file at runtime \
                     rather than storing them directly in environment variables.",
                ),
            );
        }
    }
}

fn scan_systemd_services(patterns: &PatternSet, findings: &mut Vec<Finding>) {
    let service_dirs = [
        "/etc/systemd/system",
        "/lib/systemd/system",
    ];

    // Also check user services
    if let Ok(home) = std::env::var("HOME") {
        let user_dir = format!("{}/.config/systemd/user", home);
        scan_service_dir(Path::new(&user_dir), patterns, findings);
    }

    for dir in &service_dirs {
        scan_service_dir(Path::new(dir), patterns, findings);
    }
}

fn scan_service_dir(dir: &Path, patterns: &PatternSet, findings: &mut Vec<Finding>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".service") || name.ends_with(".timer") || name.ends_with(".conf") {
            scan_file_for_secrets(&path, "systemd_service", patterns, findings);
        }
    }
}

fn scan_file_for_secrets(path: &Path, category: &str, patterns: &PatternSet, findings: &mut Vec<Finding>) {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let reader = BufReader::new(file);
    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // For systemd files, focus on Environment= and ExecStart= lines
        if category == "systemd_service" {
            let trimmed = line.trim();
            if !trimmed.starts_with("Environment=") && !trimmed.starts_with("ExecStart=")
                && !trimmed.starts_with("ExecStartPre=") && !trimmed.contains("password")
                && !trimmed.contains("token") && !trimmed.contains("secret")
                && !trimmed.contains("key=")
            {
                continue;
            }
        }

        let matches = patterns.scan_line(&line);
        for m in matches {
            let redacted = redact_secret(&m.matched_value);
            findings.push(
                Finding::new(
                    format!("secrets-{}-{}", category, m.pattern_id),
                    format!("{} in {}", m.pattern_name, path.display()),
                    format!(
                        "{} contains a {} at line {} (redacted: {})",
                        path.display(),
                        m.secret_type,
                        line_num + 1,
                        redacted,
                    ),
                    m.severity,
                    FindingSource::Secrets {
                        check_category: category.to_string(),
                        secret_type: Some(m.secret_type),
                    },
                )
                .with_resource(path.display().to_string())
                .with_metadata("line_number", serde_json::json!(line_num + 1))
                .with_remediation(
                    "Remove credentials from service files. Use systemd's LoadCredential= \
                     or EnvironmentFile= pointing to a restricted-permission file.",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_file_for_secrets_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_test");
        let stripe_key = format!("{}{}", "sk_live_", "TESTKEY000000000FAKEFAKE00");
        std::fs::write(&path, format!("STRIPE_KEY={}\nPATH=/usr/bin\n", stripe_key)).unwrap();

        let patterns = PatternSet::builtin();
        let mut findings = Vec::new();
        scan_file_for_secrets(&path, "env_config", &patterns, &mut findings);
        assert!(!findings.is_empty(), "Should find Stripe key");
    }
}
