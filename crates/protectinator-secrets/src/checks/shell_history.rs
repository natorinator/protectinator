//! Shell history scanner
//!
//! Scans bash, zsh, and fish history files for leaked credentials
//! in command arguments.

use crate::patterns::PatternSet;
use crate::redact::redact_secret;
use protectinator_core::{Finding, FindingSource, Severity};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Scan shell history files for secrets
pub fn scan_shell_history(user_homes: &[PathBuf], patterns: &PatternSet) -> Vec<Finding> {
    let mut findings = Vec::new();

    let history_files = [
        ".bash_history",
        ".zsh_history",
        ".local/share/fish/fish_history",
    ];

    for home in user_homes {
        for hist_file in &history_files {
            let path = home.join(hist_file);
            if path.exists() {
                scan_history_file(&path, patterns, &mut findings);
            }
        }
    }

    findings
}

fn scan_history_file(path: &Path, patterns: &PatternSet, findings: &mut Vec<Finding>) {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            debug!("Cannot read history file {}: {}", path.display(), e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let mut seen_types: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // For zsh history, strip the timestamp prefix (: 1234567890:0;command)
        let cmd = if line.starts_with(": ") {
            line.splitn(2, ';').nth(1).unwrap_or(&line)
        } else {
            &line
        };

        // Also check for password in common CLI patterns
        let has_password_arg = cmd.contains("-p ") || cmd.contains("--password")
            || cmd.contains("-P ") || cmd.contains("--token");

        let matches = patterns.scan_line(cmd);
        for m in matches {
            // Deduplicate by secret type (don't report same key type 50 times from history)
            if seen_types.contains(&m.secret_type) {
                continue;
            }
            seen_types.insert(m.secret_type.clone());

            let redacted = redact_secret(&m.matched_value);
            findings.push(
                Finding::new(
                    format!("secrets-history-{}", m.pattern_id),
                    format!("{} found in shell history", m.pattern_name),
                    format!(
                        "Shell history {} contains a {} (redacted: {}) at line {}. \
                         This credential was used in a shell command and is stored in plaintext.",
                        path.display(),
                        m.secret_type,
                        redacted,
                        line_num + 1,
                    ),
                    m.severity,
                    FindingSource::Secrets {
                        check_category: "shell_history".to_string(),
                        secret_type: Some(m.secret_type),
                    },
                )
                .with_resource(path.display().to_string())
                .with_metadata("line_number", serde_json::json!(line_num + 1))
                .with_remediation(
                    "Rotate this credential immediately — it is stored in plaintext shell history. \
                     Clear the history entry and consider using a secrets manager or environment variables \
                     loaded from a protected file.",
                ),
            );
        }

        // Check for password CLI args even without a pattern match
        if has_password_arg && !cmd.contains("--password=''") && !cmd.contains("-p ''") {
            // Check if there's an actual value after the flag
            let has_inline_pass = cmd.contains("--password=") ||
                (cmd.contains("-p") && !cmd.contains("-p \\") && !cmd.contains("-p \"\""));

            if has_inline_pass && seen_types.insert("cli_password_arg".to_string()) {
                findings.push(
                    Finding::new(
                        "secrets-history-cli-password",
                        "Password passed as CLI argument in shell history",
                        format!(
                            "Shell history {} contains a command with an inline password argument at line {}. \
                             Passwords passed as CLI arguments are visible in process listings and shell history.",
                            path.display(),
                            line_num + 1,
                        ),
                        Severity::Medium,
                        FindingSource::Secrets {
                            check_category: "shell_history".to_string(),
                            secret_type: Some("cli_password".to_string()),
                        },
                    )
                    .with_resource(path.display().to_string())
                    .with_metadata("line_number", serde_json::json!(line_num + 1))
                    .with_remediation(
                        "Avoid passing passwords as CLI arguments. Use environment variables, \
                         .pgpass files, or interactive password prompts instead.",
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_bash_history() {
        let dir = tempfile::tempdir().unwrap();
        let hist = dir.path().join(".bash_history");
        std::fs::write(&hist, "ls -la\ncurl -H 'Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'\ncd /tmp\n").unwrap();

        let patterns = PatternSet::builtin();
        let findings = scan_shell_history(&[dir.path().to_path_buf()], &patterns);
        assert!(!findings.is_empty(), "Should find GitHub token in history");
    }

    #[test]
    fn test_zsh_history_timestamp_stripping() {
        let dir = tempfile::tempdir().unwrap();
        let hist = dir.path().join(".zsh_history");
        let stripe_key = format!("{}{}", "sk_live_", "TESTKEY000000000FAKEFAKE00");
        std::fs::write(&hist, format!(": 1234567890:0;export STRIPE_KEY={}\n", stripe_key)).unwrap();

        let patterns = PatternSet::builtin();
        let findings = scan_shell_history(&[dir.path().to_path_buf()], &patterns);
        assert!(!findings.is_empty(), "Should find Stripe key in zsh history");
    }
}
