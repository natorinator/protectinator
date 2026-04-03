//! Git history scanner
//!
//! Scans git commit history for secrets that were committed.
//! Uses the system `git` command to parse diffs.

use crate::patterns::PatternSet;
use crate::redact::redact_secret;
use protectinator_core::{Finding, FindingSource, Severity};
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

/// Default maximum number of commits to scan
const DEFAULT_MAX_COMMITS: usize = 1000;

/// Scan git history for committed secrets
pub fn scan_git_history(
    repo_path: &Path,
    patterns: &PatternSet,
    max_commits: Option<usize>,
) -> Vec<Finding> {
    let max = max_commits.unwrap_or(DEFAULT_MAX_COMMITS);

    // Check if this is a git repo
    let is_git = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(repo_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !is_git {
        debug!("Not a git repository: {}", repo_path.display());
        return Vec::new();
    }

    info!("Scanning git history (last {} commits)...", max);

    // Get diff of all commits, showing only added lines
    let child = match Command::new("git")
        .args([
            "log",
            "-p",
            "--all",
            "--diff-filter=A",
            &format!("-{}", max),
            "--no-color",
            "--",
        ])
        .current_dir(repo_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to run git log: {}", e);
            return Vec::new();
        }
    };

    let stdout = match child.stdout {
        Some(s) => s,
        None => return Vec::new(),
    };

    parse_git_log(stdout, patterns)
}

/// Parse git log -p output and scan for secrets
fn parse_git_log(stdout: impl std::io::Read, patterns: &PatternSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    let reader = BufReader::new(stdout);

    let mut current_commit = String::new();
    let mut current_author = String::new();
    let mut current_date = String::new();
    let mut current_file = String::new();
    let mut seen: HashSet<String> = HashSet::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Parse commit metadata
        if line.starts_with("commit ") {
            current_commit = line[7..].trim().to_string();
            continue;
        }
        if line.starts_with("Author: ") {
            current_author = line[8..].trim().to_string();
            continue;
        }
        if line.starts_with("Date: ") {
            current_date = line[6..].trim().to_string();
            continue;
        }
        if line.starts_with("diff --git ") {
            // Extract file path from "diff --git a/path b/path"
            if let Some(b_path) = line.split(" b/").nth(1) {
                current_file = b_path.to_string();
            }
            continue;
        }

        // Only scan added lines (+ prefix, but not +++ header)
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }

        let added_line = &line[1..]; // Strip the + prefix

        let matches = patterns.scan_line(added_line);
        for m in matches {
            // Deduplicate: same secret type + file + commit
            let dedup_key = format!("{}:{}:{}", m.secret_type, current_file, &current_commit[..7.min(current_commit.len())]);
            if seen.contains(&dedup_key) {
                continue;
            }
            seen.insert(dedup_key);

            let redacted = redact_secret(&m.matched_value);
            let short_commit = &current_commit[..7.min(current_commit.len())];

            findings.push(
                Finding::new(
                    format!("secrets-git-{}", m.pattern_id),
                    format!("{} committed in git history", m.pattern_name),
                    format!(
                        "{} found in {} (commit {}, author: {}). Redacted: {}",
                        m.secret_type,
                        current_file,
                        short_commit,
                        current_author,
                        redacted,
                    ),
                    // Git history findings are always critical — the secret is permanently in history
                    Severity::Critical,
                    FindingSource::Secrets {
                        check_category: "git_history".to_string(),
                        secret_type: Some(m.secret_type),
                    },
                )
                .with_resource(format!("git:{}:{}", short_commit, current_file))
                .with_metadata("commit_hash", serde_json::json!(current_commit))
                .with_metadata("commit_author", serde_json::json!(current_author))
                .with_metadata("commit_date", serde_json::json!(current_date))
                .with_metadata("file_path", serde_json::json!(current_file))
                .with_metadata("redacted_value", serde_json::json!(redacted))
                .with_remediation(format!(
                    "This secret was committed to git history in commit {}. \
                     Rotate the credential immediately. To remove from history, use \
                     `git filter-branch` or `git-filter-repo`, but note that anyone \
                     who has cloned the repo may still have the secret.",
                    short_commit,
                )),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_git_log_with_secret() {
        let patterns = PatternSet::builtin();
        let stripe_key = format!("{}{}", "sk_live_", "TESTKEY000000000FAKEFAKE00");
        let log_output = format!("commit abc1234567890abcdef1234567890abcdef123456\n\
Author: Test User <test@example.com>\n\
Date:   Mon Jan 1 00:00:00 2024 +0000\n\
\n\
    Add config\n\
\n\
diff --git a/.env b/.env\n\
new file mode 100644\n\
--- /dev/null\n\
+++ b/.env\n\
+STRIPE_KEY={}\n\
+DEBUG=true\n", stripe_key);
        let findings = parse_git_log(log_output.as_bytes(), &patterns);
        assert!(!findings.is_empty(), "Should find Stripe key in git history");
        assert_eq!(findings[0].severity, Severity::Critical);

        // Check metadata
        assert!(findings[0].metadata.contains_key("commit_hash"));
        assert!(findings[0].metadata.contains_key("commit_author"));
    }

    #[test]
    fn test_parse_git_log_no_secrets() {
        let patterns = PatternSet::builtin();
        let log_output = b"commit abc1234567890abcdef1234567890abcdef123456
Author: Test <test@example.com>
Date:   Mon Jan 1 00:00:00 2024 +0000

    Normal commit

diff --git a/main.rs b/main.rs
--- /dev/null
+++ b/main.rs
+fn main() {
+    println!(\"Hello world\");
+}
";
        let findings = parse_git_log(&log_output[..], &patterns);
        assert!(findings.is_empty(), "Should not find secrets in normal code");
    }

    #[test]
    fn test_parse_git_log_deduplication() {
        let patterns = PatternSet::builtin();
        let stripe_key = format!("{}{}", "sk_live_", "TESTKEY000000000FAKEFAKE00");
        let log_output = format!("commit abc1234567890abcdef1234567890abcdef123456\n\
Author: Test <test@example.com>\n\
Date:   Mon Jan 1 00:00:00 2024 +0000\n\
\n\
    Add config\n\
\n\
diff --git a/.env b/.env\n\
--- /dev/null\n\
+++ b/.env\n\
+KEY1={sk}\n\
+KEY2={sk}\n", sk = stripe_key);
        let findings = parse_git_log(log_output.as_bytes(), &patterns);
        // Same secret type + file + commit should deduplicate
        assert_eq!(findings.len(), 1, "Should deduplicate same secret in same file/commit");
    }
}
