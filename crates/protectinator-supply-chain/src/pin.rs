//! GitHub Actions SHA pinning
//!
//! Resolves mutable action references (tags/branches) to commit SHAs
//! and rewrites workflow files in place.

use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

/// Result of pinning a single action reference
#[derive(Debug, Clone)]
pub struct PinResult {
    pub file: PathBuf,
    pub action: String,
    pub old_ref: String,
    pub new_sha: String,
    pub was_already_pinned: bool,
}

/// Result of pinning all workflow files in a directory
#[derive(Debug)]
pub struct PinSummary {
    pub files_scanned: usize,
    pub actions_found: usize,
    pub actions_pinned: usize,
    pub already_pinned: usize,
    pub errors: Vec<String>,
    pub results: Vec<PinResult>,
}

/// Discover all GitHub Actions workflow files under a root path
pub fn discover_workflow_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // Must be in a .github/workflows/ directory
        let path_str = path.to_string_lossy();
        if !path_str.contains(".github/workflows/") {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "yml" || ext == "yaml" {
            files.push(path.to_path_buf());
        }
    }

    files
}

/// Parse a workflow file and extract all action references
pub fn extract_action_refs(content: &str) -> Vec<ActionRef> {
    let re = Regex::new(r"uses:\s*([^@\s]+)@(\S+)").unwrap();
    let mut refs = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        if let Some(caps) = re.captures(trimmed) {
            let action = caps.get(1).unwrap().as_str().to_string();
            let ref_str = caps.get(2).unwrap().as_str();

            // Strip inline comment (e.g., "abc123 # v4" -> "abc123")
            let ref_clean = ref_str.split('#').next().unwrap_or(ref_str).trim();

            refs.push(ActionRef {
                action,
                reference: ref_clean.to_string(),
                line: line_num + 1,
                is_sha: is_sha(ref_clean),
            });
        }
    }

    refs
}

/// An action reference found in a workflow file
#[derive(Debug, Clone)]
pub struct ActionRef {
    pub action: String,
    pub reference: String,
    pub line: usize,
    pub is_sha: bool,
}

/// Check if a reference looks like a commit SHA (40 hex chars)
fn is_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolve an action reference to a commit SHA via the GitHub API
///
/// Handles both direct commit refs and annotated tags (which need dereferencing).
pub fn resolve_action_sha(
    agent: &ureq::Agent,
    action: &str,
    reference: &str,
) -> Result<String, String> {
    // Parse owner/repo from action (e.g., "actions/checkout" or "owner/repo/path")
    let parts: Vec<&str> = action.splitn(3, '/').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid action format: {}", action));
    }
    let owner = parts[0];
    let repo = parts[1];

    // Try as a tag first, then as a branch
    let endpoints = [
        format!(
            "https://api.github.com/repos/{}/{}/git/ref/tags/{}",
            owner, repo, reference
        ),
        format!(
            "https://api.github.com/repos/{}/{}/git/ref/heads/{}",
            owner, repo, reference
        ),
    ];

    for endpoint in &endpoints {
        match agent.get(endpoint).call() {
            Ok(response) => {
                let body: serde_json::Value = response
                    .into_json()
                    .map_err(|e| format!("Failed to parse response: {}", e))?;

                let obj_type = body["object"]["type"]
                    .as_str()
                    .unwrap_or("unknown");
                let sha = body["object"]["sha"]
                    .as_str()
                    .ok_or_else(|| "No SHA in response".to_string())?;

                // If it's an annotated tag, dereference to the commit
                if obj_type == "tag" {
                    return dereference_tag(agent, owner, repo, sha);
                }

                return Ok(sha.to_string());
            }
            Err(ureq::Error::Status(404, _)) => continue,
            Err(e) => return Err(format!("GitHub API error: {}", e)),
        }
    }

    Err(format!(
        "Could not resolve {}@{} — ref not found as tag or branch",
        action, reference
    ))
}

/// Dereference an annotated tag to its underlying commit SHA
fn dereference_tag(
    agent: &ureq::Agent,
    owner: &str,
    repo: &str,
    tag_sha: &str,
) -> Result<String, String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/git/tags/{}",
        owner, repo, tag_sha
    );

    let response = agent
        .get(&url)
        .call()
        .map_err(|e| format!("Failed to dereference tag: {}", e))?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("Failed to parse tag response: {}", e))?;

    body["object"]["sha"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No commit SHA in tag object".to_string())
}

/// Pin all action references in workflow files under the given root.
///
/// Resolves mutable refs to commit SHAs and rewrites files in place.
/// If `dry_run` is true, reports what would change without writing.
pub fn pin_workflow_actions(
    root: &Path,
    dry_run: bool,
    gh_token: Option<&str>,
) -> PinSummary {
    let mut summary = PinSummary {
        files_scanned: 0,
        actions_found: 0,
        actions_pinned: 0,
        already_pinned: 0,
        errors: Vec::new(),
        results: Vec::new(),
    };

    let files = discover_workflow_files(root);
    summary.files_scanned = files.len();

    if files.is_empty() {
        info!("No workflow files found");
        return summary;
    }

    // Build HTTP agent with auth if available
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();

    // Cache resolved SHAs to avoid duplicate API calls
    let mut sha_cache: HashMap<String, Result<String, String>> = HashMap::new();

    for file in &files {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) => {
                summary
                    .errors
                    .push(format!("Failed to read {}: {}", file.display(), e));
                continue;
            }
        };

        let refs = extract_action_refs(&content);
        summary.actions_found += refs.len();

        let mut new_content = content.clone();
        let mut file_changed = false;

        for action_ref in &refs {
            if action_ref.is_sha {
                summary.already_pinned += 1;
                summary.results.push(PinResult {
                    file: file.clone(),
                    action: action_ref.action.clone(),
                    old_ref: action_ref.reference.clone(),
                    new_sha: action_ref.reference.clone(),
                    was_already_pinned: true,
                });
                continue;
            }

            let cache_key = format!("{}@{}", action_ref.action, action_ref.reference);
            let resolved = sha_cache
                .entry(cache_key.clone())
                .or_insert_with(|| {
                    resolve_action_sha_with_token(
                        &agent,
                        &action_ref.action,
                        &action_ref.reference,
                        gh_token,
                    )
                })
                .clone();

            match resolved {
                Ok(sha) => {
                    debug!(
                        "Resolved {}@{} -> {}",
                        action_ref.action, action_ref.reference, sha
                    );

                    // Build the replacement: "uses: action@sha # old_ref"
                    let old_pattern = format!(
                        "{}@{}",
                        action_ref.action, action_ref.reference
                    );
                    let new_pattern = format!(
                        "{}@{} # {}",
                        action_ref.action, sha, action_ref.reference
                    );

                    // Replace in content — need to match the full uses: line pattern
                    // to avoid replacing partial matches
                    new_content = new_content.replace(&old_pattern, &new_pattern);
                    file_changed = true;

                    summary.actions_pinned += 1;
                    summary.results.push(PinResult {
                        file: file.clone(),
                        action: action_ref.action.clone(),
                        old_ref: action_ref.reference.clone(),
                        new_sha: sha,
                        was_already_pinned: false,
                    });
                }
                Err(err) => {
                    let msg = format!(
                        "Failed to resolve {}@{}: {}",
                        action_ref.action, action_ref.reference, err
                    );
                    warn!("{}", msg);
                    summary.errors.push(msg);
                }
            }
        }

        if file_changed && !dry_run {
            if let Err(e) = std::fs::write(file, &new_content) {
                summary
                    .errors
                    .push(format!("Failed to write {}: {}", file.display(), e));
            } else {
                info!("Updated {}", file.display());
            }
        }
    }

    summary
}

/// Resolve with optional GitHub token for authentication
fn resolve_action_sha_with_token(
    agent: &ureq::Agent,
    action: &str,
    reference: &str,
    token: Option<&str>,
) -> Result<String, String> {
    let parts: Vec<&str> = action.splitn(3, '/').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid action format: {}", action));
    }
    let owner = parts[0];
    let repo = parts[1];

    let endpoints = [
        format!(
            "https://api.github.com/repos/{}/{}/git/ref/tags/{}",
            owner, repo, reference
        ),
        format!(
            "https://api.github.com/repos/{}/{}/git/ref/heads/{}",
            owner, repo, reference
        ),
    ];

    for endpoint in &endpoints {
        let mut req = agent
            .get(endpoint)
            .set("User-Agent", "protectinator-supply-chain");

        if let Some(t) = token {
            req = req.set("Authorization", &format!("Bearer {}", t));
        }

        match req.call() {
            Ok(response) => {
                let body: serde_json::Value = response
                    .into_json()
                    .map_err(|e| format!("Failed to parse response: {}", e))?;

                let obj_type = body["object"]["type"]
                    .as_str()
                    .unwrap_or("unknown");
                let sha = body["object"]["sha"]
                    .as_str()
                    .ok_or_else(|| "No SHA in response".to_string())?;

                if obj_type == "tag" {
                    return dereference_tag_with_token(agent, owner, repo, sha, token);
                }

                return Ok(sha.to_string());
            }
            Err(ureq::Error::Status(404, _)) => continue,
            Err(ureq::Error::Status(403, _)) => {
                return Err(
                    "GitHub API rate limit — set GH_TOKEN or GITHUB_TOKEN env var".to_string(),
                );
            }
            Err(e) => return Err(format!("GitHub API error: {}", e)),
        }
    }

    Err(format!(
        "Could not resolve {}@{} — ref not found",
        action, reference
    ))
}

fn dereference_tag_with_token(
    agent: &ureq::Agent,
    owner: &str,
    repo: &str,
    tag_sha: &str,
    token: Option<&str>,
) -> Result<String, String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/git/tags/{}",
        owner, repo, tag_sha
    );

    let mut req = agent
        .get(&url)
        .set("User-Agent", "protectinator-supply-chain");

    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {}", t));
    }

    let response = req
        .call()
        .map_err(|e| format!("Failed to dereference tag: {}", e))?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("Failed to parse tag response: {}", e))?;

    body["object"]["sha"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No commit SHA in tag object".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_is_sha() {
        assert!(is_sha("34e114876b0b11c390a56381ad16ebd13914f8d5"));
        assert!(!is_sha("v4"));
        assert!(!is_sha("main"));
        assert!(!is_sha("stable"));
        assert!(!is_sha("abc123")); // too short
    }

    #[test]
    fn test_extract_action_refs() {
        let content = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/cache@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: some/action@v1.2.3
"#;
        let refs = extract_action_refs(content);
        assert_eq!(refs.len(), 4);

        assert_eq!(refs[0].action, "actions/checkout");
        assert_eq!(refs[0].reference, "v4");
        assert!(!refs[0].is_sha);

        assert_eq!(refs[1].action, "dtolnay/rust-toolchain");
        assert_eq!(refs[1].reference, "stable");
        assert!(!refs[1].is_sha);

        assert_eq!(refs[2].action, "actions/cache");
        assert_eq!(refs[2].reference, "34e114876b0b11c390a56381ad16ebd13914f8d5");
        assert!(refs[2].is_sha);

        assert_eq!(refs[3].action, "some/action");
        assert_eq!(refs[3].reference, "v1.2.3");
        assert!(!refs[3].is_sha);
    }

    #[test]
    fn test_extract_refs_skips_comments() {
        let content = "# uses: evil/action@v1\n      - uses: good/action@v2\n";
        let refs = extract_action_refs(content);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].action, "good/action");
    }

    #[test]
    fn test_discover_workflow_files() {
        let tmp = TempDir::new().unwrap();
        let wf_dir = tmp.path().join(".github/workflows");
        std::fs::create_dir_all(&wf_dir).unwrap();
        std::fs::write(wf_dir.join("ci.yml"), "name: CI").unwrap();
        std::fs::write(wf_dir.join("release.yaml"), "name: Release").unwrap();
        std::fs::write(wf_dir.join("notes.txt"), "not a workflow").unwrap();

        let files = discover_workflow_files(tmp.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_extract_ref_with_inline_comment() {
        let content = "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n";
        let refs = extract_action_refs(content);
        assert_eq!(refs.len(), 1);
        assert!(refs[0].is_sha);
        assert_eq!(
            refs[0].reference,
            "34e114876b0b11c390a56381ad16ebd13914f8d5"
        );
    }
}
