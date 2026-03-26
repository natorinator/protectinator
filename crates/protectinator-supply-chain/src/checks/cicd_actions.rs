//! GitHub Actions security audit
//!
//! Scans `.github/workflows/` directories for security issues including
//! unpinned action references, overly permissive permissions, dangerous
//! trigger patterns, and secrets exposure risks.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use walkdir::WalkDir;

/// GitHub-owned action org prefix (lower risk for mutable refs)
const GITHUB_OWNED_PREFIX: &str = "actions/";

/// Checks GitHub Actions workflow files for security issues
pub struct CicdActionsCheck;

impl SupplyChainCheck for CicdActionsCheck {
    fn id(&self) -> &str {
        "supply-chain-cicd-actions"
    }

    fn name(&self) -> &str {
        "GitHub Actions Security Audit"
    }

    fn run(&self, _fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Walk max_depth=3 from ctx.root looking for .github directories
        let workflow_dirs = discover_workflow_dirs(&ctx.root);

        for workflow_dir in &workflow_dirs {
            let Ok(entries) = std::fs::read_dir(workflow_dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };

                if !name.ends_with(".yml") && !name.ends_with(".yaml") {
                    continue;
                }

                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };

                let path_str = path.display().to_string();
                let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
                    tracing::debug!("Failed to parse YAML: {}", path_str);
                    continue;
                };

                check_unpinned_actions(&doc, &path_str, &mut findings);
                check_permissions(&doc, &path_str, &mut findings);
                check_dangerous_triggers(&doc, &path_str, &content, &mut findings);
                check_secrets_exposure(&doc, &path_str, &content, &mut findings);
            }
        }

        findings
    }
}

/// Discover `.github/workflows/` directories under root (max_depth=3)
fn discover_workflow_dirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();

    for entry in WalkDir::new(root)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_dir() && entry.file_name() == ".github" {
            let workflows = entry.path().join("workflows");
            if workflows.is_dir() {
                dirs.push(workflows);
            }
        }
    }

    dirs
}

/// Check all `uses:` values in the workflow for unpinned actions
fn check_unpinned_actions(
    doc: &serde_yaml::Value,
    path: &str,
    findings: &mut Vec<Finding>,
) {
    let uses_refs = extract_uses_refs(doc);

    for uses_ref in &uses_refs {
        // Format: owner/repo@ref or owner/repo/path@ref
        let Some(at_pos) = uses_ref.rfind('@') else {
            continue;
        };

        let action_name = &uses_ref[..at_pos];
        let ref_part = &uses_ref[at_pos + 1..];
        let is_github_owned = action_name.starts_with(GITHUB_OWNED_PREFIX);

        // SHA-pinned: 40-char hex
        if ref_part.len() == 40 && ref_part.chars().all(|c| c.is_ascii_hexdigit()) {
            // Good practice — Info
            findings.push(
                Finding::new(
                    format!("supply-chain-cicd-action-pinned-{}", sanitize(action_name)),
                    format!("SHA-pinned action: {}", uses_ref),
                    format!(
                        "Action {} in {} is SHA-pinned (good practice)",
                        uses_ref, path
                    ),
                    Severity::Info,
                    make_source(),
                )
                .with_resource(path),
            );
            continue;
        }

        // Mutable refs: vN, main, master (no dots — just major version tags or branch names)
        let is_mutable = is_mutable_ref(ref_part);

        if is_mutable {
            if is_github_owned {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-cicd-action-mutable-github-{}",
                            sanitize(action_name)
                        ),
                        format!("GitHub-owned action with mutable ref: {}", uses_ref),
                        format!(
                            "Action {} in {} uses a mutable ref '{}'. Lower risk since GitHub-owned, \
                             but SHA-pinning is still recommended.",
                            uses_ref, path, ref_part
                        ),
                        Severity::Info,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Pin {} to a specific SHA for reproducibility",
                        uses_ref
                    )),
                );
            } else {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-cicd-action-mutable-{}",
                            sanitize(action_name)
                        ),
                        format!("Unpinned GitHub Action uses mutable ref: {}", uses_ref),
                        format!(
                            "Action {} in {} uses mutable ref '{}' — vulnerable to tag \
                             rewriting attack like TeamPCP/Trivy",
                            uses_ref, path, ref_part
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Pin {} to a specific commit SHA to prevent tag rewriting attacks",
                        uses_ref
                    ))
                    .with_reference(
                        "https://blog.stealthsecurity.io/the-anatomy-of-a-github-actions-supply-chain-attack",
                    ),
                );
            }
            continue;
        }

        // Exact version tag (contains dots, like v1.2.3) — not SHA-pinned
        if ref_part.contains('.') {
            let severity = if is_github_owned {
                Severity::Info
            } else {
                Severity::Medium
            };
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-cicd-action-version-tag-{}",
                        sanitize(action_name)
                    ),
                    format!("Action uses version tag but not SHA-pinned: {}", uses_ref),
                    format!(
                        "Action {} in {} uses exact version tag '{}' but not SHA-pinned — \
                         tags can be force-pushed",
                        uses_ref, path, ref_part
                    ),
                    severity,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(format!(
                    "Pin {} to the commit SHA corresponding to tag {}",
                    uses_ref, ref_part
                )),
            );
        }
    }
}

/// Check for overly permissive permissions in the workflow
fn check_permissions(
    doc: &serde_yaml::Value,
    path: &str,
    findings: &mut Vec<Finding>,
) {
    let map = match doc.as_mapping() {
        Some(m) => m,
        None => return,
    };

    let has_top_level_permissions = map
        .get(serde_yaml::Value::String("permissions".to_string()))
        .is_some();

    if !has_top_level_permissions {
        // Check if any job has permissions
        let has_job_permissions = check_job_level_permissions(doc);
        if !has_job_permissions {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-cicd-no-permissions-{}",
                        sanitize_path(path)
                    ),
                    format!("No permissions block: {}", path),
                    format!(
                        "Workflow {} has no permissions block — defaults to read-write for all scopes",
                        path
                    ),
                    Severity::Medium,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(
                    "Add a top-level `permissions: {}` block and grant only needed scopes",
                ),
            );
        }
    }

    // Check top-level permissions value
    if let Some(perms) = map.get(serde_yaml::Value::String("permissions".to_string())) {
        check_permissions_value(perms, path, "top-level", findings);
    }

    // Check job-level permissions
    if let Some(jobs) = map
        .get(serde_yaml::Value::String("jobs".to_string()))
        .and_then(|j| j.as_mapping())
    {
        for (job_key, job_val) in jobs {
            let job_name = job_key.as_str().unwrap_or("unknown");
            if let Some(perms) = job_val
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::String("permissions".to_string())))
            {
                check_permissions_value(perms, path, &format!("job '{}'", job_name), findings);
            }
        }
    }
}

/// Check a permissions value for overly permissive settings
fn check_permissions_value(
    perms: &serde_yaml::Value,
    path: &str,
    scope: &str,
    findings: &mut Vec<Finding>,
) {
    // String value: "write-all" or "read-all"
    if let Some(s) = perms.as_str() {
        if s == "write-all" {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-cicd-write-all-{}-{}",
                        sanitize(scope),
                        sanitize_path(path)
                    ),
                    format!("write-all permissions in {}: {}", scope, path),
                    format!(
                        "Workflow {} has `permissions: write-all` at {} — grants write access to all scopes",
                        path, scope
                    ),
                    Severity::High,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation("Replace `permissions: write-all` with specific scopes"),
            );
        }
        return;
    }

    // Mapping value — check for `contents: write` at top level
    if let Some(map) = perms.as_mapping() {
        if let Some(contents) = map.get(serde_yaml::Value::String("contents".to_string())) {
            if contents.as_str() == Some("write") && scope == "top-level" {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-cicd-contents-write-{}",
                            sanitize_path(path)
                        ),
                        format!("contents: write at top level: {}", path),
                        format!(
                            "Workflow {} grants `contents: write` at top level — allows modifying repository contents",
                            path
                        ),
                        Severity::Medium,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(
                        "Move `contents: write` to specific jobs that need it, or use read-only at top level",
                    ),
                );
            }
        }

        // Check if all permissions are read-only or empty
        let all_readonly = map.is_empty()
            || map.values().all(|v| {
                v.as_str()
                    .map(|s| s == "read" || s == "none")
                    .unwrap_or(false)
            });
        if all_readonly {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-cicd-readonly-{}-{}",
                        sanitize(scope),
                        sanitize_path(path)
                    ),
                    format!("Read-only permissions at {}: {}", scope, path),
                    format!(
                        "Workflow {} has read-only or empty permissions at {} (good practice)",
                        path, scope
                    ),
                    Severity::Info,
                    make_source(),
                )
                .with_resource(path),
            );
        }
    }
}

/// Check if any job in the workflow has a permissions block
fn check_job_level_permissions(doc: &serde_yaml::Value) -> bool {
    let Some(jobs) = doc
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::String("jobs".to_string())))
        .and_then(|j| j.as_mapping())
    else {
        return false;
    };

    jobs.values().any(|job| {
        job.as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("permissions".to_string())))
            .is_some()
    })
}

/// Check for dangerous trigger patterns
fn check_dangerous_triggers(
    doc: &serde_yaml::Value,
    path: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(on) = doc
        .as_mapping()
        .and_then(|m| {
            m.get(serde_yaml::Value::String("on".to_string()))
                .or_else(|| m.get(serde_yaml::Value::Bool(true)))
        })
    else {
        return;
    };

    let has_prt = has_trigger(on, "pull_request_target");
    let has_wd = has_trigger(on, "workflow_dispatch");

    if has_prt {
        // Check if any step checks out the PR head
        let checks_out_pr_head = content.contains("github.event.pull_request.head.sha")
            || content.contains("refs/pull/");

        if checks_out_pr_head {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-cicd-prt-checkout-{}",
                        sanitize_path(path)
                    ),
                    format!("pull_request_target with PR head checkout: {}", path),
                    format!(
                        "Workflow {} uses pull_request_target with PR head checkout — \
                         allows code execution from forks",
                        path
                    ),
                    Severity::Critical,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(
                    "Avoid checking out PR head ref in pull_request_target workflows. \
                     Use pull_request trigger instead, or ensure the checkout ref is \
                     from the base branch.",
                )
                .with_reference(
                    "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
                ),
            );
        }
    }

    if has_wd {
        // Check if workflow_dispatch has required inputs
        let has_inputs = check_workflow_dispatch_inputs(on);
        if !has_inputs {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-cicd-wd-no-inputs-{}",
                        sanitize_path(path)
                    ),
                    format!("workflow_dispatch with no required inputs: {}", path),
                    format!(
                        "Workflow {} uses workflow_dispatch with no required inputs — \
                         can be triggered by anyone with write access",
                        path
                    ),
                    Severity::Low,
                    make_source(),
                )
                .with_resource(path),
            );
        }
    }
}

/// Check if a trigger key is present in the `on:` block
fn has_trigger(on: &serde_yaml::Value, trigger: &str) -> bool {
    match on {
        serde_yaml::Value::String(s) => s == trigger,
        serde_yaml::Value::Sequence(seq) => seq.iter().any(|v| v.as_str() == Some(trigger)),
        serde_yaml::Value::Mapping(map) => {
            map.contains_key(serde_yaml::Value::String(trigger.to_string()))
        }
        _ => false,
    }
}

/// Check if workflow_dispatch has any inputs defined
fn check_workflow_dispatch_inputs(on: &serde_yaml::Value) -> bool {
    let Some(map) = on.as_mapping() else {
        return false;
    };

    let Some(wd) = map.get(serde_yaml::Value::String("workflow_dispatch".to_string())) else {
        return false;
    };

    let Some(wd_map) = wd.as_mapping() else {
        return false;
    };

    wd_map
        .get(serde_yaml::Value::String("inputs".to_string()))
        .and_then(|i| i.as_mapping())
        .map(|m| !m.is_empty())
        .unwrap_or(false)
}

/// Check for secrets exposure patterns
fn check_secrets_exposure(
    doc: &serde_yaml::Value,
    path: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    // Check for `secrets: inherit`
    check_secrets_inherit(doc, path, findings);

    // Check for secrets used in env that feed into run blocks
    // This is done via raw content scanning since YAML structure is complex
    if content.contains("${{ secrets.") && content.contains("run:") {
        findings.push(
            Finding::new(
                format!(
                    "supply-chain-cicd-secrets-in-env-{}",
                    sanitize_path(path)
                ),
                format!("Secrets referenced in workflow: {}", path),
                format!(
                    "Workflow {} references secrets and has run blocks — common pattern \
                     but ensure secrets are passed via env: mapping, not directly in shell commands",
                    path
                ),
                Severity::Low,
                make_source(),
            )
            .with_resource(path),
        );
    }
}

/// Check for `secrets: inherit` in workflow calls
fn check_secrets_inherit(
    doc: &serde_yaml::Value,
    path: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(jobs) = doc
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::String("jobs".to_string())))
        .and_then(|j| j.as_mapping())
    else {
        return;
    };

    for (_job_key, job_val) in jobs {
        let Some(job_map) = job_val.as_mapping() else {
            continue;
        };

        if let Some(secrets) = job_map.get(serde_yaml::Value::String("secrets".to_string())) {
            if secrets.as_str() == Some("inherit") {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-cicd-secrets-inherit-{}",
                            sanitize_path(path)
                        ),
                        format!("secrets: inherit in workflow: {}", path),
                        format!(
                            "Workflow {} uses `secrets: inherit` — inherits all secrets to called workflow",
                            path
                        ),
                        Severity::Medium,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(
                        "Explicitly pass only the secrets needed by the called workflow \
                         instead of using `secrets: inherit`",
                    ),
                );
                return; // One finding per workflow is enough
            }
        }
    }
}

/// Extract all `uses:` string values from a workflow document recursively
fn extract_uses_refs(value: &serde_yaml::Value) -> Vec<String> {
    let mut refs = Vec::new();
    collect_uses(value, &mut refs);
    refs
}

fn collect_uses(value: &serde_yaml::Value, refs: &mut Vec<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, val) in map {
                if key.as_str() == Some("uses") {
                    if let Some(s) = val.as_str() {
                        refs.push(s.to_string());
                    }
                } else {
                    collect_uses(val, refs);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                collect_uses(item, refs);
            }
        }
        _ => {}
    }
}

/// Check if a ref is a mutable reference (branch name or major version tag)
fn is_mutable_ref(ref_part: &str) -> bool {
    // Branch names
    if ref_part == "main" || ref_part == "master" || ref_part == "develop" {
        return true;
    }
    // Major version tags like v1, v2 (no dots)
    if ref_part.starts_with('v') && !ref_part.contains('.') {
        let rest = &ref_part[1..];
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Create the standard FindingSource for CI/CD checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "cicd".to_string(),
        ecosystem: None,
    }
}

/// Sanitize an action name for use in finding IDs
fn sanitize(s: &str) -> String {
    s.replace('/', "-")
        .replace('@', "-")
        .replace('.', "-")
        .replace(' ', "-")
        .replace('\'', "")
}

/// Sanitize a file path for use in finding IDs
fn sanitize_path(path: &str) -> String {
    path.replace('/', "-").trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_workflow(tmp: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
        let workflow_dir = tmp.path().join(".github/workflows");
        std::fs::create_dir_all(&workflow_dir).unwrap();
        let path = workflow_dir.join(filename);
        std::fs::write(&path, content).unwrap();
        tmp.path().to_path_buf()
    }

    fn make_ctx(root: &std::path::Path) -> SupplyChainContext {
        SupplyChainContext {
            root: root.to_path_buf(),
            user_homes: Vec::new(),
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        }
    }

    fn make_fs(root: &std::path::Path) -> ContainerFs {
        ContainerFs::new(root)
    }

    #[test]
    fn test_unpinned_mutable_action_high() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@v1
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let high_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        assert_eq!(high_findings.len(), 1);
        assert!(high_findings[0].title.contains("mutable ref"));
    }

    #[test]
    fn test_sha_pinned_action_info() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let pinned: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("SHA-pinned"))
            .collect();
        assert_eq!(pinned.len(), 1);
        assert_eq!(pinned[0].severity, Severity::Info);
    }

    #[test]
    fn test_github_owned_mutable_is_info() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let checkout_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("actions/checkout"))
            .collect();
        assert_eq!(checkout_findings.len(), 1);
        assert_eq!(checkout_findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_no_permissions_medium() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let perm_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("No permissions"))
            .collect();
        assert_eq!(perm_findings.len(), 1);
        assert_eq!(perm_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_prt_with_checkout_critical() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: pull_request_target
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert_eq!(critical.len(), 1);
        assert!(critical[0].title.contains("pull_request_target"));
    }

    #[test]
    fn test_secrets_inherit_medium() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: push
permissions: {}
jobs:
  call-workflow:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let inherit: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("secrets: inherit"))
            .collect();
        assert_eq!(inherit.len(), 1);
        assert_eq!(inherit[0].severity, Severity::Medium);
    }

    #[test]
    fn test_version_tag_not_sha_medium() {
        let tmp = TempDir::new().unwrap();
        let root = setup_workflow(
            &tmp,
            "ci.yml",
            r#"
name: CI
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@v1.2.3
"#,
        );
        let ctx = make_ctx(&root);
        let fs = make_fs(&root);
        let check = CicdActionsCheck;
        let findings = check.run(&fs, &ctx);
        let version_tag: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("version tag"))
            .collect();
        assert_eq!(version_tag.len(), 1);
        assert_eq!(version_tag[0].severity, Severity::Medium);
    }
}
