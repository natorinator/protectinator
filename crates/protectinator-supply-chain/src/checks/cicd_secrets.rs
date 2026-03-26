//! CI/CD secrets exposure check
//!
//! Checks for secrets that may be exposed in the repository or CI environment,
//! including committed .env files, Docker/Kubernetes credentials, and dangerous
//! patterns in GitHub Actions workflow files.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use walkdir::WalkDir;

/// .env file names to search for
const ENV_FILE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
];

/// Critical secret variable names (if committed to git)
const CRITICAL_SECRET_VARS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "PYPI_PUBLISH",
];

/// High-severity secret patterns
const HIGH_SECRET_PATTERNS: &[&str] = &["PRIVATE_KEY", "SECRET_KEY"];

/// Medium-severity generic secret suffixes
const GENERIC_SECRET_SUFFIXES: &[&str] = &["_TOKEN=", "_SECRET=", "_KEY=", "_PASSWORD="];

/// Checks for secrets exposure in the repository and CI configuration
pub struct CicdSecretsCheck;

impl SupplyChainCheck for CicdSecretsCheck {
    fn id(&self) -> &str {
        "supply-chain-cicd-secrets"
    }

    fn name(&self) -> &str {
        "CI/CD Secrets Exposure Check"
    }

    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        check_env_files(fs, ctx, &mut findings);
        check_workflow_secret_patterns(fs, ctx, &mut findings);
        check_docker_config(fs, ctx, &mut findings);
        check_kube_config(fs, ctx, &mut findings);

        findings
    }
}

/// Check for .env files that may be committed or unprotected
fn check_env_files(
    _fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    let root = &ctx.root;

    // Walk max_depth=4 looking for .env files
    for entry in WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let Some(name) = entry.file_name().to_str() else {
            continue;
        };

        if !ENV_FILE_NAMES.iter().any(|n| *n == name) {
            continue;
        }

        let path = entry.path();
        let path_str = path.display().to_string();

        let is_tracked = is_git_tracked(path);
        let is_gitignored = is_in_gitignore(root, name);

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        if is_tracked {
            // Committed .env file — check contents for specific secrets
            check_env_content_committed(&path_str, &content, &mut *findings);
        } else if !is_gitignored {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-secrets-env-no-gitignore-{}",
                        sanitize_path(&path_str)
                    ),
                    format!("Secret file not in .gitignore: {}", name),
                    format!(
                        "File {} is not tracked by git but is also not in .gitignore — \
                         it may be accidentally committed in the future",
                        path_str
                    ),
                    Severity::Medium,
                    make_source(),
                )
                .with_resource(&path_str)
                .with_remediation(format!(
                    "Add '{}' to .gitignore to prevent accidental commits",
                    name
                )),
            );
        }
    }
}

/// Check committed .env file content for high-value secrets
fn check_env_content_committed(
    path: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check for critical secret variables
        for var in CRITICAL_SECRET_VARS {
            if trimmed.starts_with(var) && has_non_empty_value(trimmed) {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-secrets-committed-{}-{}",
                            sanitize(var),
                            sanitize_path(path)
                        ),
                        format!("Critical secret committed to git: {}", var),
                        format!(
                            "File {} is tracked by git and contains {} with a non-empty value",
                            path, var
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Remove {} from {} and rotate the credential immediately. \
                         Use environment variables or a secrets manager instead.",
                        var, path
                    )),
                );
                break; // One finding per variable per file
            }
        }

        // Check for DATABASE_URL with password
        if trimmed.starts_with("DATABASE_URL=") {
            let value = &trimmed["DATABASE_URL=".len()..];
            if value.contains(':') && value.contains('@') {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-secrets-committed-database-url-{}",
                            sanitize_path(path)
                        ),
                        format!("Database URL with credentials committed: {}", path),
                        format!(
                            "File {} is tracked by git and contains DATABASE_URL with embedded credentials",
                            path
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Remove DATABASE_URL from {} and use a secrets manager. Rotate the database password.",
                        path
                    )),
                );
            }
        }

        // Check for high-severity patterns
        for pattern in HIGH_SECRET_PATTERNS {
            if trimmed.contains(pattern) && has_non_empty_value(trimmed) {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-secrets-committed-{}-{}",
                            sanitize(pattern),
                            sanitize_path(path)
                        ),
                        format!("Secret key committed to git: {}", path),
                        format!(
                            "File {} is tracked by git and contains a {} value",
                            path, pattern
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Remove secret from {} and rotate the key. Use environment variables or a secrets manager.",
                        path
                    )),
                );
                break;
            }
        }

        // Check for generic secret suffixes
        for suffix in GENERIC_SECRET_SUFFIXES {
            if trimmed.contains(suffix) {
                let value_start = trimmed.find(suffix).unwrap() + suffix.len();
                let value = trimmed[value_start..].trim();
                if !value.is_empty() && value != "\"\"" && value != "''" {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-secrets-committed-generic-{}",
                                sanitize_path(path)
                            ),
                            format!("Potential secret committed to git: {}", path),
                            format!(
                                "File {} is tracked by git and contains a variable matching \
                                 secret pattern '{}'",
                                path,
                                suffix.trim_end_matches('=')
                            ),
                            Severity::Medium,
                            make_source(),
                        )
                        .with_resource(path),
                    );
                    break; // One generic finding per file
                }
            }
        }
    }
}

/// Check GitHub Actions workflow files for secret-related issues
fn check_workflow_secret_patterns(
    _fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    let workflow_dir = ctx.root.join(".github/workflows");
    if !workflow_dir.is_dir() {
        return;
    }

    let Ok(entries) = std::fs::read_dir(&workflow_dir) else {
        return;
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

        // Check for ${{ github.token }} used directly in run: blocks
        check_github_token_in_run(&path_str, &content, findings);

        // Check for secrets dumped to logs
        check_secrets_echo(&path_str, &content, findings);
    }
}

/// Check for `${{ github.token }}` used directly in run: blocks
fn check_github_token_in_run(
    path: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    // Simple heuristic: look for run: blocks that contain ${{ github.token }}
    let mut in_run_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Handle both "run:" and "- run:" (YAML list item)
        let is_run_line = trimmed.starts_with("run:") || trimmed.starts_with("- run:");
        if is_run_line {
            in_run_block = true;
            // Check inline run
            if trimmed.contains("${{ github.token }}") {
                emit_github_token_finding(path, findings);
                in_run_block = false;
            }
            continue;
        }

        if in_run_block {
            // We're in a multiline run block
            if !trimmed.is_empty()
                && !line.starts_with(' ')
                && !line.starts_with('\t')
                && !trimmed.starts_with('-')
                && !trimmed.starts_with('#')
            {
                // Left the run block (new YAML key at same/higher indent)
                in_run_block = false;
            }

            if trimmed.contains("${{ github.token }}") {
                emit_github_token_finding(path, findings);
                in_run_block = false;
            }
        }
    }
}

fn emit_github_token_finding(path: &str, findings: &mut Vec<Finding>) {
    findings.push(
        Finding::new(
            format!(
                "supply-chain-secrets-github-token-run-{}",
                sanitize_path(path)
            ),
            format!("github.token used in run block: {}", path),
            format!(
                "Workflow {} uses ${{{{ github.token }}}} directly in a run: block — \
                 use env: mapping instead to avoid token exposure in logs",
                path
            ),
            Severity::Low,
            make_source(),
        )
        .with_resource(path)
        .with_remediation(
            "Map the token to an environment variable using `env:` instead of \
             using ${{ github.token }} directly in shell commands",
        ),
    );
}

/// Check for `echo ${{ secrets.` in run blocks
fn check_secrets_echo(path: &str, content: &str, findings: &mut Vec<Finding>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("echo") && trimmed.contains("${{ secrets.") {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-secrets-echo-{}",
                        sanitize_path(path)
                    ),
                    format!("Secret echoed to logs: {}", path),
                    format!(
                        "Workflow {} echoes a secret value, which will appear in CI logs",
                        path
                    ),
                    Severity::High,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(
                    "Never echo secrets in CI workflows. Use `add-mask` if you must \
                     reference a secret in output.",
                ),
            );
            return; // One finding per file
        }
    }
}

/// Check for Docker config with embedded credentials
fn check_docker_config(
    fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    for home in &ctx.user_homes {
        let config_path = format!("{}/.docker/config.json", home.display());
        let Ok(content) = fs.read_to_string(&config_path) else {
            continue;
        };

        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) else {
            tracing::debug!("Failed to parse Docker config: {}", config_path);
            continue;
        };

        if let Some(auths) = doc.get("auths").and_then(|a| a.as_object()) {
            for (registry, auth_val) in auths {
                // Check if there's an "auth" field (base64-encoded credentials)
                if auth_val
                    .as_object()
                    .and_then(|o| o.get("auth"))
                    .and_then(|a| a.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    findings.push(
                        Finding::new(
                            format!(
                                "supply-chain-secrets-docker-auth-{}",
                                sanitize(registry)
                            ),
                            format!("Docker registry credentials: {}", config_path),
                            format!(
                                "File {} contains base64-encoded credentials for registry '{}'",
                                config_path, registry
                            ),
                            Severity::High,
                            make_source(),
                        )
                        .with_resource(&config_path)
                        .with_remediation(
                            "Use a Docker credential helper instead of storing credentials \
                             in config.json. Run `docker logout` and reconfigure with a \
                             credential store.",
                        )
                        .with_metadata("registry", serde_json::json!(registry)),
                    );
                }
            }
        }
    }
}

/// Check for Kubernetes config with embedded tokens/certificates
fn check_kube_config(
    fs: &ContainerFs,
    ctx: &SupplyChainContext,
    findings: &mut Vec<Finding>,
) {
    for home in &ctx.user_homes {
        let config_path = format!("{}/.kube/config", home.display());
        let Ok(content) = fs.read_to_string(&config_path) else {
            continue;
        };

        // Check for embedded credentials in kubeconfig
        let has_embedded_creds = content.contains("client-certificate-data:")
            || content.contains("client-key-data:")
            || content.contains("token:");

        if has_embedded_creds {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-secrets-kube-config-{}",
                        sanitize(&home.display().to_string())
                    ),
                    format!("Kubernetes config with embedded credentials: {}", config_path),
                    format!(
                        "File {} contains embedded certificates or tokens",
                        config_path
                    ),
                    Severity::Medium,
                    make_source(),
                )
                .with_resource(&config_path)
                .with_remediation(
                    "Use external credential providers or exec-based authentication \
                     instead of embedding credentials in kubeconfig",
                ),
            );
        }
    }
}

/// Check if a file is tracked by git
fn is_git_tracked(path: &std::path::Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };

    std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch"])
        .arg(path)
        .current_dir(parent)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if a filename pattern is in .gitignore
fn is_in_gitignore(root: &std::path::Path, filename: &str) -> bool {
    // Check .gitignore at root
    let gitignore_path = root.join(".gitignore");
    if let Ok(content) = std::fs::read_to_string(&gitignore_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Simple pattern matching: exact match or glob
            if trimmed == filename
                || trimmed == format!("/{}", filename)
                || trimmed == ".env*"
                || trimmed == ".env.*"
                || (trimmed.ends_with('*') && filename.starts_with(trimmed.trim_end_matches('*')))
            {
                return true;
            }
        }
    }
    false
}

/// Check if a line has a non-empty value after the `=` sign
fn has_non_empty_value(line: &str) -> bool {
    if let Some(pos) = line.find('=') {
        let value = line[pos + 1..].trim().trim_matches('"').trim_matches('\'');
        !value.is_empty()
    } else {
        false
    }
}

/// Create FindingSource for secrets checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "secrets".to_string(),
        ecosystem: None,
    }
}

/// Sanitize a string for use in finding IDs
fn sanitize(s: &str) -> String {
    s.replace('/', "-")
        .replace('.', "-")
        .replace(':', "-")
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
    fn test_docker_config_credentials_high() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "home/testuser/.docker/config.json",
            r#"{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"}}}"#,
        );

        let check = CicdSecretsCheck;
        let findings = check.run(&fs, &ctx);
        let docker_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Docker registry"))
            .collect();
        assert_eq!(docker_findings.len(), 1);
        assert_eq!(docker_findings[0].severity, Severity::High);
    }

    #[test]
    fn test_kube_config_embedded_creds_medium() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            "home/testuser/.kube/config",
            "apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.example.com\nusers:\n- user:\n    client-certificate-data: LS0tLS1...\n    client-key-data: LS0tLS1...\n",
        );

        let check = CicdSecretsCheck;
        let findings = check.run(&fs, &ctx);
        let kube_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Kubernetes"))
            .collect();
        assert_eq!(kube_findings.len(), 1);
        assert_eq!(kube_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_workflow_echo_secrets_high() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            ".github/workflows/deploy.yml",
            "name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.MY_SECRET }}\n",
        );

        let check = CicdSecretsCheck;
        let findings = check.run(&fs, &ctx);
        let echo_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("echoed to logs"))
            .collect();
        assert_eq!(echo_findings.len(), 1);
        assert_eq!(echo_findings[0].severity, Severity::High);
    }

    #[test]
    fn test_github_token_in_run_low() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        write_file(
            &tmp,
            ".github/workflows/ci.yml",
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -H \"Authorization: token ${{ github.token }}\" https://api.github.com\n",
        );

        let check = CicdSecretsCheck;
        let findings = check.run(&fs, &ctx);
        let token_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("github.token"))
            .collect();
        assert_eq!(token_findings.len(), 1);
        assert_eq!(token_findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_env_file_not_in_gitignore() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let ctx = make_ctx(&tmp);

        // Create .env file (not tracked by git, no .gitignore)
        write_file(&tmp, ".env", "SECRET_KEY=mysecret\n");

        let check = CicdSecretsCheck;
        let findings = check.run(&fs, &ctx);
        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains(".gitignore"))
            .collect();
        assert_eq!(env_findings.len(), 1);
        assert_eq!(env_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_clean_environment_no_findings() {
        let tmp = TempDir::new().unwrap();
        let fs = make_fs(&tmp);
        let mut ctx = make_ctx(&tmp);
        ctx.user_homes.clear();

        let check = CicdSecretsCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }
}
