//! Secret pattern matching engine
//!
//! Two-pass architecture: keyword pre-filter -> regex matching.
//! Patterns organized in three confidence tiers:
//! - Tier 1 (Structural): Known prefix formats, very low false positive
//! - Tier 2 (Keyword-anchored): Require nearby keyword context
//! - Tier 3 (Entropy-only): Generic patterns, require entropy check

use protectinator_core::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::warn;

/// Confidence tier for a secret pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternTier {
    /// Known structural prefix -- regex alone is sufficient
    Structural,
    /// Requires nearby keyword for context
    KeywordAnchored,
    /// Generic pattern -- only apply to config files with entropy check
    EntropyOnly,
}

/// A compiled secret detection pattern
pub struct SecretPattern {
    pub id: String,
    pub name: String,
    pub regex: Regex,
    pub severity: Severity,
    pub description: String,
    /// Keywords for fast pre-filter (at least one must appear in line)
    pub keywords: Vec<String>,
    /// Type of secret (e.g., "aws_access_key", "github_token")
    pub secret_type: String,
    pub tier: PatternTier,
}

/// A match from the pattern engine
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub pattern_id: String,
    pub pattern_name: String,
    pub secret_type: String,
    pub matched_value: String,
    pub severity: Severity,
    pub tier: PatternTier,
    pub description: String,
}

/// Custom pattern definition for TOML loading
#[derive(Debug, Deserialize)]
pub struct CustomPatternDef {
    pub id: String,
    pub name: String,
    pub regex: String,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub secret_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CustomPatternsFile {
    #[serde(default)]
    pub patterns: Vec<CustomPatternDef>,
}

/// Collection of secret patterns with scan methods
pub struct PatternSet {
    patterns: Vec<SecretPattern>,
}

impl PatternSet {
    /// Create a new PatternSet with all built-in patterns
    pub fn builtin() -> Self {
        Self {
            patterns: builtin_patterns(),
        }
    }

    /// Create empty pattern set
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Add custom patterns from a TOML file
    pub fn load_custom(&mut self, path: &Path) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read custom patterns: {}", e))?;
        let file: CustomPatternsFile = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse custom patterns: {}", e))?;

        let mut loaded = 0;
        for def in file.patterns {
            let regex = match Regex::new(&def.regex) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Skipping custom pattern {}: invalid regex: {}", def.id, e);
                    continue;
                }
            };
            let severity = match def.severity.as_deref() {
                Some("critical") => Severity::Critical,
                Some("high") => Severity::High,
                Some("medium") => Severity::Medium,
                Some("low") => Severity::Low,
                _ => Severity::High,
            };
            self.patterns.push(SecretPattern {
                id: def.id.clone(),
                name: def.name,
                regex,
                severity,
                description: def.description.unwrap_or_default(),
                keywords: def.keywords.unwrap_or_default(),
                secret_type: def.secret_type.unwrap_or_else(|| def.id),
                tier: PatternTier::Structural,
            });
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Scan a single line for secret matches (two-pass)
    ///
    /// Pass 1: Check if any keyword from any pattern appears in the line
    /// Pass 2: Apply regex only to patterns whose keywords matched
    pub fn scan_line(&self, line: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        let line_lower = line.to_lowercase();

        for pattern in &self.patterns {
            // Pass 1: Keyword pre-filter
            if !pattern.keywords.is_empty() {
                let has_keyword = pattern
                    .keywords
                    .iter()
                    .any(|kw| line_lower.contains(kw));
                if !has_keyword {
                    continue;
                }
            }

            // Pass 2: Regex match
            if let Some(m) = pattern.regex.find(line) {
                matches.push(SecretMatch {
                    pattern_id: pattern.id.clone(),
                    pattern_name: pattern.name.clone(),
                    secret_type: pattern.secret_type.clone(),
                    matched_value: m.as_str().to_string(),
                    severity: pattern.severity,
                    tier: pattern.tier,
                    description: pattern.description.clone(),
                });
            }
        }

        matches
    }

    /// Get the number of patterns
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// List all pattern names and IDs (for the `patterns` subcommand)
    pub fn list_patterns(&self) -> Vec<PatternInfo> {
        self.patterns
            .iter()
            .map(|p| PatternInfo {
                id: p.id.clone(),
                name: p.name.clone(),
                secret_type: p.secret_type.clone(),
                severity: p.severity,
                tier: p.tier,
                description: p.description.clone(),
            })
            .collect()
    }
}

/// Pattern info for listing (no regex)
#[derive(Debug, Clone, Serialize)]
pub struct PatternInfo {
    pub id: String,
    pub name: String,
    pub secret_type: String,
    pub severity: Severity,
    pub tier: PatternTier,
    pub description: String,
}

/// Helper to create a pattern concisely
fn pat(
    id: &str,
    name: &str,
    regex: &str,
    severity: Severity,
    desc: &str,
    keywords: &[&str],
    secret_type: &str,
    tier: PatternTier,
) -> SecretPattern {
    SecretPattern {
        id: id.to_string(),
        name: name.to_string(),
        regex: Regex::new(regex).unwrap_or_else(|e| panic!("Bad regex for {}: {}", id, e)),
        severity,
        description: desc.to_string(),
        keywords: keywords.iter().map(|s| s.to_string()).collect(),
        secret_type: secret_type.to_string(),
        tier,
    }
}

/// Build all built-in secret patterns
fn builtin_patterns() -> Vec<SecretPattern> {
    use PatternTier::*;
    use Severity::*;

    vec![
        // ====================================
        // TIER 1: STRUCTURAL (regex alone, very low FP)
        // ====================================

        // AWS
        pat(
            "aws-access-key-id",
            "AWS Access Key ID",
            r"(?:^|[^A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)",
            Critical,
            "AWS access key ID with known prefix",
            &["akia", "asia", "abia", "acca"],
            "aws_access_key",
            Structural,
        ),

        // GitHub
        pat(
            "github-pat",
            "GitHub Personal Access Token",
            r"ghp_[A-Za-z0-9]{36,}",
            Critical,
            "GitHub personal access token",
            &["ghp_"],
            "github_pat",
            Structural,
        ),
        pat(
            "github-oauth",
            "GitHub OAuth Token",
            r"gho_[A-Za-z0-9]{36,}",
            Critical,
            "GitHub OAuth access token",
            &["gho_"],
            "github_oauth",
            Structural,
        ),
        pat(
            "github-app",
            "GitHub App Token",
            r"(?:ghs|ghu|ghr)_[A-Za-z0-9]{36,}",
            Critical,
            "GitHub app installation/user/refresh token",
            &["ghs_", "ghu_", "ghr_"],
            "github_app",
            Structural,
        ),
        pat(
            "github-fine-grained",
            "GitHub Fine-Grained PAT",
            r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
            Critical,
            "GitHub fine-grained personal access token",
            &["github_pat_"],
            "github_fine_grained_pat",
            Structural,
        ),

        // GitLab
        pat(
            "gitlab-pat",
            "GitLab Personal Access Token",
            r"glpat-[A-Za-z0-9\-_]{20,}",
            Critical,
            "GitLab personal access token",
            &["glpat-"],
            "gitlab_pat",
            Structural,
        ),

        // Anthropic
        pat(
            "anthropic-api-key",
            "Anthropic API Key",
            r"sk-ant-api03-[A-Za-z0-9\-_]{80,}",
            Critical,
            "Anthropic Claude API key",
            &["sk-ant-api03-"],
            "anthropic_api_key",
            Structural,
        ),

        // OpenAI
        pat(
            "openai-api-key",
            "OpenAI API Key",
            r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{20,}",
            Critical,
            "OpenAI API key (project/service/admin)",
            &["sk-proj-", "sk-svcacct-", "sk-admin-"],
            "openai_api_key",
            Structural,
        ),
        pat(
            "openai-api-key-legacy",
            "OpenAI API Key (Legacy)",
            r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
            Critical,
            "OpenAI API key (legacy format with T3BlbkFJ marker)",
            &["t3blbkfj"],
            "openai_api_key",
            Structural,
        ),

        // Stripe
        pat(
            "stripe-live-secret",
            "Stripe Live Secret Key",
            r"sk_live_[A-Za-z0-9]{24,}",
            Critical,
            "Stripe live secret API key",
            &["sk_live_"],
            "stripe_live_secret",
            Structural,
        ),
        pat(
            "stripe-test-secret",
            "Stripe Test Secret Key",
            r"sk_test_[A-Za-z0-9]{24,}",
            Medium,
            "Stripe test secret API key",
            &["sk_test_"],
            "stripe_test_secret",
            Structural,
        ),
        pat(
            "stripe-restricted",
            "Stripe Restricted Key",
            r"rk_(?:live|test)_[A-Za-z0-9]{24,}",
            High,
            "Stripe restricted API key",
            &["rk_live_", "rk_test_"],
            "stripe_restricted",
            Structural,
        ),

        // Slack
        pat(
            "slack-bot-token",
            "Slack Bot Token",
            r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}",
            Critical,
            "Slack bot user OAuth token",
            &["xoxb-"],
            "slack_bot_token",
            Structural,
        ),
        pat(
            "slack-user-token",
            "Slack User Token",
            r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}",
            Critical,
            "Slack user OAuth token",
            &["xoxp-"],
            "slack_user_token",
            Structural,
        ),
        pat(
            "slack-app-token",
            "Slack App Token",
            r"xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[a-z0-9]{64}",
            High,
            "Slack app-level token",
            &["xapp-"],
            "slack_app_token",
            Structural,
        ),
        pat(
            "slack-webhook",
            "Slack Webhook URL",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
            High,
            "Slack incoming webhook URL",
            &["hooks.slack.com"],
            "slack_webhook",
            Structural,
        ),

        // SendGrid
        pat(
            "sendgrid-api-key",
            "SendGrid API Key",
            r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}",
            High,
            "SendGrid API key",
            &["sg."],
            "sendgrid_api_key",
            Structural,
        ),

        // npm
        pat(
            "npm-token",
            "npm Access Token",
            r"npm_[A-Za-z0-9]{36,}",
            High,
            "npm access token",
            &["npm_"],
            "npm_token",
            Structural,
        ),

        // PyPI
        pat(
            "pypi-token",
            "PyPI API Token",
            r"pypi-AgEI[A-Za-z0-9\-_]{50,}",
            High,
            "PyPI API token",
            &["pypi-agei"],
            "pypi_token",
            Structural,
        ),

        // DigitalOcean
        pat(
            "digitalocean-pat",
            "DigitalOcean PAT",
            r"dop_v1_[a-f0-9]{64}",
            High,
            "DigitalOcean personal access token",
            &["dop_v1_"],
            "digitalocean_pat",
            Structural,
        ),

        // Hugging Face
        pat(
            "huggingface-token",
            "Hugging Face Token",
            r"hf_[A-Za-z0-9]{34,}",
            High,
            "Hugging Face access token",
            &["hf_"],
            "huggingface_token",
            Structural,
        ),

        // Discord
        pat(
            "discord-webhook",
            "Discord Webhook URL",
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9\-_]{60,}",
            High,
            "Discord webhook URL",
            &["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
            "discord_webhook",
            Structural,
        ),

        // Private keys
        pat(
            "private-key-pem",
            "Private Key (PEM)",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            Critical,
            "PEM-encoded private key block",
            &["-----begin", "private key"],
            "private_key",
            Structural,
        ),

        // JWT
        pat(
            "jwt-token",
            "JWT Token",
            r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}",
            Medium,
            "JSON Web Token (may contain claims)",
            &["eyj"],
            "jwt",
            Structural,
        ),

        // NuGet
        pat(
            "nuget-api-key",
            "NuGet API Key",
            r"oy2[A-Za-z0-9]{43}",
            High,
            "NuGet API key",
            &["oy2"],
            "nuget_api_key",
            Structural,
        ),

        // Telegram
        pat(
            "telegram-bot-token",
            "Telegram Bot Token",
            r"[0-9]{5,}:AA[A-Za-z0-9\-_]{33}",
            High,
            "Telegram bot API token",
            &["telegram", "bot"],
            "telegram_bot_token",
            KeywordAnchored,
        ),

        // ====================================
        // TIER 2: KEYWORD-ANCHORED (require context)
        // ====================================

        // AWS Secret Key
        pat(
            "aws-secret-key",
            "AWS Secret Access Key",
            r"(?i)(?:aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret)\s*[=:]\s*['\x22]?([A-Za-z0-9/+=]{40})['\x22]?",
            Critical,
            "AWS secret access key in config/env assignment",
            &["aws_secret", "aws-secret", "secret_access_key", "secret-access-key"],
            "aws_secret_key",
            KeywordAnchored,
        ),

        // Google API Key
        pat(
            "google-api-key",
            "Google API Key",
            r"AIza[A-Za-z0-9\-_]{35}",
            High,
            "Google API key",
            &["aiza"],
            "google_api_key",
            Structural,
        ),

        // Twilio
        pat(
            "twilio-account-sid",
            "Twilio Account SID",
            r"AC[a-f0-9]{32}",
            High,
            "Twilio account SID",
            &["twilio", "ac"],
            "twilio_account_sid",
            KeywordAnchored,
        ),

        // Datadog
        pat(
            "datadog-api-key",
            "Datadog API Key",
            r"(?i)(?:datadog|dd)[_\-]?(?:api[_\-]?key|app[_\-]?key)\s*[=:]\s*['\x22]?([a-f0-9]{32,40})['\x22]?",
            High,
            "Datadog API or application key",
            &["datadog", "dd_api", "dd_app", "dd-api", "dd-app"],
            "datadog_api_key",
            KeywordAnchored,
        ),

        // Mailgun
        pat(
            "mailgun-api-key",
            "Mailgun API Key",
            r"key-[a-f0-9]{32}",
            High,
            "Mailgun API key",
            &["mailgun", "key-"],
            "mailgun_api_key",
            KeywordAnchored,
        ),

        // Database connection strings
        pat(
            "database-url-password",
            "Database URL with Password",
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:]+:[^@\s]{3,}@[^\s]+",
            Critical,
            "Database connection URL with embedded credentials",
            &["://", "postgres", "mysql", "mongodb", "redis", "amqp"],
            "database_url",
            Structural,
        ),

        // Generic password in URL
        pat(
            "url-with-credentials",
            "URL with Embedded Credentials",
            r"https?://[^:]+:[^@\s]{8,}@[^\s]+",
            High,
            "HTTP(S) URL with embedded username:password",
            &["://", "@"],
            "url_credentials",
            KeywordAnchored,
        ),

        // ====================================
        // TIER 3: ENTROPY-ONLY (config files only)
        // ====================================

        // Generic secret assignments
        pat(
            "generic-secret-assignment",
            "Generic Secret Assignment",
            r"(?i)(?:password|passwd|secret|token|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?token|private[_\-]?key|client[_\-]?secret)\s*[=:]\s*['\x22]?([A-Za-z0-9\-_/+=\.]{12,})['\x22]?",
            Medium,
            "Possible secret in key=value assignment",
            &["password", "passwd", "secret", "token", "api_key", "apikey", "api-key",
              "auth_token", "auth-token", "access_token", "access-token", "private_key",
              "private-key", "client_secret", "client-secret"],
            "generic_secret",
            EntropyOnly,
        ),

        // Base64-encoded Authorization header
        pat(
            "authorization-basic",
            "Basic Auth Header",
            r"(?i)(?:authorization|auth)\s*[=:]\s*['\x22]?Basic\s+[A-Za-z0-9+/]{20,}={0,2}['\x22]?",
            High,
            "Base64-encoded Basic authentication credentials",
            &["authorization", "basic"],
            "basic_auth",
            KeywordAnchored,
        ),

        // Bearer token
        pat(
            "authorization-bearer",
            "Bearer Token",
            r"(?i)(?:authorization|auth)\s*[=:]\s*['\x22]?Bearer\s+[A-Za-z0-9\-_\.]{20,}['\x22]?",
            High,
            "Bearer authentication token",
            &["authorization", "bearer"],
            "bearer_token",
            KeywordAnchored,
        ),

        // npmrc auth
        pat(
            "npmrc-auth",
            "npmrc Auth Token",
            r"//[^/]+/:_authToken=.{10,}",
            High,
            "npm registry authentication token in .npmrc",
            &["_authtoken"],
            "npmrc_auth",
            Structural,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns() -> PatternSet {
        PatternSet::builtin()
    }

    #[test]
    fn test_builtin_patterns_compile() {
        let ps = patterns();
        assert!(ps.len() > 30, "Expected 30+ patterns, got {}", ps.len());
    }

    #[test]
    fn test_aws_access_key() {
        let ps = patterns();
        let matches = ps.scan_line("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(!matches.is_empty(), "Should match AWS access key");
        assert_eq!(matches[0].secret_type, "aws_access_key");
    }

    #[test]
    fn test_github_pat() {
        let ps = patterns();
        let matches = ps.scan_line("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(!matches.is_empty(), "Should match GitHub PAT");
        assert_eq!(matches[0].secret_type, "github_pat");
    }

    #[test]
    fn test_anthropic_key() {
        let ps = patterns();
        let line = format!("ANTHROPIC_API_KEY=sk-ant-api03-{}", "a".repeat(80));
        let matches = ps.scan_line(&line);
        assert!(!matches.is_empty(), "Should match Anthropic key");
        assert_eq!(matches[0].secret_type, "anthropic_api_key");
    }

    #[test]
    fn test_stripe_live_key() {
        let ps = patterns();
        let key = format!("stripe_key = {}{}", "sk_live_", "TESTKEY000000000FAKEFAKE00");
        let matches = ps.scan_line(&key);
        assert!(!matches.is_empty(), "Should match Stripe live key");
        assert_eq!(matches[0].secret_type, "stripe_live_secret");
    }

    #[test]
    fn test_slack_webhook() {
        let ps = patterns();
        let url = format!(
            "WEBHOOK=https://hooks.slack.com/services/{}",
            "TXXXXXXXX/BXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX"
        );
        let matches = ps.scan_line(&url);
        assert!(!matches.is_empty(), "Should match Slack webhook");
    }

    #[test]
    fn test_private_key() {
        let ps = patterns();
        let matches = ps.scan_line("-----BEGIN RSA PRIVATE KEY-----");
        assert!(!matches.is_empty(), "Should match private key");
        assert_eq!(matches[0].secret_type, "private_key");
    }

    #[test]
    fn test_database_url() {
        let ps = patterns();
        let matches = ps.scan_line("DATABASE_URL=postgresql://user:s3cret_pass@db.host:5432/mydb");
        assert!(!matches.is_empty(), "Should match database URL with password");
        assert_eq!(matches[0].secret_type, "database_url");
    }

    #[test]
    fn test_jwt() {
        let ps = patterns();
        let matches = ps.scan_line("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IjqbaZ7lm");
        assert!(!matches.is_empty(), "Should match JWT");
    }

    #[test]
    fn test_generic_secret() {
        let ps = patterns();
        let matches = ps.scan_line("API_KEY=abcdef123456GHIJKL");
        assert!(!matches.is_empty(), "Should match generic secret");
    }

    #[test]
    fn test_no_false_positive_normal_code() {
        let ps = patterns();
        let matches = ps.scan_line("let result = function_call(arg1, arg2);");
        assert!(matches.is_empty(), "Should not match normal code");
    }

    #[test]
    fn test_no_false_positive_comment() {
        let ps = patterns();
        let matches = ps.scan_line("// This is a comment about the API");
        assert!(matches.is_empty(), "Should not match comments without secrets");
    }

    #[test]
    fn test_sendgrid_key() {
        let ps = patterns();
        let matches = ps.scan_line("SENDGRID_KEY=SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQR");
        assert!(!matches.is_empty(), "Should match SendGrid key");
    }

    #[test]
    fn test_gitlab_pat() {
        let ps = patterns();
        let matches = ps.scan_line("GITLAB_TOKEN=glpat-abcdefghijklmnopqrst");
        assert!(!matches.is_empty(), "Should match GitLab PAT");
    }

    #[test]
    fn test_huggingface_token() {
        let ps = patterns();
        let line = format!("HF_TOKEN=hf_{}", "a".repeat(34));
        let matches = ps.scan_line(&line);
        assert!(!matches.is_empty(), "Should match HF token");
    }

    #[test]
    fn test_npm_token() {
        let ps = patterns();
        let line = format!("NPM_TOKEN=npm_{}", "A".repeat(36));
        let matches = ps.scan_line(&line);
        assert!(!matches.is_empty(), "Should match npm token");
    }

    #[test]
    fn test_discord_webhook() {
        let ps = patterns();
        let matches = ps.scan_line(&format!(
            "DISCORD=https://discord.com/api/webhooks/12345678901234567/{}",
            "a".repeat(68)
        ));
        assert!(!matches.is_empty(), "Should match Discord webhook");
    }

    #[test]
    fn test_bearer_token() {
        let ps = patterns();
        let matches = ps.scan_line("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert!(!matches.is_empty(), "Should match Bearer token");
    }

    #[test]
    fn test_pattern_count() {
        let ps = patterns();
        assert!(ps.len() >= 35, "Should have at least 35 built-in patterns, got {}", ps.len());
    }

    #[test]
    fn test_custom_patterns_loading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(&path, r#"
[[patterns]]
id = "my-secret"
name = "My Custom Secret"
regex = "MYSECRET_[A-Z]{10}"
severity = "high"
keywords = ["mysecret_"]
"#).unwrap();

        let mut ps = PatternSet::empty();
        let loaded = ps.load_custom(&path).unwrap();
        assert_eq!(loaded, 1);

        let matches = ps.scan_line("TOKEN=MYSECRET_ABCDEFGHIJ");
        assert!(!matches.is_empty());
    }
}
