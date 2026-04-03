//! Secrets and credential scanning for Protectinator
//!
//! Detects leaked secrets, API keys, tokens, and credentials in:
//! - Configuration files (.env, YAML, TOML, JSON)
//! - Shell history (bash, zsh, fish)
//! - Environment variables and systemd services
//! - Git commit history

pub mod checks;
pub mod entropy;
pub mod patterns;
pub mod redact;
pub mod scanner;

pub use entropy::{shannon_entropy, is_high_entropy, Charset};
pub use patterns::{SecretPattern, PatternSet, PatternTier, SecretMatch};
pub use redact::redact_secret;
pub use scanner::SecretsScanner;
