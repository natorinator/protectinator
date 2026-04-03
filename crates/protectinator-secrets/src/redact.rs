//! Secret value redaction
//!
//! Ensures actual secret values are never displayed in findings or logs.

/// Redact a secret value, showing only first 4 and last 2 characters
///
/// Examples:
/// - "sk-ant-api03-abc123xyz" -> "sk-a...yz"
/// - "AKIAIOSFODNN7EXAMPLE" -> "AKIA...LE"
/// - "short" -> "shor..."
/// - "" -> "***"
pub fn redact_secret(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "***".to_string();
    }
    if value.len() <= 6 {
        return format!("{}...", &value[..value.len().min(4)]);
    }
    // Show first 4, last 2
    let start = &value[..4];
    let end = &value[value.len() - 2..];
    format!("{}...{}", start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_normal() {
        assert_eq!(redact_secret("sk-ant-api03-abc123xyz"), "sk-a...yz");
    }

    #[test]
    fn test_redact_aws_key() {
        assert_eq!(redact_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA...LE");
    }

    #[test]
    fn test_redact_short() {
        assert_eq!(redact_secret("short"), "shor...");
    }

    #[test]
    fn test_redact_very_short() {
        assert_eq!(redact_secret("ab"), "ab...");
    }

    #[test]
    fn test_redact_empty() {
        assert_eq!(redact_secret(""), "***");
    }

    #[test]
    fn test_redact_with_whitespace() {
        assert_eq!(redact_secret("  sk-ant-api03-abc123xyz  "), "sk-a...yz");
    }
}
