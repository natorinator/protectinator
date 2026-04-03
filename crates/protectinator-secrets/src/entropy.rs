//! Shannon entropy calculation for secret detection
//!
//! High-entropy strings often indicate secrets, tokens, or encoded data.
//! Standard thresholds from detect-secrets and gitleaks:
//! - Hex strings: > 3.0 bits
//! - Base64 strings: > 4.5 bits
//! - Alphanumeric strings: > 3.5 bits

use std::collections::HashMap;

/// Character set classification for entropy thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Hex,
    Base64,
    Alphanumeric,
}

/// Default entropy thresholds by character set
impl Charset {
    pub fn default_threshold(&self) -> f64 {
        match self {
            Charset::Hex => 3.0,
            Charset::Base64 => 4.5,
            Charset::Alphanumeric => 3.5,
        }
    }
}

/// Calculate Shannon entropy of a string
///
/// Returns bits of entropy per character. Higher values indicate more randomness.
/// Typical values:
/// - English text: ~1.0-2.0
/// - UUIDs: ~3.0
/// - Random hex: ~3.5-4.0
/// - Random base64: ~5.0-6.0
/// - API keys/tokens: ~4.5-6.0
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Detect the likely character set of a string
pub fn detect_charset(s: &str) -> Charset {
    let is_hex = s.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex && s.len() >= 16 {
        return Charset::Hex;
    }

    let is_base64 = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if is_base64 && s.contains(|c: char| c == '+' || c == '/' || c == '=') {
        return Charset::Base64;
    }

    Charset::Alphanumeric
}

/// Check if a string has high entropy for its detected character set
pub fn is_high_entropy(s: &str, min_entropy: Option<f64>) -> bool {
    if s.len() < 8 {
        return false; // Too short to be meaningful
    }

    // Filter out common false positives
    if is_false_positive(s) {
        return false;
    }

    let entropy = shannon_entropy(s);
    let charset = detect_charset(s);
    let threshold = min_entropy.unwrap_or_else(|| charset.default_threshold());

    entropy > threshold
}

/// Check for common false positive patterns
fn is_false_positive(s: &str) -> bool {
    let lower = s.to_lowercase();

    // UUID pattern (8-4-4-4-12 hex)
    if s.len() == 36
        && s.chars().filter(|&c| c == '-').count() == 4
        && s.replace('-', "").chars().all(|c| c.is_ascii_hexdigit())
    {
        return true;
    }

    // Git SHA (40 or 7 hex chars, pure hex)
    if (s.len() == 40 || s.len() == 7) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // Common placeholder values
    let placeholders = [
        "example", "changeme", "password", "xxxxxxxx", "your_", "insert_",
        "replace_", "todo", "fixme", "placeholder", "dummy", "test",
        "sample", "default", "change_me", "update_me",
    ];
    for p in &placeholders {
        if lower.contains(p) {
            return true;
        }
    }

    // Repeated characters (e.g., "aaaaaaaaaa", "0000000000")
    if s.len() >= 8 {
        let first = s.chars().next().unwrap();
        if s.chars().all(|c| c == first) {
            return true;
        }
    }

    // Sequential patterns
    if lower == "abcdefghijklmnop" || lower == "0123456789abcdef" {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_entropy_two_chars() {
        let e = shannon_entropy("ab");
        assert!((e - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_entropy_english_text() {
        let e = shannon_entropy("the quick brown fox jumps over the lazy dog");
        assert!(e > 1.0 && e < 5.0, "English text entropy: {}", e);
    }

    #[test]
    fn test_entropy_random_hex() {
        // High-entropy hex string (simulated random)
        let e = shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0");
        assert!(e > 3.0, "Random hex entropy: {}", e);
    }

    #[test]
    fn test_entropy_api_key_like() {
        // Simulated API key - moderate entropy (real keys have higher)
        let key = format!("{}{}", "sk_live_", "Xr8Kq2mNpW5vJtLz9Y3hBcDf");
        let e = shannon_entropy(&key);
        assert!(e > 3.5, "API key entropy: {}", e);
    }

    #[test]
    fn test_detect_charset_hex() {
        assert_eq!(detect_charset("a1b2c3d4e5f6a7b8"), Charset::Hex);
    }

    #[test]
    fn test_detect_charset_base64() {
        assert_eq!(detect_charset("SGVsbG8gV29ybGQ="), Charset::Base64);
    }

    #[test]
    fn test_detect_charset_alphanum() {
        let key = format!("{}{}", "sk_live_", "4eC39HqLyjWDar");
        assert_eq!(detect_charset(&key), Charset::Alphanumeric);
    }

    #[test]
    fn test_is_high_entropy_uuid_false_positive() {
        assert!(!is_high_entropy(
            "550e8400-e29b-41d4-a716-446655440000",
            None
        ));
    }

    #[test]
    fn test_is_high_entropy_git_sha_false_positive() {
        assert!(!is_high_entropy(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            None
        ));
    }

    #[test]
    fn test_is_high_entropy_placeholder_false_positive() {
        assert!(!is_high_entropy("your_api_key_here_example", None));
    }

    #[test]
    fn test_is_high_entropy_repeated_chars() {
        assert!(!is_high_entropy("aaaaaaaaaaaaaaaa", None));
    }

    #[test]
    fn test_is_high_entropy_too_short() {
        assert!(!is_high_entropy("abc", None));
    }

    #[test]
    fn test_false_positive_uuid() {
        assert!(is_false_positive("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_false_positive_git_sha() {
        assert!(is_false_positive("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"));
    }
}
