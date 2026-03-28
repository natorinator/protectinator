//! Error types for standalone FIM usage
//!
//! When the `provider` feature is disabled, these types replace
//! `protectinator_core::ProtectinatorError` and `protectinator_core::Result`.

use std::fmt;

/// FIM error type (standalone, no protectinator-core dependency)
#[derive(Debug)]
pub enum FimError {
    /// I/O error
    Io(std::io::Error),
    /// Configuration error
    Config(String),
    /// Database error
    Database(String),
    /// Resource not found
    NotFound(String),
    /// Hash mismatch
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for FimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FimError::Io(e) => write!(f, "IO error: {}", e),
            FimError::Config(s) => write!(f, "Configuration error: {}", s),
            FimError::Database(s) => write!(f, "Database error: {}", s),
            FimError::NotFound(s) => write!(f, "Not found: {}", s),
            FimError::HashMismatch { path, expected, actual } => {
                write!(f, "Hash mismatch for {}: expected {}, got {}", path, expected, actual)
            }
        }
    }
}

impl std::error::Error for FimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FimError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FimError {
    fn from(e: std::io::Error) -> Self {
        FimError::Io(e)
    }
}

/// FIM result type alias
pub type FimResult<T> = std::result::Result<T, FimError>;

// --- Bridging to protectinator-core when the provider feature is enabled ---

#[cfg(feature = "provider")]
impl From<FimError> for protectinator_core::ProtectinatorError {
    fn from(e: FimError) -> Self {
        match e {
            FimError::Io(e) => protectinator_core::ProtectinatorError::Io(e),
            FimError::Config(s) => protectinator_core::ProtectinatorError::Config(s),
            FimError::Database(s) => protectinator_core::ProtectinatorError::Database(s),
            FimError::NotFound(s) => protectinator_core::ProtectinatorError::NotFound(s),
            FimError::HashMismatch { path, expected, actual } => {
                protectinator_core::ProtectinatorError::HashMismatch { path, expected, actual }
            }
        }
    }
}

#[cfg(feature = "provider")]
impl From<protectinator_core::ProtectinatorError> for FimError {
    fn from(e: protectinator_core::ProtectinatorError) -> Self {
        match e {
            protectinator_core::ProtectinatorError::Io(e) => FimError::Io(e),
            protectinator_core::ProtectinatorError::Config(s) => FimError::Config(s),
            protectinator_core::ProtectinatorError::Database(s) => FimError::Database(s),
            protectinator_core::ProtectinatorError::NotFound(s) => FimError::NotFound(s),
            protectinator_core::ProtectinatorError::HashMismatch { path, expected, actual } => {
                FimError::HashMismatch { path, expected, actual }
            }
            other => FimError::Config(other.to_string()),
        }
    }
}
