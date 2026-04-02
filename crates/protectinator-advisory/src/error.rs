//! Error types for the advisory crate

use std::fmt;

/// Errors that can occur during advisory operations
#[derive(Debug)]
pub enum AdvisoryError {
    /// HTTP request failed
    Http(String),
    /// JSON/data parsing failed
    Parse(String),
    /// Cache operation failed
    Cache(String),
    /// Requested item not found
    NotFound,
}

impl fmt::Display for AdvisoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvisoryError::Http(msg) => write!(f, "HTTP error: {}", msg),
            AdvisoryError::Parse(msg) => write!(f, "Parse error: {}", msg),
            AdvisoryError::Cache(msg) => write!(f, "Cache error: {}", msg),
            AdvisoryError::NotFound => write!(f, "Not found"),
        }
    }
}

impl std::error::Error for AdvisoryError {}
