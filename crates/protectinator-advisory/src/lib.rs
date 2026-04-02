//! CVE intelligence and remediation guidance for Protectinator
//!
//! Integrates with the Debian Security Tracker to provide actionability
//! classification and enrichment for vulnerability findings.

pub mod cache;
pub mod classify;
pub mod debian;
mod error;

pub use cache::AdvisoryCache;
pub use classify::{ActionabilityClass, CveIntelligence};
pub use debian::{DebianCveEntry, DebianTracker, SubState, TrackerStatus};
pub use error::AdvisoryError;
