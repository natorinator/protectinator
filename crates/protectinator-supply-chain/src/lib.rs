//! Software Supply Chain Security Scanner for Protectinator
//!
//! Scans developer workstations and CI/CD systems for software supply chain
//! compromises including known vulnerabilities (via OSV), malicious package
//! indicators, lock file integrity issues, and CI/CD misconfigurations.
//!
//! # Example
//!
//! ```no_run
//! use protectinator_supply_chain::SupplyChainScanner;
//! use std::path::PathBuf;
//!
//! let scanner = SupplyChainScanner::new(PathBuf::from("/"));
//! let results = scanner.scan();
//! println!("{} findings", results.scan_results.findings.len());
//! ```

pub mod checks;
pub mod gaol;
pub mod history;
pub mod lockfile;
pub mod osv;
pub mod pin;
pub mod scanner;
pub mod types;

pub use scanner::SupplyChainScanner;
pub use types::{Ecosystem, SupplyChainContext, SupplyChainScanResults};
