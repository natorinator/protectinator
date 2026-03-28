//! Container Security Scanner for Protectinator
//!
//! Scans nspawn (and later Docker) containers from the outside by examining
//! the container's filesystem from the host. Checks for rootkits, outdated
//! packages, persistence mechanisms, hardening issues, and more.
//!
//! # Example
//!
//! ```no_run
//! use protectinator_container::{discover, ContainerScanner};
//!
//! let containers = discover::list_nspawn_containers();
//! for container in &containers {
//!     println!("Found container: {} ({})", container.name, container.state);
//!     let scanner = ContainerScanner::new();
//!     let results = scanner.scan(container);
//!     println!("  {} findings", results.scan_results.findings.len());
//! }
//! ```

pub mod checks;
pub mod discover;
pub mod filesystem;
pub mod packages;
pub mod scanner;
pub mod types;

pub use scanner::ContainerScanner;
pub use types::{Container, ContainerOsInfo, ContainerRuntime, ContainerScanResults, ContainerState};
