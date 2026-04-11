//! Package Manager Binary Integrity Monitoring for Protectinator
//!
//! Monitors binaries installed by system package managers (apt, Homebrew) for
//! unauthorized modifications. Detects tampered binaries, unauthorized package
//! sources, and suspicious changes.
//!
//! # Supported Package Managers
//!
//! - **apt/dpkg** (Debian/Ubuntu): Verifies binaries against dpkg md5sums manifests,
//!   audits package sources for unsigned or HTTP repositories
//! - **Homebrew** (macOS/Linux): Creates and verifies SHA256 baselines for installed
//!   binaries, detects tampering vs legitimate upgrades
//!
//! # Example
//!
//! ```no_run
//! use protectinator_pkgmon::{PkgMonScanner, PkgMonConfig};
//! use std::path::Path;
//!
//! let config = PkgMonConfig::default();
//! let scanner = PkgMonScanner::new(config);
//! let findings = scanner.scan().unwrap();
//! for finding in &findings {
//!     println!("{}: {}", finding.severity, finding.title);
//! }
//! ```

pub mod apt;
pub mod baseline;
pub mod homebrew;
pub mod homebrew_audit;
pub mod scanner;
pub mod types;

pub use scanner::PkgMonScanner;
pub use types::{
    BaselineEntry, MonitoredBinary, PackageManager, PkgMonConfig, PkgMonContext,
};
