//! Remote Host Security Scanner for Protectinator
//!
//! Scans remote hosts via SSH for security issues including known
//! vulnerabilities (CVEs), rootkit indicators, persistence mechanisms,
//! and hardening issues.
//!
//! Two scanning modes:
//! - **Agent**: Runs protectinator on the remote host and collects JSON results
//! - **Agentless**: Gathers system data via SSH commands and analyzes locally
//!
//! # Example
//!
//! ```no_run
//! use protectinator_remote::{RemoteHost, RemoteScanner, ScanMode};
//!
//! let host = RemoteHost::new("server.example.com")
//!     .with_user("root");
//! let scanner = RemoteScanner::new(host, ScanMode::Agentless);
//! let results = scanner.scan().unwrap();
//! println!("{} findings", results.scan_results.findings.len());
//! ```

pub mod agent;
pub mod agentless;
pub mod scanner;
pub mod ssh;
pub mod types;

pub use scanner::RemoteScanner;
pub use types::{RemoteHost, RemoteScanResults, ScanMode};
