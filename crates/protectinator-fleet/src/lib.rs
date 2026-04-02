//! Fleet management and multi-host scanning
//!
//! Orchestrates parallel scanning of remote hosts, containers, and supply-chain
//! repos from a single TOML configuration file.

pub mod config;
pub mod notify;
pub mod runner;
pub mod types;

pub use config::FleetConfig;
pub use runner::FleetRunner;
pub use types::*;
