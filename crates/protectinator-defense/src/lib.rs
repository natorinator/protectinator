//! Defensive software audit checks for Protectinator
//!
//! Detects missing or misconfigured defensive software:
//! - Firewalls (ufw, firewalld, nftables, iptables)
//! - Brute-force protection (sshguard, fail2ban, crowdsec)
//! - Open ports vs allowed services
//! - Automatic security updates

pub mod checks;
pub mod audit;

pub use audit::{DefenseAudit, DefenseAuditResult, HostContext};
