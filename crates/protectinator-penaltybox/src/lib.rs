//! Protectinator Penalty Box
//!
//! Auto-sandbox vulnerable packages using Gaol/Landlock restrictions.
//! Maps CVE characteristics to filesystem and network restrictions,
//! generates gaol sandbox commands, and manages penalty box profiles.

pub mod discovery;
pub mod manager;
pub mod profile;
pub mod restrictions;

pub use discovery::PackageDiscovery;
pub use manager::PenaltyBoxManager;
pub use profile::PenaltyBoxProfile;
pub use restrictions::{EnforcementLevel, NetworkPolicy, SandboxRestrictions};
