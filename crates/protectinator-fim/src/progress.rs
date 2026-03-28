//! Progress reporting trait for FIM operations
//!
//! When the `provider` feature is enabled, this re-exports
//! `protectinator_core::ProgressReporter`. Otherwise, it provides
//! a standalone trait with the same interface.

#[cfg(feature = "provider")]
pub use protectinator_core::ProgressReporter;

#[cfg(not(feature = "provider"))]
pub trait ProgressReporter: Send + Sync {
    /// Called when a new phase begins
    fn phase_started(&self, name: &str, total_items: usize);
    /// Called when progress is made within a phase
    fn progress(&self, current: usize, message: &str);
    /// Called when a phase completes
    fn phase_completed(&self, name: &str);
    /// Called on error
    fn error(&self, module: &str, message: &str);
}
