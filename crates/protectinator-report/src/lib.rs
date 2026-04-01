//! PDF report generation for Protectinator scan results
//!
//! Generates executive summary + detailed findings reports from scan data.
//! Used by both the web API and CLI.

mod pdf;

pub use pdf::generate_pdf_report;
