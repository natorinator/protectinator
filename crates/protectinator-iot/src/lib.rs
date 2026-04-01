//! IoT & Raspberry Pi Security Scanner for Protectinator
//!
//! Scans Raspberry Pi and other ARM/IoT devices for security issues including
//! tampered binaries, boot partition backdoors, PAM module injection, IoT-specific
//! malware (Mirai, Hajime), and default credentials.
//!
//! Supports three scan modes:
//! - **Local**: Running directly on the Pi
//! - **Mounted**: Scanning a mounted SD card from the host (`--root /mnt/pi`)
//! - **SSHFS**: Scanning over sshfs (`--root /mnt/sshfs-pi`)
//!
//! Reuses container checks (packages, rootkit, persistence, hardening, suid, os_version)
//! plus 11 IoT-specific checks.
//!
//! # Example
//!
//! ```no_run
//! use protectinator_iot::{IotScanner, IotScanMode};
//! use std::path::PathBuf;
//!
//! let scanner = IotScanner::new(
//!     "mypi".to_string(),
//!     IotScanMode::Mounted,
//!     PathBuf::from("/mnt/pi"),
//! );
//! let results = scanner.scan();
//! println!("{} findings", results.scan_results.findings.len());
//! ```

pub mod checks;
pub mod platform;
pub mod scanner;
#[cfg(feature = "ssh")]
pub mod ssh_gather;
pub mod types;

pub use platform::detect_device;
pub use scanner::IotScanner;
pub use types::{IotDevice, IotDeviceType, IotScanMode, IotScanResults, PiModel};
