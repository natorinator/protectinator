//! IoT device types and scan configuration

use protectinator_container::ContainerOsInfo;
use protectinator_core::ScanResults;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Raspberry Pi model identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PiModel {
    Pi1,
    Pi2,
    Pi3,
    Pi4,
    Pi5,
    PiZero,
    PiZero2,
    PiZeroW,
    Pi400,
    PiCM4,
    Unknown(String),
}

impl fmt::Display for PiModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PiModel::Pi1 => write!(f, "Raspberry Pi 1"),
            PiModel::Pi2 => write!(f, "Raspberry Pi 2"),
            PiModel::Pi3 => write!(f, "Raspberry Pi 3"),
            PiModel::Pi4 => write!(f, "Raspberry Pi 4"),
            PiModel::Pi5 => write!(f, "Raspberry Pi 5"),
            PiModel::PiZero => write!(f, "Raspberry Pi Zero"),
            PiModel::PiZero2 => write!(f, "Raspberry Pi Zero 2"),
            PiModel::PiZeroW => write!(f, "Raspberry Pi Zero W"),
            PiModel::Pi400 => write!(f, "Raspberry Pi 400"),
            PiModel::PiCM4 => write!(f, "Raspberry Pi Compute Module 4"),
            PiModel::Unknown(s) => write!(f, "Raspberry Pi ({})", s),
        }
    }
}

/// Type of IoT device being scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IotDeviceType {
    RaspberryPi(PiModel),
    GenericARM,
    GenericLinux,
}

impl fmt::Display for IotDeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IotDeviceType::RaspberryPi(model) => write!(f, "{}", model),
            IotDeviceType::GenericARM => write!(f, "Generic ARM Device"),
            IotDeviceType::GenericLinux => write!(f, "Generic Linux Device"),
        }
    }
}

/// How the IoT device is being scanned
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IotScanMode {
    /// Running directly on the device
    Local,
    /// Scanning a mounted SD card or filesystem
    Mounted,
}

impl fmt::Display for IotScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IotScanMode::Local => write!(f, "local"),
            IotScanMode::Mounted => write!(f, "mounted"),
        }
    }
}

/// Represents an IoT device being scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotDevice {
    /// User-provided name for the device
    pub name: String,
    /// Detected device type
    pub device_type: IotDeviceType,
    /// Scan mode
    pub scan_mode: IotScanMode,
    /// Root filesystem path (/ for local, mount point for mounted)
    pub root_path: PathBuf,
    /// Detected OS info
    pub os_info: Option<ContainerOsInfo>,
}

/// Complete scan results for an IoT device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotScanResults {
    /// Device that was scanned
    pub device: IotDevice,
    /// Scan results with all findings
    pub scan_results: ScanResults,
}
