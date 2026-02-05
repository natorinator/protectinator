//! Types for agent and rootkit detection

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Category of detected agent/software
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCategory {
    /// Rootkit or kernel-level malware
    Rootkit,
    /// Mobile Device Management
    Mdm,
    /// Endpoint Detection and Response / Antivirus
    EndpointSecurity,
    /// Remote access tools (TeamViewer, AnyDesk, etc.)
    RemoteAccess,
    /// Configuration management (Puppet, Chef, Ansible, etc.)
    ConfigManagement,
    /// RMM (Remote Monitoring and Management) tools
    Rmm,
}

impl AgentCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentCategory::Rootkit => "rootkit",
            AgentCategory::Mdm => "mdm",
            AgentCategory::EndpointSecurity => "endpoint_security",
            AgentCategory::RemoteAccess => "remote_access",
            AgentCategory::ConfigManagement => "config_management",
            AgentCategory::Rmm => "rmm",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AgentCategory::Rootkit => "Rootkit or kernel-level malware indicator",
            AgentCategory::Mdm => "Mobile Device Management agent",
            AgentCategory::EndpointSecurity => "Endpoint Detection and Response / Antivirus",
            AgentCategory::RemoteAccess => "Remote access software",
            AgentCategory::ConfigManagement => "Configuration management tool",
            AgentCategory::Rmm => "Remote Monitoring and Management tool",
        }
    }
}

impl std::fmt::Display for AgentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Specific agent type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    // Rootkit indicators
    SuspiciousKernelModule,
    HiddenProcess,
    DeletedBinaryProcess,
    LdPreloadHijack,
    SuspiciousKext,

    // MDM
    JamfPro,
    Kandji,
    Mosyle,
    AppleMdm,
    MicrosoftIntune,
    Sccm,
    WorkspaceOne,

    // Endpoint Security
    CrowdStrike,
    SentinelOne,
    MicrosoftDefender,
    CarbonBlack,
    Sophos,
    McAfee,
    Symantec,
    TrendMicro,
    Cylance,
    Tanium,
    OsQuery,

    // Remote Access
    TeamViewer,
    AnyDesk,
    ScreenConnect,
    LogMeIn,
    Splashtop,
    RustDesk,
    VncServer,
    RdpServer,
    SshServer,

    // Config Management
    Puppet,
    Chef,
    Ansible,
    Salt,
    Cfengine,

    // RMM
    Datto,
    NinjaRmm,
    ConnectWise,
    Atera,
    Kaseya,

    // Generic/Unknown
    Unknown,
}

impl AgentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            // Rootkit
            AgentType::SuspiciousKernelModule => "suspicious_kernel_module",
            AgentType::HiddenProcess => "hidden_process",
            AgentType::DeletedBinaryProcess => "deleted_binary_process",
            AgentType::LdPreloadHijack => "ld_preload_hijack",
            AgentType::SuspiciousKext => "suspicious_kext",

            // MDM
            AgentType::JamfPro => "jamf_pro",
            AgentType::Kandji => "kandji",
            AgentType::Mosyle => "mosyle",
            AgentType::AppleMdm => "apple_mdm",
            AgentType::MicrosoftIntune => "microsoft_intune",
            AgentType::Sccm => "sccm",
            AgentType::WorkspaceOne => "workspace_one",

            // Endpoint Security
            AgentType::CrowdStrike => "crowdstrike",
            AgentType::SentinelOne => "sentinelone",
            AgentType::MicrosoftDefender => "microsoft_defender",
            AgentType::CarbonBlack => "carbon_black",
            AgentType::Sophos => "sophos",
            AgentType::McAfee => "mcafee",
            AgentType::Symantec => "symantec",
            AgentType::TrendMicro => "trend_micro",
            AgentType::Cylance => "cylance",
            AgentType::Tanium => "tanium",
            AgentType::OsQuery => "osquery",

            // Remote Access
            AgentType::TeamViewer => "teamviewer",
            AgentType::AnyDesk => "anydesk",
            AgentType::ScreenConnect => "screenconnect",
            AgentType::LogMeIn => "logmein",
            AgentType::Splashtop => "splashtop",
            AgentType::RustDesk => "rustdesk",
            AgentType::VncServer => "vnc_server",
            AgentType::RdpServer => "rdp_server",
            AgentType::SshServer => "ssh_server",

            // Config Management
            AgentType::Puppet => "puppet",
            AgentType::Chef => "chef",
            AgentType::Ansible => "ansible",
            AgentType::Salt => "salt",
            AgentType::Cfengine => "cfengine",

            // RMM
            AgentType::Datto => "datto",
            AgentType::NinjaRmm => "ninja_rmm",
            AgentType::ConnectWise => "connectwise",
            AgentType::Atera => "atera",
            AgentType::Kaseya => "kaseya",

            AgentType::Unknown => "unknown",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            // Rootkit
            AgentType::SuspiciousKernelModule => "Suspicious Kernel Module",
            AgentType::HiddenProcess => "Hidden Process",
            AgentType::DeletedBinaryProcess => "Process with Deleted Binary",
            AgentType::LdPreloadHijack => "LD_PRELOAD Hijack",
            AgentType::SuspiciousKext => "Suspicious Kernel Extension",

            // MDM
            AgentType::JamfPro => "Jamf Pro",
            AgentType::Kandji => "Kandji",
            AgentType::Mosyle => "Mosyle",
            AgentType::AppleMdm => "Apple MDM Profile",
            AgentType::MicrosoftIntune => "Microsoft Intune",
            AgentType::Sccm => "Microsoft SCCM/ConfigMgr",
            AgentType::WorkspaceOne => "VMware Workspace ONE",

            // Endpoint Security
            AgentType::CrowdStrike => "CrowdStrike Falcon",
            AgentType::SentinelOne => "SentinelOne",
            AgentType::MicrosoftDefender => "Microsoft Defender",
            AgentType::CarbonBlack => "Carbon Black",
            AgentType::Sophos => "Sophos",
            AgentType::McAfee => "McAfee",
            AgentType::Symantec => "Symantec/Broadcom",
            AgentType::TrendMicro => "Trend Micro",
            AgentType::Cylance => "Cylance",
            AgentType::Tanium => "Tanium",
            AgentType::OsQuery => "osquery",

            // Remote Access
            AgentType::TeamViewer => "TeamViewer",
            AgentType::AnyDesk => "AnyDesk",
            AgentType::ScreenConnect => "ConnectWise ScreenConnect",
            AgentType::LogMeIn => "LogMeIn",
            AgentType::Splashtop => "Splashtop",
            AgentType::RustDesk => "RustDesk",
            AgentType::VncServer => "VNC Server",
            AgentType::RdpServer => "RDP Server",
            AgentType::SshServer => "SSH Server",

            // Config Management
            AgentType::Puppet => "Puppet Agent",
            AgentType::Chef => "Chef Client",
            AgentType::Ansible => "Ansible",
            AgentType::Salt => "Salt Minion",
            AgentType::Cfengine => "CFEngine",

            // RMM
            AgentType::Datto => "Datto RMM",
            AgentType::NinjaRmm => "NinjaRMM",
            AgentType::ConnectWise => "ConnectWise Automate",
            AgentType::Atera => "Atera",
            AgentType::Kaseya => "Kaseya VSA",

            AgentType::Unknown => "Unknown Agent",
        }
    }

    pub fn category(&self) -> AgentCategory {
        match self {
            AgentType::SuspiciousKernelModule
            | AgentType::HiddenProcess
            | AgentType::DeletedBinaryProcess
            | AgentType::LdPreloadHijack
            | AgentType::SuspiciousKext => AgentCategory::Rootkit,

            AgentType::JamfPro
            | AgentType::Kandji
            | AgentType::Mosyle
            | AgentType::AppleMdm
            | AgentType::MicrosoftIntune
            | AgentType::Sccm
            | AgentType::WorkspaceOne => AgentCategory::Mdm,

            AgentType::CrowdStrike
            | AgentType::SentinelOne
            | AgentType::MicrosoftDefender
            | AgentType::CarbonBlack
            | AgentType::Sophos
            | AgentType::McAfee
            | AgentType::Symantec
            | AgentType::TrendMicro
            | AgentType::Cylance
            | AgentType::Tanium
            | AgentType::OsQuery => AgentCategory::EndpointSecurity,

            AgentType::TeamViewer
            | AgentType::AnyDesk
            | AgentType::ScreenConnect
            | AgentType::LogMeIn
            | AgentType::Splashtop
            | AgentType::RustDesk
            | AgentType::VncServer
            | AgentType::RdpServer
            | AgentType::SshServer => AgentCategory::RemoteAccess,

            AgentType::Puppet
            | AgentType::Chef
            | AgentType::Ansible
            | AgentType::Salt
            | AgentType::Cfengine => AgentCategory::ConfigManagement,

            AgentType::Datto
            | AgentType::NinjaRmm
            | AgentType::ConnectWise
            | AgentType::Atera
            | AgentType::Kaseya => AgentCategory::Rmm,

            AgentType::Unknown => AgentCategory::Rootkit,
        }
    }
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk level for agent detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Informational - expected in enterprise environments
    #[default]
    Info,
    /// Low risk - worth noting but expected
    Low,
    /// Medium risk - should be reviewed
    Medium,
    /// High risk - requires attention
    High,
    /// Critical risk - immediate action required
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// How the agent was detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    /// Running process detected
    Process { pid: Option<u32>, name: String },
    /// File presence at specific path
    FilePresence { path: PathBuf },
    /// Kernel module loaded
    KernelModule { name: String },
    /// MDM profile installed (macOS)
    MdmProfile { name: String },
    /// System service/daemon
    Service { name: String },
    /// Launch item (macOS LaunchAgent/LaunchDaemon, Linux systemd)
    LaunchItem { path: PathBuf },
    /// Process anomaly (hidden, deleted binary, etc.)
    ProcessAnomaly { description: String },
    /// Kernel extension (macOS)
    KernelExtension { name: String },
    /// LD_PRELOAD or library preloading
    LibraryPreload { path: PathBuf },
}

impl DetectionMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionMethod::Process { .. } => "process",
            DetectionMethod::FilePresence { .. } => "file_presence",
            DetectionMethod::KernelModule { .. } => "kernel_module",
            DetectionMethod::MdmProfile { .. } => "mdm_profile",
            DetectionMethod::Service { .. } => "service",
            DetectionMethod::LaunchItem { .. } => "launch_item",
            DetectionMethod::ProcessAnomaly { .. } => "process_anomaly",
            DetectionMethod::KernelExtension { .. } => "kernel_extension",
            DetectionMethod::LibraryPreload { .. } => "library_preload",
        }
    }
}

/// A detected agent entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEntry {
    /// Type of agent detected
    pub agent_type: AgentType,
    /// Category of the agent
    pub category: AgentCategory,
    /// Human-readable name
    pub name: String,
    /// Description of what was found
    pub description: String,
    /// Risk level
    pub risk: RiskLevel,
    /// How it was detected
    pub detection_method: DetectionMethod,
    /// Related file paths
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AgentEntry {
    pub fn new(
        agent_type: AgentType,
        name: impl Into<String>,
        description: impl Into<String>,
        detection_method: DetectionMethod,
    ) -> Self {
        let category = agent_type.category();
        let risk = default_risk_for_category(category);

        Self {
            agent_type,
            category,
            name: name.into(),
            description: description.into(),
            risk,
            detection_method,
            paths: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk = risk;
        self
    }

    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.paths.push(path);
        self
    }

    pub fn with_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.paths.extend(paths);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Get the default risk level for a category
fn default_risk_for_category(category: AgentCategory) -> RiskLevel {
    match category {
        AgentCategory::Rootkit => RiskLevel::High,
        AgentCategory::Mdm => RiskLevel::Info,
        AgentCategory::EndpointSecurity => RiskLevel::Info,
        AgentCategory::RemoteAccess => RiskLevel::Low,
        AgentCategory::ConfigManagement => RiskLevel::Info,
        AgentCategory::Rmm => RiskLevel::Low,
    }
}

/// Summary of agent scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub by_category: HashMap<AgentCategory, usize>,
    pub by_type: HashMap<AgentType, usize>,
}

impl AgentSummary {
    pub fn from_entries(entries: &[AgentEntry]) -> Self {
        let mut summary = Self::default();
        summary.total_findings = entries.len();

        for entry in entries {
            *summary.by_category.entry(entry.category).or_insert(0) += 1;
            *summary.by_type.entry(entry.agent_type).or_insert(0) += 1;

            match entry.risk {
                RiskLevel::Critical => summary.critical_count += 1,
                RiskLevel::High => summary.high_count += 1,
                RiskLevel::Medium => summary.medium_count += 1,
                RiskLevel::Low => summary.low_count += 1,
                RiskLevel::Info => summary.info_count += 1,
            }
        }

        summary
    }

    pub fn has_rootkit_indicators(&self) -> bool {
        self.by_category.get(&AgentCategory::Rootkit).copied().unwrap_or(0) > 0
    }

    pub fn has_critical(&self) -> bool {
        self.critical_count > 0 || self.high_count > 0
    }
}

/// Filter options for agent scanning
#[derive(Debug, Clone, Default)]
pub struct ScanFilter {
    /// Only scan for specific categories
    pub categories: Option<Vec<AgentCategory>>,
    /// Minimum risk level to report
    pub min_risk: Option<RiskLevel>,
    /// Only scan for rootkits
    pub rootkits_only: bool,
}

impl ScanFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rootkits_only() -> Self {
        Self {
            categories: Some(vec![AgentCategory::Rootkit]),
            rootkits_only: true,
            ..Default::default()
        }
    }

    pub fn with_category(mut self, category: AgentCategory) -> Self {
        self.categories
            .get_or_insert_with(Vec::new)
            .push(category);
        self
    }

    pub fn with_min_risk(mut self, risk: RiskLevel) -> Self {
        self.min_risk = Some(risk);
        self
    }

    pub fn matches(&self, entry: &AgentEntry) -> bool {
        // Check category filter
        if let Some(ref cats) = self.categories {
            if !cats.contains(&entry.category) {
                return false;
            }
        }

        // Check risk level
        if let Some(ref min_risk) = self.min_risk {
            if entry.risk < *min_risk {
                return false;
            }
        }

        true
    }
}
