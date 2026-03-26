//! User systemd service audit
//!
//! Scans user-level systemd service and timer units for indicators of
//! persistence, supply chain compromise, or known malware (e.g., TeamPCP).

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use regex::Regex;

/// Known legitimate user systemd services (prefix match)
const LEGITIMATE_SERVICE_PREFIXES: &[&str] = &[
    "pipewire",
    "pulseaudio",
    "dbus",
    "gpg-agent",
    "ssh-agent",
    "gnome-",
    "xdg-",
    "at-spi-",
    "tracker-",
    "evolution-",
    "gvfs-",
    "dconf-service",
    "plasma-",
    "kded5",
    "syncthing",
    "emacs",
    "vscode-",
    "wireplumber",
    "xdg-document-portal",
    "xdg-desktop-portal",
    "xdg-permission-store",
    "p11-kit-server",
    "gcr-ssh-agent",
];

/// Paths in ExecStart that indicate critical risk
const CRITICAL_EXEC_PATHS: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
];

/// Known malware filenames in ExecStart
const MALWARE_INDICATORS: &[&str] = &[
    "sysmon.py",
    "tpcp",
    "payload",
    "beacon",
    "implant",
    "c2client",
    "reverse_shell",
    "backdoor",
];

/// Audits user-level systemd services and timers for suspicious activity
pub struct UserSystemdCheck;

impl SupplyChainCheck for UserSystemdCheck {
    fn id(&self) -> &str {
        "supply-chain-user-systemd"
    }

    fn name(&self) -> &str {
        "User Systemd Service Audit"
    }

    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for home in &ctx.user_homes {
            let home_str = home.display().to_string();
            let systemd_dir = format!("{}/.config/systemd/user", home_str);

            let Ok(entries) = fs.read_dir(&systemd_dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
                    continue;
                };

                let unit_path = format!("{}/{}", systemd_dir, name);

                if name.ends_with(".service") {
                    let Ok(content) = fs.read_to_string(&unit_path) else {
                        continue;
                    };
                    check_service_unit(&unit_path, &name, &home_str, &content, &mut findings);
                } else if name.ends_with(".timer") {
                    let Ok(content) = fs.read_to_string(&unit_path) else {
                        continue;
                    };

                    // For timers, find the corresponding service and check frequency
                    check_timer_unit(fs, &unit_path, &name, &home_str, &systemd_dir, &content, &mut findings);
                }
            }
        }

        findings
    }
}

/// Check a systemd service unit for suspicious patterns
fn check_service_unit(
    path: &str,
    name: &str,
    home: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let service_name = name.trim_end_matches(".service");

    // Extract ExecStart, ExecStartPre, ExecStartPost values
    let exec_lines = extract_exec_values(content);

    if exec_lines.is_empty() {
        return;
    }

    // Check for known TeamPCP IOC
    if name == "sysmon.service" {
        let has_sysmon_py = exec_lines.iter().any(|line| line.contains("sysmon.py"));
        if has_sysmon_py {
            findings.push(
                Finding::new(
                    format!("supply-chain-systemd-teampcp-{}", sanitize(home)),
                    format!("TeamPCP IOC: sysmon.service in {}", home),
                    format!(
                        "Known TeamPCP indicator of compromise: sysmon.service with sysmon.py \
                         found in {}. This is a known supply chain malware persistence mechanism.",
                        path
                    ),
                    Severity::Critical,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(
                    "Immediately investigate this system for TeamPCP/LiteLLM compromise. \
                     Remove the service, check for .pth file injection, and rotate all credentials.",
                )
                .with_reference(
                    "https://www.reversinglabs.com/blog/fake-litellm-pypi-package",
                ),
            );
            return;
        }
    }

    // Check if this is a known legitimate service
    let is_legitimate = LEGITIMATE_SERVICE_PREFIXES
        .iter()
        .any(|prefix| service_name.starts_with(prefix));

    for exec_line in &exec_lines {
        // Check for critical exec paths
        for &crit_path in CRITICAL_EXEC_PATHS {
            if exec_line.contains(crit_path) {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-systemd-critical-path-{}-{}",
                            sanitize(service_name),
                            sanitize(home)
                        ),
                        format!(
                            "User service executes from suspicious path: {}",
                            service_name
                        ),
                        format!(
                            "Service {} in {} executes a command from {}: {}. \
                             Temporary directories are commonly used by malware for persistence.",
                            name, home, crit_path,
                            truncate(exec_line, 200)
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Remove {} and investigate what placed it. Check for other \
                         signs of compromise.",
                        path
                    ))
                    .with_metadata("exec_line", serde_json::json!(truncate(exec_line, 500)))
                    .with_metadata("service_name", serde_json::json!(service_name)),
                );
                return;
            }
        }

        // Check for known malware indicators
        let lower = exec_line.to_lowercase();
        for &indicator in MALWARE_INDICATORS {
            if lower.contains(indicator) {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-systemd-malware-{}-{}",
                            sanitize(service_name),
                            sanitize(home)
                        ),
                        format!(
                            "Known malware indicator in user service: {}",
                            service_name
                        ),
                        format!(
                            "Service {} in {} contains a known malware indicator \"{}\": {}",
                            name, home, indicator,
                            truncate(exec_line, 200)
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(format!(
                        "Remove {} immediately and investigate the system for compromise.",
                        path
                    ))
                    .with_metadata("indicator", serde_json::json!(indicator))
                    .with_metadata("exec_line", serde_json::json!(truncate(exec_line, 500))),
                );
                return;
            }
        }

        // Check for scripting engines executing from user config dirs
        let scripting_engines = ["python", "python3", "node", "bash", "sh", "perl", "ruby"];
        let runs_script = scripting_engines.iter().any(|&engine| {
            lower.starts_with(engine)
                || lower.starts_with(&format!("/usr/bin/{}", engine))
                || lower.starts_with(&format!("/usr/local/bin/{}", engine))
        });

        let targets_config = exec_line.contains("/.config/")
            || exec_line.contains("/.local/")
            || exec_line.contains("/.cache/");

        if runs_script && targets_config && !is_legitimate {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-systemd-script-config-{}-{}",
                        sanitize(service_name),
                        sanitize(home)
                    ),
                    format!(
                        "User service runs script from config directory: {}",
                        service_name
                    ),
                    format!(
                        "Service {} in {} executes a script from a user configuration \
                         directory: {}. This pattern is commonly used for persistence.",
                        name, home,
                        truncate(exec_line, 200)
                    ),
                    Severity::High,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(format!(
                    "Verify that {} is a legitimate service. Check what created it \
                     and whether the executed script is trustworthy.",
                    path
                ))
                .with_metadata("exec_line", serde_json::json!(truncate(exec_line, 500)))
                .with_metadata("service_name", serde_json::json!(service_name)),
            );
            return;
        }
    }

    // Check for aggressive restart (persistence indicator)
    if has_aggressive_restart(content) && !is_legitimate {
        findings.push(
            Finding::new(
                format!(
                    "supply-chain-systemd-aggressive-restart-{}-{}",
                    sanitize(service_name),
                    sanitize(home)
                ),
                format!(
                    "User service with aggressive restart: {}",
                    service_name
                ),
                format!(
                    "Service {} in {} has Restart=always with a short RestartSec. \
                     Aggressive restart policies are commonly used by malware to maintain persistence.",
                    name, home
                ),
                Severity::High,
                make_source(),
            )
            .with_resource(path)
            .with_remediation(format!(
                "Verify that {} is a legitimate service. An aggressive restart \
                 policy with Restart=always and a short RestartSec is unusual for user services.",
                path
            ))
            .with_metadata("service_name", serde_json::json!(service_name)),
        );
        return;
    }

    // Any unknown user service is at least medium
    if !is_legitimate {
        findings.push(
            Finding::new(
                format!(
                    "supply-chain-systemd-unknown-{}-{}",
                    sanitize(service_name),
                    sanitize(home)
                ),
                format!("Unknown user systemd service: {}", service_name),
                format!(
                    "User service {} in {} does not match known legitimate services. \
                     User-level systemd services can be used for persistence by supply chain attacks.",
                    name, home
                ),
                Severity::Medium,
                make_source(),
            )
            .with_resource(path)
            .with_metadata("service_name", serde_json::json!(service_name))
            .with_metadata(
                "exec_lines",
                serde_json::json!(exec_lines
                    .iter()
                    .map(|l| truncate(l, 200))
                    .collect::<Vec<_>>()),
            ),
        );
    }
}

/// Check a timer unit for suspicious frequency
fn check_timer_unit(
    fs: &ContainerFs,
    path: &str,
    name: &str,
    home: &str,
    systemd_dir: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let timer_name = name.trim_end_matches(".timer");

    let is_legitimate = LEGITIMATE_SERVICE_PREFIXES
        .iter()
        .any(|prefix| timer_name.starts_with(prefix));

    if is_legitimate {
        return;
    }

    // Check if timer fires very frequently (< 5 minutes)
    let is_frequent = is_frequent_timer(content);

    if is_frequent {
        // Check the corresponding service for suspicious ExecStart
        let service_path = format!("{}/{}.service", systemd_dir, timer_name);
        let service_exec = fs
            .read_to_string(&service_path)
            .ok()
            .map(|c| extract_exec_values(&c))
            .unwrap_or_default();

        let has_suspicious_exec = service_exec.iter().any(|line| {
            let lower = line.to_lowercase();
            CRITICAL_EXEC_PATHS.iter().any(|p| lower.contains(p))
                || MALWARE_INDICATORS.iter().any(|m| lower.contains(m))
                || lower.contains("curl ")
                || lower.contains("wget ")
        });

        let severity = if has_suspicious_exec {
            Severity::High
        } else {
            Severity::Medium
        };

        findings.push(
            Finding::new(
                format!(
                    "supply-chain-systemd-frequent-timer-{}-{}",
                    sanitize(timer_name),
                    sanitize(home)
                ),
                format!(
                    "Frequently firing user timer: {}",
                    timer_name
                ),
                format!(
                    "Timer {} in {} fires more frequently than every 5 minutes. \
                     Very frequent timers are commonly used by malware for C2 beaconing or \
                     maintaining persistence.",
                    name, home
                ),
                severity,
                make_source(),
            )
            .with_resource(path)
            .with_remediation(format!(
                "Verify that {} and its corresponding service are legitimate. \
                 Check what installed this timer.",
                path
            ))
            .with_metadata("timer_name", serde_json::json!(timer_name)),
        );
    }
}

/// Extract ExecStart, ExecStartPre, ExecStartPost values from a unit file
fn extract_exec_values(content: &str) -> Vec<String> {
    let mut values = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ExecStart=")
            || trimmed.starts_with("ExecStartPre=")
            || trimmed.starts_with("ExecStartPost=")
        {
            if let Some((_key, val)) = trimmed.split_once('=') {
                let val = val.trim();
                // Strip systemd special prefixes like -, +, !, !!
                let val = val.trim_start_matches(|c: char| c == '-' || c == '+' || c == '!' || c == '@');
                if !val.is_empty() {
                    values.push(val.to_string());
                }
            }
        }
    }

    values
}

/// Check if a service has Restart=always with RestartSec < 60
fn has_aggressive_restart(content: &str) -> bool {
    let has_restart_always = content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "Restart=always" || trimmed == "Restart=on-failure"
    });

    if !has_restart_always {
        return false;
    }

    // Look for RestartSec
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("RestartSec=") {
            let val = val.trim();
            // Parse the value: could be "5", "30s", "1min"
            if let Some(seconds) = parse_time_seconds(val) {
                return seconds < 60;
            }
        }
    }

    // No RestartSec with Restart=always defaults to 100ms, which is aggressive
    has_restart_always
}

/// Parse a systemd time value to seconds
fn parse_time_seconds(val: &str) -> Option<u64> {
    let val = val.trim();

    // Try plain number (seconds)
    if let Ok(n) = val.parse::<u64>() {
        return Some(n);
    }

    // Try with suffix
    if let Some(n) = val.strip_suffix('s').and_then(|v| v.trim().parse::<u64>().ok()) {
        return Some(n);
    }
    if let Some(n) = val
        .strip_suffix("min")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return Some(n * 60);
    }
    if let Some(n) = val.strip_suffix('m').and_then(|v| v.trim().parse::<u64>().ok()) {
        return Some(n * 60);
    }
    if let Some(n) = val.strip_suffix('h').and_then(|v| v.trim().parse::<u64>().ok()) {
        return Some(n * 3600);
    }

    None
}

/// Check if a timer fires more frequently than every 5 minutes
fn is_frequent_timer(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();

        // Check OnBootSec, OnStartupSec, OnUnitActiveSec
        for prefix in &["OnBootSec=", "OnStartupSec=", "OnUnitActiveSec="] {
            if let Some(val) = trimmed.strip_prefix(prefix) {
                if let Some(secs) = parse_time_seconds(val) {
                    if secs < 300 {
                        return true;
                    }
                }
            }
        }

        // Check OnCalendar for very frequent patterns
        if let Some(val) = trimmed.strip_prefix("OnCalendar=") {
            let val = val.trim().to_lowercase();
            // Patterns like "*:0/1" (every minute), "*:0/2" (every 2 minutes)
            let minute_re = Regex::new(r"\*:\d*/(\d+)").ok();
            if let Some(re) = minute_re {
                if let Some(caps) = re.captures(&val) {
                    if let Ok(interval) = caps[1].parse::<u64>() {
                        if interval < 5 {
                            return true;
                        }
                    }
                }
            }
            // "minutely" is every minute
            if val == "minutely" {
                return true;
            }
        }
    }

    false
}

/// Create the standard FindingSource for user systemd checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "ioc".to_string(),
        ecosystem: None,
    }
}

/// Truncate a string to a maximum length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Sanitize a string for use in finding IDs
fn sanitize(s: &str) -> String {
    s.replace('/', "-")
        .replace('.', "-")
        .replace('@', "")
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_with_home(tmp: &TempDir) -> (ContainerFs, SupplyChainContext) {
        let root = tmp.path();
        let home = root.join("home/testuser/.config/systemd/user");
        std::fs::create_dir_all(&home).unwrap();

        let fs = ContainerFs::new(root);
        let ctx = SupplyChainContext {
            root: root.to_path_buf(),
            user_homes: vec![std::path::PathBuf::from("/home/testuser")],
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        };

        (fs, ctx)
    }

    fn write_unit(tmp: &TempDir, name: &str, content: &str) {
        let path = tmp
            .path()
            .join("home/testuser/.config/systemd/user")
            .join(name);
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_teampcp_ioc_detected() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_home(&tmp);

        write_unit(
            &tmp,
            "sysmon.service",
            "[Unit]\nDescription=System Monitor\n\n[Service]\nExecStart=/usr/bin/python3 /home/testuser/.config/sysmon.py\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        );

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        assert!(!findings.is_empty(), "Should detect TeamPCP IOC");
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(!critical.is_empty(), "TeamPCP IOC should be Critical");
        assert!(
            critical[0].title.contains("TeamPCP"),
            "Should mention TeamPCP in title"
        );
    }

    #[test]
    fn test_tmp_exec_path_critical() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_home(&tmp);

        write_unit(
            &tmp,
            "backdoor.service",
            "[Unit]\nDescription=Totally Legit\n\n[Service]\nExecStart=/tmp/.hidden/payload\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n",
        );

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            !critical.is_empty(),
            "Exec from /tmp/ should be Critical"
        );
    }

    #[test]
    fn test_legitimate_service_no_findings() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_home(&tmp);

        write_unit(
            &tmp,
            "pipewire.service",
            "[Unit]\nDescription=PipeWire\n\n[Service]\nExecStart=/usr/bin/pipewire\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n",
        );

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        assert!(
            findings.is_empty(),
            "Legitimate service should not produce findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_unknown_service_medium() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_home(&tmp);

        write_unit(
            &tmp,
            "my-custom-app.service",
            "[Unit]\nDescription=My App\n\n[Service]\nExecStart=/usr/bin/my-custom-app --daemon\n\n[Install]\nWantedBy=default.target\n",
        );

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        let medium: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .collect();
        assert!(
            !medium.is_empty(),
            "Unknown service should be Medium severity"
        );
    }

    #[test]
    fn test_aggressive_restart_high() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_home(&tmp);

        write_unit(
            &tmp,
            "suspicious.service",
            "[Unit]\nDescription=Suspicious\n\n[Service]\nExecStart=/usr/bin/suspicious-thing\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        );

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        let high: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        assert!(
            !high.is_empty(),
            "Aggressive restart should be High severity"
        );
    }

    #[test]
    fn test_frequent_timer_detected() {
        let tmp = TempDir::new().unwrap();
        let (fs, ctx) = setup_with_home(&tmp);

        write_unit(
            &tmp,
            "beacon.timer",
            "[Unit]\nDescription=Beacon Timer\n\n[Timer]\nOnBootSec=30\nOnUnitActiveSec=60\n\n[Install]\nWantedBy=timers.target\n",
        );

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        assert!(!findings.is_empty(), "Frequent timer should produce findings");
    }

    #[test]
    fn test_no_services_no_crash() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = SupplyChainContext {
            root: tmp.path().to_path_buf(),
            user_homes: vec![std::path::PathBuf::from("/home/testuser")],
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        };

        let check = UserSystemdCheck;
        let findings = check.run(&fs, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_time_seconds() {
        assert_eq!(parse_time_seconds("5"), Some(5));
        assert_eq!(parse_time_seconds("30s"), Some(30));
        assert_eq!(parse_time_seconds("5min"), Some(300));
        assert_eq!(parse_time_seconds("1h"), Some(3600));
        assert_eq!(parse_time_seconds("invalid"), None);
    }

    #[test]
    fn test_extract_exec_values() {
        let content = "[Service]\nExecStart=/usr/bin/foo\nExecStartPre=-/usr/bin/setup\nExecStartPost=/usr/bin/cleanup\n";
        let values = extract_exec_values(content);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], "/usr/bin/foo");
        assert_eq!(values[1], "/usr/bin/setup");
        assert_eq!(values[2], "/usr/bin/cleanup");
    }
}
