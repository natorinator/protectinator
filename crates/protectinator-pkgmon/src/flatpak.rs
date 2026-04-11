//! Flatpak permission and remote audit
//!
//! Audits Flatpak applications for excessive permissions, non-Flathub remotes,
//! disabled GPG verification, and user-applied permission overrides.

use crate::scanner::PkgMonCheck;
use crate::types::{PackageManager, PkgMonContext};
use protectinator_core::{Finding, FindingSource, Severity};
use std::path::{Path, PathBuf};
use tracing::debug;

/// A discovered Flatpak app with its permissions
#[derive(Debug, Clone)]
pub struct FlatpakApp {
    pub app_id: String,
    pub permissions: FlatpakPermissions,
    pub metadata_path: PathBuf,
    /// "system" or "user"
    pub install_type: String,
}

/// Parsed Flatpak permissions from [Context] section
#[derive(Debug, Clone, Default)]
pub struct FlatpakPermissions {
    pub shared: Vec<String>,
    pub sockets: Vec<String>,
    pub devices: Vec<String>,
    pub filesystems: Vec<String>,
    pub features: Vec<String>,
}

/// A Flatpak remote from repo config
#[derive(Debug, Clone)]
pub struct FlatpakRemote {
    pub name: String,
    pub url: String,
    pub gpg_verify: bool,
    pub config_path: PathBuf,
}

/// Discover all installed Flatpak apps and parse their metadata
pub fn discover_apps(root: &Path) -> Vec<FlatpakApp> {
    let mut apps = Vec::new();

    // System-wide installations
    let system_app_dir = root.join("var/lib/flatpak/app");
    apps.extend(discover_apps_in_dir(&system_app_dir, "system"));

    // User installations — scan all home dirs
    if let Ok(entries) = std::fs::read_dir(root.join("home")) {
        for entry in entries.flatten() {
            let user_app_dir = entry.path().join(".local/share/flatpak/app");
            apps.extend(discover_apps_in_dir(&user_app_dir, "user"));
        }
    }

    // Also check the running user's home
    if let Some(home) = std::env::var_os("HOME") {
        let user_app_dir = PathBuf::from(home).join(".local/share/flatpak/app");
        // Avoid duplicates by checking if we already scanned this path
        if !apps.iter().any(|a| a.metadata_path.starts_with(&user_app_dir)) {
            apps.extend(discover_apps_in_dir(&user_app_dir, "user"));
        }
    }

    apps
}

fn discover_apps_in_dir(app_dir: &Path, install_type: &str) -> Vec<FlatpakApp> {
    let mut apps = Vec::new();

    let entries = match std::fs::read_dir(app_dir) {
        Ok(e) => e,
        Err(_) => return apps,
    };

    for entry in entries.flatten() {
        let app_id = entry.file_name().to_string_lossy().to_string();
        let metadata_path = entry.path().join("current/active/metadata");

        if !metadata_path.exists() {
            continue;
        }

        let permissions = match parse_metadata(&metadata_path) {
            Some(p) => p,
            None => continue,
        };

        apps.push(FlatpakApp {
            app_id,
            permissions,
            metadata_path,
            install_type: install_type.to_string(),
        });
    }

    apps
}

/// Parse Flatpak metadata file (INI/GKeyFile format) to extract [Context] permissions
fn parse_metadata(path: &Path) -> Option<FlatpakPermissions> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_context_section(&content)
}

/// Parse the [Context] section from metadata content
fn parse_context_section(content: &str) -> Option<FlatpakPermissions> {
    let mut perms = FlatpakPermissions::default();
    let mut in_context = false;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_context = line == "[Context]";
            continue;
        }
        if !in_context {
            continue;
        }
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let items: Vec<String> = value
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        match key.trim() {
            "shared" => perms.shared = items,
            "sockets" => perms.sockets = items,
            "devices" => perms.devices = items,
            "filesystems" => perms.filesystems = items,
            "features" => perms.features = items,
            _ => {}
        }
    }

    Some(perms)
}

/// Flatpak permission audit check
pub struct FlatpakPermissionAudit;

impl PkgMonCheck for FlatpakPermissionAudit {
    fn name(&self) -> &str {
        "flatpak-permission-audit"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Flatpak
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let apps = discover_apps(&ctx.config.root);
        let mut findings = Vec::new();

        debug!("Flatpak permission audit: found {} apps", apps.len());

        for app in &apps {
            findings.extend(audit_app_permissions(app));
        }

        findings
    }
}

/// Audit a single app's permissions
fn audit_app_permissions(app: &FlatpakApp) -> Vec<Finding> {
    let mut findings = Vec::new();
    let perms = &app.permissions;

    // Check for broad filesystem access
    for fs in &perms.filesystems {
        let fs_lower = fs.to_lowercase();
        if fs_lower == "host" || fs_lower == "host:rw" {
            findings.push(make_perm_finding(
                &app.app_id,
                "pkgmon-flatpak-fs-host",
                &format!("{}: full host filesystem access (filesystems=host)", app.app_id),
                "Application has unrestricted access to the entire host filesystem, \
                 completely defeating Flatpak's sandboxing.",
                Severity::High,
                "filesystems",
                fs,
                &app.metadata_path,
            ));
        } else if fs_lower == "home" || fs_lower == "home:rw" {
            findings.push(make_perm_finding(
                &app.app_id,
                "pkgmon-flatpak-fs-home",
                &format!("{}: full home directory access (filesystems=home)", app.app_id),
                "Application has read/write access to the entire home directory, \
                 including SSH keys, browser profiles, and other sensitive data.",
                Severity::High,
                "filesystems",
                fs,
                &app.metadata_path,
            ));
        } else if fs_lower.starts_with("xdg-config") && !fs_lower.ends_with(":ro") {
            findings.push(make_perm_finding(
                &app.app_id,
                "pkgmon-flatpak-fs-config",
                &format!("{}: writable access to XDG config ({})", app.app_id, fs),
                "Application can write to XDG config directories, potentially \
                 modifying other applications' configuration files.",
                Severity::Medium,
                "filesystems",
                fs,
                &app.metadata_path,
            ));
        }
    }

    // Check for broad device access combined with filesystem access
    let has_all_devices = perms.devices.iter().any(|d| d == "all");
    let has_filesystem = !perms.filesystems.is_empty();
    if has_all_devices && has_filesystem {
        findings.push(make_perm_finding(
            &app.app_id,
            "pkgmon-flatpak-devices-fs",
            &format!("{}: all devices + filesystem access", app.app_id),
            "Application has access to all devices AND filesystem paths. \
             This combination provides broad system access.",
            Severity::Medium,
            "devices",
            "all",
            &app.metadata_path,
        ));
    }

    // X11 socket without Wayland (X11 has no app isolation)
    let has_x11 = perms.sockets.iter().any(|s| s == "x11");
    let has_wayland = perms.sockets.iter().any(|s| s == "wayland");
    if has_x11 && !has_wayland {
        findings.push(make_perm_finding(
            &app.app_id,
            "pkgmon-flatpak-x11-only",
            &format!("{}: X11-only display (no Wayland isolation)", app.app_id),
            "Application uses X11 without Wayland. X11 provides no isolation \
             between applications — any X11 app can keylog other X11 apps.",
            Severity::Medium,
            "sockets",
            "x11",
            &app.metadata_path,
        ));
    }

    findings
}

fn make_perm_finding(
    app_id: &str,
    id: &str,
    title: &str,
    description: &str,
    severity: Severity,
    perm_type: &str,
    perm_value: &str,
    metadata_path: &Path,
) -> Finding {
    Finding::new(
        id,
        title,
        description,
        severity,
        FindingSource::PackageMonitor {
            package_manager: "flatpak".to_string(),
            check_category: "permission_audit".to_string(),
        },
    )
    .with_resource(app_id)
    .with_metadata("permission_type", serde_json::json!(perm_type))
    .with_metadata("permission_value", serde_json::json!(perm_value))
    .with_metadata("metadata_path", serde_json::json!(metadata_path.to_string_lossy()))
}

/// Flatpak remote audit check
pub struct FlatpakRemoteAudit;

impl PkgMonCheck for FlatpakRemoteAudit {
    fn name(&self) -> &str {
        "flatpak-remote-audit"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Flatpak
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let remotes = discover_remotes(&ctx.config.root);
        let mut findings = Vec::new();

        for remote in &remotes {
            // Skip Flathub (trusted)
            if remote.name == "flathub" {
                continue;
            }

            // Flag non-Flathub remotes
            if !remote.url.is_empty() {
                findings.push(
                    Finding::new(
                        "pkgmon-flatpak-non-flathub",
                        format!("Non-Flathub Flatpak remote: {}", remote.name),
                        format!(
                            "Remote '{}' (URL: {}) is not the official Flathub repository. \
                             Third-party remotes may distribute unreviewed applications.",
                            remote.name,
                            if remote.url.is_empty() { "<empty>" } else { &remote.url }
                        ),
                        Severity::Medium,
                        FindingSource::PackageMonitor {
                            package_manager: "flatpak".to_string(),
                            check_category: "remote_audit".to_string(),
                        },
                    )
                    .with_resource(&remote.name)
                    .with_metadata("url", serde_json::json!(remote.url)),
                );
            }

            // Flag disabled GPG verification
            if !remote.gpg_verify {
                findings.push(
                    Finding::new(
                        "pkgmon-flatpak-no-gpg",
                        format!("Flatpak remote without GPG verification: {}", remote.name),
                        format!(
                            "Remote '{}' has GPG verification disabled (gpg-verify=false). \
                             Applications from this remote cannot be verified for authenticity.",
                            remote.name
                        ),
                        Severity::High,
                        FindingSource::PackageMonitor {
                            package_manager: "flatpak".to_string(),
                            check_category: "remote_audit".to_string(),
                        },
                    )
                    .with_resource(&remote.name),
                );
            }

            // Flag HTTP URLs
            if remote.url.starts_with("http://") {
                findings.push(
                    Finding::new(
                        "pkgmon-flatpak-http-remote",
                        format!("Insecure HTTP Flatpak remote: {}", remote.name),
                        format!(
                            "Remote '{}' uses unencrypted HTTP ({}). \
                             Applications could be intercepted or modified in transit.",
                            remote.name, remote.url
                        ),
                        Severity::High,
                        FindingSource::PackageMonitor {
                            package_manager: "flatpak".to_string(),
                            check_category: "remote_audit".to_string(),
                        },
                    )
                    .with_resource(&remote.name),
                );
            }
        }

        findings
    }
}

/// Discover Flatpak remotes from repo config
fn discover_remotes(root: &Path) -> Vec<FlatpakRemote> {
    let mut remotes = Vec::new();

    // System config
    let system_config = root.join("var/lib/flatpak/repo/config");
    remotes.extend(parse_repo_config(&system_config));

    // User config
    if let Some(home) = std::env::var_os("HOME") {
        let user_config = PathBuf::from(home).join(".local/share/flatpak/repo/config");
        remotes.extend(parse_repo_config(&user_config));
    }

    remotes
}

/// Parse a Flatpak repo config file for remote definitions
fn parse_repo_config(path: &Path) -> Vec<FlatpakRemote> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut remotes = Vec::new();
    let mut current_remote: Option<String> = None;
    let mut current_url = String::new();
    let mut current_gpg = true;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("[remote \"") && line.ends_with("\"]") {
            // Save previous remote
            if let Some(name) = current_remote.take() {
                remotes.push(FlatpakRemote {
                    name,
                    url: std::mem::take(&mut current_url),
                    gpg_verify: current_gpg,
                    config_path: path.to_path_buf(),
                });
            }

            let name = line
                .trim_start_matches("[remote \"")
                .trim_end_matches("\"]")
                .to_string();
            current_remote = Some(name);
            current_url = String::new();
            current_gpg = true;
        } else if line.starts_with('[') {
            // New non-remote section
            if let Some(name) = current_remote.take() {
                remotes.push(FlatpakRemote {
                    name,
                    url: std::mem::take(&mut current_url),
                    gpg_verify: current_gpg,
                    config_path: path.to_path_buf(),
                });
            }
        } else if current_remote.is_some() {
            if let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    "url" => current_url = value.trim().to_string(),
                    "gpg-verify" => current_gpg = value.trim() != "false",
                    _ => {}
                }
            }
        }
    }

    // Don't forget the last remote
    if let Some(name) = current_remote {
        remotes.push(FlatpakRemote {
            name,
            url: current_url,
            gpg_verify: current_gpg,
            config_path: path.to_path_buf(),
        });
    }

    remotes
}

/// Flatpak permission override audit
pub struct FlatpakOverrideAudit;

impl PkgMonCheck for FlatpakOverrideAudit {
    fn name(&self) -> &str {
        "flatpak-override-audit"
    }

    fn package_manager(&self) -> PackageManager {
        PackageManager::Flatpak
    }

    fn check(&self, ctx: &PkgMonContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check system overrides
        let system_overrides = ctx.config.root.join("var/lib/flatpak/overrides");
        findings.extend(audit_overrides_dir(&system_overrides, "system"));

        // Check user overrides
        if let Some(home) = std::env::var_os("HOME") {
            let user_overrides = PathBuf::from(home).join(".local/share/flatpak/overrides");
            findings.extend(audit_overrides_dir(&user_overrides, "user"));
        }

        findings
    }
}

fn audit_overrides_dir(dir: &Path, install_type: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let app_id = entry.file_name().to_string_lossy().to_string();
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if let Some(perms) = parse_context_section(&content) {
            // Flag overrides that grant filesystem access
            for fs in &perms.filesystems {
                if !fs.starts_with('!') {
                    // Not a deny rule — this grants access
                    findings.push(
                        Finding::new(
                            "pkgmon-flatpak-override-grant",
                            format!("{}: override grants filesystem access ({})", app_id, fs),
                            format!(
                                "A {} override for '{}' grants additional filesystem access: {}. \
                                 This was manually added and expands the app's sandbox.",
                                install_type, app_id, fs
                            ),
                            Severity::Medium,
                            FindingSource::PackageMonitor {
                                package_manager: "flatpak".to_string(),
                                check_category: "override_audit".to_string(),
                            },
                        )
                        .with_resource(&app_id)
                        .with_metadata("override_type", serde_json::json!(install_type))
                        .with_metadata("granted_filesystem", serde_json::json!(fs)),
                    );
                }
            }

            // Flag device grants
            for dev in &perms.devices {
                if !dev.starts_with('!') {
                    findings.push(
                        Finding::new(
                            "pkgmon-flatpak-override-device",
                            format!("{}: override grants device access ({})", app_id, dev),
                            format!(
                                "A {} override for '{}' grants device access: {}.",
                                install_type, app_id, dev
                            ),
                            Severity::Medium,
                            FindingSource::PackageMonitor {
                                package_manager: "flatpak".to_string(),
                                check_category: "override_audit".to_string(),
                            },
                        )
                        .with_resource(&app_id),
                    );
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parse_discord_metadata() {
        let content = "\
[Application]
name=com.discordapp.Discord
runtime=org.freedesktop.Platform/x86_64/25.08

[Context]
shared=network;ipc;
sockets=x11;wayland;pulseaudio;pcsc;
devices=all;
filesystems=xdg-download;xdg-pictures:ro;xdg-videos:ro;
";
        let perms = parse_context_section(content).unwrap();
        assert_eq!(perms.shared, vec!["network", "ipc"]);
        assert_eq!(perms.sockets, vec!["x11", "wayland", "pulseaudio", "pcsc"]);
        assert_eq!(perms.devices, vec!["all"]);
        assert_eq!(perms.filesystems, vec!["xdg-download", "xdg-pictures:ro", "xdg-videos:ro"]);
    }

    #[test]
    fn parse_empty_context() {
        let content = "[Application]\nname=test\n";
        let perms = parse_context_section(content).unwrap();
        assert!(perms.shared.is_empty());
        assert!(perms.filesystems.is_empty());
    }

    #[test]
    fn detect_host_filesystem() {
        let app = FlatpakApp {
            app_id: "com.evil.App".to_string(),
            permissions: FlatpakPermissions {
                filesystems: vec!["host".to_string()],
                ..Default::default()
            },
            metadata_path: PathBuf::from("/test"),
            install_type: "system".to_string(),
        };
        let findings = audit_app_permissions(&app);
        let host_findings: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-flatpak-fs-host").collect();
        assert_eq!(host_findings.len(), 1);
        assert_eq!(host_findings[0].severity, Severity::High);
    }

    #[test]
    fn detect_home_filesystem() {
        let app = FlatpakApp {
            app_id: "com.sketchy.App".to_string(),
            permissions: FlatpakPermissions {
                filesystems: vec!["home".to_string()],
                ..Default::default()
            },
            metadata_path: PathBuf::from("/test"),
            install_type: "system".to_string(),
        };
        let findings = audit_app_permissions(&app);
        let home_findings: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-flatpak-fs-home").collect();
        assert_eq!(home_findings.len(), 1);
        assert_eq!(home_findings[0].severity, Severity::High);
    }

    #[test]
    fn safe_app_no_high_findings() {
        let app = FlatpakApp {
            app_id: "com.safe.App".to_string(),
            permissions: FlatpakPermissions {
                shared: vec!["network".to_string()],
                sockets: vec!["wayland".to_string(), "pulseaudio".to_string()],
                ..Default::default()
            },
            metadata_path: PathBuf::from("/test"),
            install_type: "system".to_string(),
        };
        let findings = audit_app_permissions(&app);
        let high: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High).collect();
        assert!(high.is_empty());
    }

    #[test]
    fn x11_only_flagged() {
        let app = FlatpakApp {
            app_id: "com.old.App".to_string(),
            permissions: FlatpakPermissions {
                sockets: vec!["x11".to_string()],
                ..Default::default()
            },
            metadata_path: PathBuf::from("/test"),
            install_type: "system".to_string(),
        };
        let findings = audit_app_permissions(&app);
        let x11: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-flatpak-x11-only").collect();
        assert_eq!(x11.len(), 1);
    }

    #[test]
    fn x11_with_wayland_not_flagged() {
        let app = FlatpakApp {
            app_id: "com.modern.App".to_string(),
            permissions: FlatpakPermissions {
                sockets: vec!["x11".to_string(), "wayland".to_string()],
                ..Default::default()
            },
            metadata_path: PathBuf::from("/test"),
            install_type: "system".to_string(),
        };
        let findings = audit_app_permissions(&app);
        let x11: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-flatpak-x11-only").collect();
        assert!(x11.is_empty());
    }

    #[test]
    fn parse_repo_config_flathub() {
        let content = "\
[core]
repo_version=1

[remote \"flathub\"]
url=https://dl.flathub.org/repo/
gpg-verify=true
";
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config");
        fs::write(&path, content).unwrap();

        let remotes = parse_repo_config(&path);
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].name, "flathub");
        assert!(remotes[0].gpg_verify);
    }

    #[test]
    fn parse_repo_config_no_gpg() {
        let content = "\
[remote \"sketchy\"]
url=http://evil.example.com/repo
gpg-verify=false
gpg-verify-summary=false
";
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config");
        fs::write(&path, content).unwrap();

        let remotes = parse_repo_config(&path);
        assert_eq!(remotes.len(), 1);
        assert!(!remotes[0].gpg_verify);
        assert!(remotes[0].url.starts_with("http://"));
    }

    #[test]
    fn non_flathub_remote_flagged() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create system repo config with non-flathub remote
        let config_dir = root.join("var/lib/flatpak/repo");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("config"),
            "[remote \"custom\"]\nurl=https://custom.example.com/repo\ngpg-verify=true\n",
        )
        .unwrap();

        // Also create flatpak marker for detection
        fs::create_dir_all(root.join("var/lib/flatpak")).unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = FlatpakRemoteAudit.check(&ctx);

        let non_flathub: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-flatpak-non-flathub")
            .collect();
        assert_eq!(non_flathub.len(), 1);
    }

    #[test]
    fn no_gpg_remote_flagged() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let config_dir = root.join("var/lib/flatpak/repo");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("config"),
            "[remote \"nogpg\"]\nurl=https://example.com\ngpg-verify=false\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("var/lib/flatpak")).unwrap();

        let config = crate::types::PkgMonConfig {
            root: root.to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);
        let findings = FlatpakRemoteAudit.check(&ctx);

        let no_gpg: Vec<_> = findings.iter().filter(|f| f.id == "pkgmon-flatpak-no-gpg").collect();
        assert_eq!(no_gpg.len(), 1);
        assert_eq!(no_gpg[0].severity, Severity::High);
    }

    #[test]
    fn discover_apps_from_temp_dir() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let app_dir = root.join("var/lib/flatpak/app/com.test.App/current/active");
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(
            app_dir.join("metadata"),
            "[Application]\nname=com.test.App\n[Context]\nshared=network;\n",
        )
        .unwrap();

        let apps = discover_apps(root);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].app_id, "com.test.App");
        assert_eq!(apps[0].permissions.shared, vec!["network"]);
    }

    #[test]
    fn override_granting_fs_flagged() {
        let tmp = TempDir::new().unwrap();
        let override_dir = tmp.path().join("overrides");
        fs::create_dir_all(&override_dir).unwrap();
        fs::write(
            override_dir.join("com.test.App"),
            "[Context]\nfilesystems=home;\n",
        )
        .unwrap();

        let findings = audit_overrides_dir(&override_dir, "user");
        let grants: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-flatpak-override-grant")
            .collect();
        assert_eq!(grants.len(), 1);
    }

    #[test]
    fn override_deny_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let override_dir = tmp.path().join("overrides");
        fs::create_dir_all(&override_dir).unwrap();
        fs::write(
            override_dir.join("com.test.App"),
            "[Context]\nfilesystems=!home;\n",
        )
        .unwrap();

        let findings = audit_overrides_dir(&override_dir, "user");
        let grants: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "pkgmon-flatpak-override-grant")
            .collect();
        assert!(grants.is_empty());
    }

    #[test]
    fn no_flatpak_graceful() {
        let tmp = TempDir::new().unwrap();
        let config = crate::types::PkgMonConfig {
            root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let ctx = crate::types::PkgMonContext::new(config);

        assert!(FlatpakPermissionAudit.check(&ctx).is_empty());
        assert!(FlatpakRemoteAudit.check(&ctx).is_empty());
        assert!(FlatpakOverrideAudit.check(&ctx).is_empty());
    }
}
