//! Container package extraction
//!
//! Parses installed packages from container filesystems for SBOM generation
//! and vulnerability scanning. Supports dpkg (Debian/Ubuntu) and apk (Alpine).

use crate::filesystem::ContainerFs;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// An installed package extracted from a container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    /// Package manager type: "deb" or "apk"
    pub pkg_type: String,
    /// Distro identifier for PURL (e.g., "debian", "ubuntu", "alpine")
    pub distro: String,
}

impl InstalledPackage {
    /// Generate a Package URL (PURL) for this package
    pub fn purl(&self) -> String {
        match self.pkg_type.as_str() {
            "deb" => format!(
                "pkg:deb/{}/{}@{}",
                self.distro, self.name, self.version
            ),
            "apk" => format!(
                "pkg:apk/{}/{}@{}",
                self.distro, self.name, self.version
            ),
            _ => format!(
                "pkg:{}/{}@{}",
                self.pkg_type, self.name, self.version
            ),
        }
    }
}

/// Extract all installed packages from a container filesystem.
///
/// Detects the OS from /etc/os-release, then parses the appropriate
/// package database (dpkg for Debian/Ubuntu, apk for Alpine).
pub fn extract_packages(fs: &ContainerFs) -> Vec<InstalledPackage> {
    let os_info = fs.detect_os();
    let os_id = os_info
        .as_ref()
        .map(|o| o.id.as_str())
        .unwrap_or("unknown");

    match os_id {
        "debian" | "ubuntu" => parse_dpkg(fs, os_id),
        "alpine" => parse_apk(fs),
        _ => {
            debug!("Unsupported OS for package extraction: {}", os_id);
            Vec::new()
        }
    }
}

/// Parse dpkg status file (Debian/Ubuntu)
fn parse_dpkg(fs: &ContainerFs, distro: &str) -> Vec<InstalledPackage> {
    let content = match fs.read_to_string("/var/lib/dpkg/status") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut packages = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut installed = false;

    for line in content.lines() {
        if line.is_empty() {
            if !name.is_empty() && installed && !version.is_empty() {
                packages.push(InstalledPackage {
                    name: std::mem::take(&mut name),
                    version: std::mem::take(&mut version),
                    pkg_type: "deb".to_string(),
                    distro: distro.to_string(),
                });
            } else {
                name.clear();
                version.clear();
            }
            installed = false;
            continue;
        }

        if let Some(n) = line.strip_prefix("Package: ") {
            name = n.to_string();
        } else if let Some(v) = line.strip_prefix("Version: ") {
            version = v.to_string();
        } else if let Some(s) = line.strip_prefix("Status: ") {
            installed = s.contains("installed") && !s.contains("not-installed");
        }
    }

    if !name.is_empty() && installed && !version.is_empty() {
        packages.push(InstalledPackage {
            name,
            version,
            pkg_type: "deb".to_string(),
            distro: distro.to_string(),
        });
    }

    debug!("Parsed {} dpkg packages", packages.len());
    packages
}

/// Parse Alpine apk installed database
fn parse_apk(fs: &ContainerFs) -> Vec<InstalledPackage> {
    let content = match fs.read_to_string("/lib/apk/db/installed") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut packages = Vec::new();
    let mut name = String::new();
    let mut version = String::new();

    for line in content.lines() {
        if line.is_empty() {
            if !name.is_empty() && !version.is_empty() {
                packages.push(InstalledPackage {
                    name: std::mem::take(&mut name),
                    version: std::mem::take(&mut version),
                    pkg_type: "apk".to_string(),
                    distro: "alpine".to_string(),
                });
            } else {
                name.clear();
                version.clear();
            }
            continue;
        }

        if let Some(n) = line.strip_prefix("P:") {
            name = n.to_string();
        } else if let Some(v) = line.strip_prefix("V:") {
            version = v.to_string();
        }
    }

    if !name.is_empty() && !version.is_empty() {
        packages.push(InstalledPackage {
            name,
            version,
            pkg_type: "apk".to_string(),
            distro: "alpine".to_string(),
        });
    }

    debug!("Parsed {} apk packages", packages.len());
    packages
}

/// Generate a CycloneDX 1.5 JSON SBOM from container packages
pub fn generate_container_sbom(
    packages: &[InstalledPackage],
    container_name: &str,
    os_info: Option<&str>,
) -> serde_json::Value {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let components: Vec<serde_json::Value> = packages
        .iter()
        .map(|pkg| {
            let purl = pkg.purl();
            serde_json::json!({
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "purl": purl,
                "bom-ref": purl,
            })
        })
        .collect();

    let mut metadata_component = serde_json::json!({
        "type": "container",
        "name": container_name,
        "bom-ref": container_name,
    });

    if let Some(os) = os_info {
        metadata_component["description"] = serde_json::Value::String(os.to_string());
    }

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "vendor": "protectinator",
                "name": "protectinator-container",
                "version": "0.1.0",
            }],
            "component": metadata_component,
        },
        "components": components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_purl_deb() {
        let pkg = InstalledPackage {
            name: "curl".to_string(),
            version: "7.88.1-10+deb12u8".to_string(),
            pkg_type: "deb".to_string(),
            distro: "debian".to_string(),
        };
        assert_eq!(pkg.purl(), "pkg:deb/debian/curl@7.88.1-10+deb12u8");
    }

    #[test]
    fn test_purl_apk() {
        let pkg = InstalledPackage {
            name: "musl".to_string(),
            version: "1.2.5-r0".to_string(),
            pkg_type: "apk".to_string(),
            distro: "alpine".to_string(),
        };
        assert_eq!(pkg.purl(), "pkg:apk/alpine/musl@1.2.5-r0");
    }

    #[test]
    fn test_extract_dpkg() {
        let tmp = TempDir::new().unwrap();
        let dpkg_dir = tmp.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg_dir).unwrap();
        // Also need an os-release for OS detection
        let etc_dir = tmp.path().join("etc");
        std::fs::create_dir_all(&etc_dir).unwrap();
        std::fs::write(
            etc_dir.join("os-release"),
            "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
        )
        .unwrap();
        std::fs::write(
            dpkg_dir.join("status"),
            "Package: curl\nStatus: install ok installed\nVersion: 7.88.1\n\nPackage: wget\nStatus: install ok installed\nVersion: 1.21\n\n",
        )
        .unwrap();

        let fs = ContainerFs::new(tmp.path());
        let pkgs = extract_packages(&fs);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "curl");
        assert_eq!(pkgs[0].pkg_type, "deb");
        assert_eq!(pkgs[0].distro, "debian");
    }

    #[test]
    fn test_extract_apk() {
        let tmp = TempDir::new().unwrap();
        let apk_dir = tmp.path().join("lib/apk/db");
        std::fs::create_dir_all(&apk_dir).unwrap();
        let etc_dir = tmp.path().join("etc");
        std::fs::create_dir_all(&etc_dir).unwrap();
        std::fs::write(
            etc_dir.join("os-release"),
            "ID=alpine\nVERSION_ID=3.22.0\nPRETTY_NAME=\"Alpine Linux v3.22\"\n",
        )
        .unwrap();
        std::fs::write(
            apk_dir.join("installed"),
            "P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r29\n\n",
        )
        .unwrap();

        let fs = ContainerFs::new(tmp.path());
        let pkgs = extract_packages(&fs);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "musl");
        assert_eq!(pkgs[0].pkg_type, "apk");
        assert_eq!(pkgs[0].distro, "alpine");
    }

    #[test]
    fn test_generate_container_sbom() {
        let packages = vec![
            InstalledPackage {
                name: "curl".to_string(),
                version: "7.88.1".to_string(),
                pkg_type: "deb".to_string(),
                distro: "debian".to_string(),
            },
        ];

        let sbom = generate_container_sbom(&packages, "my-container", Some("Debian 12"));
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert_eq!(sbom["metadata"]["component"]["name"], "my-container");
        assert_eq!(sbom["metadata"]["component"]["type"], "container");

        let components = sbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["name"], "curl");
        assert_eq!(components[0]["purl"], "pkg:deb/debian/curl@7.88.1");
    }
}
