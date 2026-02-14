//! Container filesystem access from the host
//!
//! Provides safe access to a container's filesystem by prefixing
//! all paths with the container's root directory on the host.

use crate::types::ContainerOsInfo;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Provides filesystem access to a container's root from the host
#[derive(Debug, Clone)]
pub struct ContainerFs {
    root: PathBuf,
}

impl ContainerFs {
    /// Create a new ContainerFs with the given root path
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Get the container root path
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve an absolute path within the container to its host path.
    /// The input path should be an absolute path as seen inside the container
    /// (e.g., `/etc/os-release`).
    pub fn resolve(&self, path: &str) -> PathBuf {
        let stripped = path.strip_prefix('/').unwrap_or(path);
        self.root.join(stripped)
    }

    /// Read a file from the container filesystem
    pub fn read_to_string(&self, path: &str) -> io::Result<String> {
        fs::read_to_string(self.resolve(path))
    }

    /// Check if a path exists in the container filesystem
    pub fn exists(&self, path: &str) -> bool {
        self.resolve(path).exists()
    }

    /// Read a directory in the container filesystem
    pub fn read_dir(&self, path: &str) -> io::Result<fs::ReadDir> {
        fs::read_dir(self.resolve(path))
    }

    /// Get metadata for a path in the container filesystem
    pub fn metadata(&self, path: &str) -> io::Result<fs::Metadata> {
        fs::metadata(self.resolve(path))
    }

    /// Detect the container's OS by reading /etc/os-release
    pub fn detect_os(&self) -> Option<ContainerOsInfo> {
        let content = self.read_to_string("/etc/os-release").ok()?;
        parse_os_release(&content)
    }
}

/// Parse /etc/os-release content into ContainerOsInfo
fn parse_os_release(content: &str) -> Option<ContainerOsInfo> {
    let mut id = String::new();
    let mut version = String::new();
    let mut pretty_name = String::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches('"');
            match key {
                "ID" => id = value.to_string(),
                "VERSION_ID" => version = value.to_string(),
                "PRETTY_NAME" => pretty_name = value.to_string(),
                _ => {}
            }
        }
    }

    if id.is_empty() {
        return None;
    }

    if pretty_name.is_empty() {
        pretty_name = format!("{} {}", id, version);
    }

    let eol = check_eol(&id, &version);

    Some(ContainerOsInfo {
        id,
        version,
        pretty_name,
        eol,
    })
}

/// Check if a distro version is known to be end-of-life
fn check_eol(id: &str, version: &str) -> Option<bool> {
    match id {
        "debian" => {
            let ver: u32 = version.parse().ok()?;
            // Debian 10 (buster) and earlier are EOL
            Some(ver <= 10)
        }
        "ubuntu" => {
            // Ubuntu non-LTS releases and old LTS versions
            let eol_versions = [
                "14.04", "16.04", "17.04", "17.10", "18.04", "18.10", "19.04", "19.10", "20.10",
                "21.04", "21.10", "22.10", "23.04", "23.10",
            ];
            Some(eol_versions.contains(&version))
        }
        "centos" => {
            let ver: u32 = version.parse().ok()?;
            // CentOS 7 and earlier are EOL, CentOS 8 is EOL too
            Some(ver <= 8)
        }
        "fedora" => {
            let ver: u32 = version.parse().ok()?;
            // Fedora versions older than ~2 releases back are EOL
            Some(ver <= 39)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_absolute_path() {
        let fs = ContainerFs::new("/var/lib/machines/testcontainer");
        assert_eq!(
            fs.resolve("/etc/os-release"),
            PathBuf::from("/var/lib/machines/testcontainer/etc/os-release")
        );
    }

    #[test]
    fn test_resolve_relative_path() {
        let fs = ContainerFs::new("/var/lib/machines/testcontainer");
        assert_eq!(
            fs.resolve("etc/passwd"),
            PathBuf::from("/var/lib/machines/testcontainer/etc/passwd")
        );
    }

    #[test]
    fn test_parse_os_release_debian() {
        let content = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
"#;
        let info = parse_os_release(content).unwrap();
        assert_eq!(info.id, "debian");
        assert_eq!(info.version, "12");
        assert_eq!(info.pretty_name, "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(info.eol, Some(false));
    }

    #[test]
    fn test_parse_os_release_eol() {
        let content = r#"ID=debian
VERSION_ID="9"
PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
"#;
        let info = parse_os_release(content).unwrap();
        assert_eq!(info.eol, Some(true));
    }

    #[test]
    fn test_parse_os_release_empty() {
        let info = parse_os_release("");
        assert!(info.is_none());
    }
}
