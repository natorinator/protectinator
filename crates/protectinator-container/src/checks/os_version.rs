//! OS version and currency checks
//!
//! Verifies that the container is running a supported OS version
//! and flags end-of-life distributions.

use crate::checks::ContainerCheck;
use crate::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};

/// Known end-of-life dates for major distributions
/// Format: (id, version, eol_date_description)
const EOL_VERSIONS: &[(&str, &str, &str)] = &[
    // Debian
    ("debian", "6", "Debian 6 (squeeze) — EOL February 2016"),
    ("debian", "7", "Debian 7 (wheezy) — EOL May 2018"),
    ("debian", "8", "Debian 8 (jessie) — EOL June 2020"),
    ("debian", "9", "Debian 9 (stretch) — EOL June 2022"),
    ("debian", "10", "Debian 10 (buster) — EOL June 2024"),
    // Ubuntu
    ("ubuntu", "14.04", "Ubuntu 14.04 (Trusty) — EOL April 2019"),
    ("ubuntu", "16.04", "Ubuntu 16.04 (Xenial) — EOL April 2021"),
    ("ubuntu", "18.04", "Ubuntu 18.04 (Bionic) — EOL May 2023"),
    ("ubuntu", "18.10", "Ubuntu 18.10 (Cosmic) — EOL July 2019"),
    ("ubuntu", "19.04", "Ubuntu 19.04 (Disco) — EOL January 2020"),
    ("ubuntu", "19.10", "Ubuntu 19.10 (Eoan) — EOL July 2020"),
    ("ubuntu", "20.10", "Ubuntu 20.10 (Groovy) — EOL July 2021"),
    ("ubuntu", "21.04", "Ubuntu 21.04 (Hirsute) — EOL January 2022"),
    ("ubuntu", "21.10", "Ubuntu 21.10 (Impish) — EOL July 2022"),
    ("ubuntu", "22.10", "Ubuntu 22.10 (Kinetic) — EOL July 2023"),
    ("ubuntu", "23.04", "Ubuntu 23.04 (Lunar) — EOL January 2024"),
    ("ubuntu", "23.10", "Ubuntu 23.10 (Mantic) — EOL July 2024"),
    // CentOS
    ("centos", "6", "CentOS 6 — EOL November 2020"),
    ("centos", "7", "CentOS 7 — EOL June 2024"),
    ("centos", "8", "CentOS 8 — EOL December 2021"),
    // Fedora (approximate — only list clearly EOL versions)
    ("fedora", "36", "Fedora 36 — EOL May 2023"),
    ("fedora", "37", "Fedora 37 — EOL December 2023"),
    ("fedora", "38", "Fedora 38 — EOL May 2024"),
    ("fedora", "39", "Fedora 39 — EOL November 2024"),
    // Alpine
    ("alpine", "3.14", "Alpine 3.14 — EOL May 2023"),
    ("alpine", "3.15", "Alpine 3.15 — EOL November 2023"),
    ("alpine", "3.16", "Alpine 3.16 — EOL May 2024"),
    ("alpine", "3.17", "Alpine 3.17 — EOL November 2024"),
];

/// Check the container's OS version for support status
pub struct OsVersionCheck;

impl ContainerCheck for OsVersionCheck {
    fn id(&self) -> &str {
        "container-os-version"
    }

    fn name(&self) -> &str {
        "Container OS Version Check"
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        let os_info = match fs.detect_os() {
            Some(info) => info,
            None => {
                findings.push(Finding::new(
                    "container-os-unknown",
                    "Could not determine container OS",
                    "Unable to read /etc/os-release from the container. OS version auditing not possible.",
                    Severity::Info,
                    FindingSource::OsVerification {
                        manifest_source: "os-release".to_string(),
                    },
                ));
                return findings;
            }
        };

        // Report the detected OS
        findings.push(Finding::new(
            "container-os-detected",
            format!("Container OS: {}", os_info.pretty_name),
            format!(
                "Detected OS: {} version {} ({})",
                os_info.id, os_info.version, os_info.pretty_name
            ),
            Severity::Info,
            FindingSource::OsVerification {
                manifest_source: "os-release".to_string(),
            },
        ));

        // Check against known EOL versions
        for (eol_id, eol_version, eol_desc) in EOL_VERSIONS {
            if os_info.id == *eol_id && os_info.version == *eol_version {
                findings.push(
                    Finding::new(
                        "container-os-eol",
                        format!("Container running end-of-life OS: {}", os_info.pretty_name),
                        format!(
                            "{}. This OS version no longer receives security updates. \
                             The container should be upgraded to a supported version.",
                            eol_desc
                        ),
                        Severity::High,
                        FindingSource::OsVerification {
                            manifest_source: "os-release".to_string(),
                        },
                    )
                    .with_remediation(format!(
                        "Upgrade the container to a supported version of {}",
                        os_info.id
                    )),
                );
                break;
            }
        }

        findings
    }
}
