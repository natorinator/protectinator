//! Network service audit for IoT devices
//!
//! Parses `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and
//! `/proc/net/udp6` to identify listening services and flag known botnet
//! ports, unexpected high ports, and services bound to all interfaces.
//! Requires local execution (needs /proc access).

use crate::checks::IotCheck;
use protectinator_container::filesystem::ContainerFs;
use protectinator_core::{Finding, FindingSource, Severity};
use tracing::debug;

/// Known botnet/dangerous ports with their descriptions and severities
const DANGEROUS_PORTS: &[(u16, &str, Severity)] = &[
    (23, "Telnet — common IoT botnet vector (Mirai)", Severity::High),
    (
        48101,
        "Mirai botnet default C2/report-back port",
        Severity::Critical,
    ),
    (
        5555,
        "Android Debug Bridge (ADB) — common IoT exploitation target",
        Severity::High,
    ),
];

/// Common expected ports and their informational descriptions
const EXPECTED_PORTS: &[(u16, &str, Severity)] = &[
    (22, "SSH", Severity::Info),
    (80, "HTTP", Severity::Low),
    (443, "HTTPS", Severity::Info),
    (53, "DNS", Severity::Low),
];

/// Network service audit — requires local execution for /proc access
pub struct NetworkServicesCheck;

impl IotCheck for NetworkServicesCheck {
    fn id(&self) -> &str {
        "iot-network-services"
    }

    fn name(&self) -> &str {
        "Network Services Audit"
    }

    fn requires_local(&self) -> bool {
        true
    }

    fn run(&self, fs: &ContainerFs) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Parse TCP listeners
        parse_proc_net_file(fs, "/proc/net/tcp", "tcp", &mut findings);
        parse_proc_net_file(fs, "/proc/net/tcp6", "tcp6", &mut findings);

        // Parse UDP listeners
        parse_proc_net_file(fs, "/proc/net/udp", "udp", &mut findings);
        parse_proc_net_file(fs, "/proc/net/udp6", "udp6", &mut findings);

        findings
    }
}

fn source() -> FindingSource {
    FindingSource::Hardening {
        check_id: "network-services".to_string(),
        category: "network".to_string(),
    }
}

/// Represents a parsed listening socket entry
#[derive(Debug)]
struct ListeningSocket {
    /// Decoded port number
    port: u16,
    /// Protocol (tcp, tcp6, udp, udp6)
    protocol: String,
    /// Whether it's bound to all interfaces (0.0.0.0 or ::)
    is_all_interfaces: bool,
}

/// Parse a /proc/net/{tcp,tcp6,udp,udp6} file and extract listening sockets
fn parse_proc_net_file(
    fs: &ContainerFs,
    path: &str,
    protocol: &str,
    findings: &mut Vec<Finding>,
) {
    let content = match fs.read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            debug!("Cannot read {} (expected if not running locally): {}", path, e);
            return;
        }
    };

    let sockets = parse_proc_net_entries(&content, protocol);

    for socket in &sockets {
        assess_socket(socket, findings);
    }
}

/// Parse the contents of a /proc/net/ file into listening socket entries.
///
/// Format: `sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`
/// local_address: `hex_ip:hex_port`
/// st: `0A` = LISTEN (TCP), for UDP `07` = CLOSE but all entries are relevant
fn parse_proc_net_entries(content: &str, protocol: &str) -> Vec<ListeningSocket> {
    let is_udp = protocol.starts_with("udp");

    content
        .lines()
        .skip(1) // Skip header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }

            let local_addr = fields[1]; // e.g., "0100007F:0050"
            let state = fields[3]; // e.g., "0A" for LISTEN

            // For TCP, only care about LISTEN state (0A)
            // For UDP, sockets are generally stateless; 07 (CLOSE) is the idle state
            if !is_udp && state != "0A" {
                return None;
            }
            // For UDP, accept both 07 (CLOSE/idle) and 01 (ESTABLISHED)
            // All bound UDP sockets are of interest
            if is_udp && state != "07" && state != "01" {
                return None;
            }

            let (addr_hex, port_hex) = local_addr.split_once(':')?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;

            // Determine if bound to all interfaces
            // IPv4 all-interfaces: "00000000"
            // IPv6 all-interfaces: "00000000000000000000000000000000"
            let is_all = addr_hex.chars().all(|c| c == '0');

            Some(ListeningSocket {
                port,
                protocol: protocol.to_string(),
                is_all_interfaces: is_all,
            })
        })
        .collect()
}

/// Assess a single listening socket and generate findings as appropriate
fn assess_socket(socket: &ListeningSocket, findings: &mut Vec<Finding>) {
    let addr_desc = if socket.is_all_interfaces {
        "all interfaces (0.0.0.0/::)"
    } else {
        "localhost"
    };

    // Check against known dangerous ports
    for (dangerous_port, description, severity) in DANGEROUS_PORTS {
        if socket.port == *dangerous_port {
            findings.push(
                Finding::new(
                    "iot-network-services",
                    format!(
                        "Dangerous port {} open ({}/{})",
                        socket.port, socket.protocol, addr_desc
                    ),
                    format!(
                        "Port {} is listening on {} via {}. {}. \
                         This port is commonly associated with IoT malware or exploitation.",
                        socket.port, addr_desc, socket.protocol, description
                    ),
                    *severity,
                    source(),
                )
                .with_resource(format!("{}:{}", socket.protocol, socket.port))
                .with_remediation(format!(
                    "Investigate and close port {} if not needed. Check for signs of compromise.",
                    socket.port
                ))
                .with_metadata("port", serde_json::json!(socket.port))
                .with_metadata(
                    "protocol",
                    serde_json::Value::String(socket.protocol.clone()),
                )
                .with_metadata("all_interfaces", serde_json::json!(socket.is_all_interfaces))
                .with_reference("https://attack.mitre.org/techniques/T1571/"),
            );
            return; // Already flagged as dangerous, skip further checks
        }
    }

    // Check against known expected ports
    for (expected_port, service_name, severity) in EXPECTED_PORTS {
        if socket.port == *expected_port {
            findings.push(
                Finding::new(
                    "iot-network-services",
                    format!(
                        "{} service on port {} ({}/{})",
                        service_name, socket.port, socket.protocol, addr_desc
                    ),
                    format!(
                        "{} service detected on port {} ({}) bound to {}.",
                        service_name, socket.port, socket.protocol, addr_desc
                    ),
                    *severity,
                    source(),
                )
                .with_resource(format!("{}:{}", socket.protocol, socket.port))
                .with_metadata("port", serde_json::json!(socket.port))
                .with_metadata(
                    "service",
                    serde_json::Value::String(service_name.to_string()),
                )
                .with_metadata(
                    "protocol",
                    serde_json::Value::String(socket.protocol.clone()),
                ),
            );
            return;
        }
    }

    // Flag services listening on all interfaces
    if socket.is_all_interfaces {
        let severity = if socket.port > 10000 {
            Severity::Medium
        } else {
            Severity::Medium
        };

        let title = if socket.port > 10000 {
            format!(
                "Unexpected high port {} listening on all interfaces ({})",
                socket.port, socket.protocol
            )
        } else {
            format!(
                "Port {} listening on all interfaces ({})",
                socket.port, socket.protocol
            )
        };

        let description = if socket.port > 10000 {
            format!(
                "An unknown service on high port {} is listening on all interfaces \
                 via {}. High ports listening externally may indicate a backdoor or \
                 unauthorized service.",
                socket.port, socket.protocol
            )
        } else {
            format!(
                "Port {} is listening on all interfaces via {}. Services exposed \
                 to all interfaces are accessible from the network.",
                socket.port, socket.protocol
            )
        };

        findings.push(
            Finding::new(
                "iot-network-services",
                title,
                description,
                severity,
                source(),
            )
            .with_resource(format!("{}:{}", socket.protocol, socket.port))
            .with_remediation(format!(
                "Verify port {} is expected. Bind to localhost if not needed externally.",
                socket.port
            ))
            .with_metadata("port", serde_json::json!(socket.port))
            .with_metadata(
                "protocol",
                serde_json::Value::String(socket.protocol.clone()),
            )
            .with_metadata("all_interfaces", serde_json::json!(true)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_container(tmp: &TempDir) -> ContainerFs {
        ContainerFs::new(tmp.path())
    }

    /// Create a /proc/net/tcp line with the given hex address, hex port, and state
    fn make_tcp_line(sl: u32, local_addr: &str, local_port: u16, state: &str) -> String {
        let port_hex = format!("{:04X}", local_port);
        format!(
            "  {}: {}:{} 00000000:0000 {} 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0",
            sl, local_addr, port_hex, state
        )
    }

    #[test]
    fn test_detects_telnet_listener() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let proc_net = root.join("proc/net");
        fs::create_dir_all(&proc_net).unwrap();

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        // Telnet on port 23, listening on all interfaces, LISTEN state (0A)
        let line = make_tcp_line(0, "00000000", 23, "0A");

        fs::write(proc_net.join("tcp"), format!("{}\n{}\n", header, line)).unwrap();
        // Empty tcp6/udp/udp6 so they don't error
        fs::write(proc_net.join("tcp6"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp6"), format!("{}\n", header)).unwrap();

        let cfs = setup_container(&tmp);
        let check = NetworkServicesCheck;
        let findings = check.run(&cfs);

        let telnet = findings
            .iter()
            .find(|f| f.title.contains("Dangerous port 23"));
        assert!(telnet.is_some(), "Should detect telnet listener");
        assert_eq!(telnet.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_detects_mirai_port() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let proc_net = root.join("proc/net");
        fs::create_dir_all(&proc_net).unwrap();

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        // Mirai C2 port 48101, listening on all interfaces
        let line = make_tcp_line(0, "00000000", 48101, "0A");

        fs::write(proc_net.join("tcp"), format!("{}\n{}\n", header, line)).unwrap();
        fs::write(proc_net.join("tcp6"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp6"), format!("{}\n", header)).unwrap();

        let cfs = setup_container(&tmp);
        let check = NetworkServicesCheck;
        let findings = check.run(&cfs);

        let mirai = findings
            .iter()
            .find(|f| f.title.contains("48101"));
        assert!(mirai.is_some(), "Should detect Mirai port");
        assert_eq!(mirai.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_detects_all_interfaces_listener() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let proc_net = root.join("proc/net");
        fs::create_dir_all(&proc_net).unwrap();

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        // Unknown service on port 8080 listening on all interfaces
        let line = make_tcp_line(0, "00000000", 8080, "0A");

        fs::write(proc_net.join("tcp"), format!("{}\n{}\n", header, line)).unwrap();
        fs::write(proc_net.join("tcp6"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp6"), format!("{}\n", header)).unwrap();

        let cfs = setup_container(&tmp);
        let check = NetworkServicesCheck;
        let findings = check.run(&cfs);

        let all_ifaces = findings
            .iter()
            .find(|f| f.title.contains("8080") && f.title.contains("all interfaces"));
        assert!(
            all_ifaces.is_some(),
            "Should detect service on all interfaces"
        );
        assert_eq!(all_ifaces.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_ignores_non_listen_state() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let proc_net = root.join("proc/net");
        fs::create_dir_all(&proc_net).unwrap();

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        // State 01 = ESTABLISHED, not LISTEN
        let line = make_tcp_line(0, "00000000", 23, "01");

        fs::write(proc_net.join("tcp"), format!("{}\n{}\n", header, line)).unwrap();
        fs::write(proc_net.join("tcp6"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp6"), format!("{}\n", header)).unwrap();

        let cfs = setup_container(&tmp);
        let check = NetworkServicesCheck;
        let findings = check.run(&cfs);

        let telnet = findings
            .iter()
            .find(|f| f.title.contains("port 23"));
        assert!(
            telnet.is_none(),
            "Should not flag ESTABLISHED connections"
        );
    }

    #[test]
    fn test_detects_high_port_all_interfaces() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let proc_net = root.join("proc/net");
        fs::create_dir_all(&proc_net).unwrap();

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        // High port 31337 on all interfaces
        let line = make_tcp_line(0, "00000000", 31337, "0A");

        fs::write(proc_net.join("tcp"), format!("{}\n{}\n", header, line)).unwrap();
        fs::write(proc_net.join("tcp6"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp6"), format!("{}\n", header)).unwrap();

        let cfs = setup_container(&tmp);
        let check = NetworkServicesCheck;
        let findings = check.run(&cfs);

        let high_port = findings
            .iter()
            .find(|f| f.title.contains("Unexpected high port 31337"));
        assert!(
            high_port.is_some(),
            "Should detect unexpected high port"
        );
    }

    #[test]
    fn test_ssh_is_info_severity() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let proc_net = root.join("proc/net");
        fs::create_dir_all(&proc_net).unwrap();

        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        // SSH on port 22, localhost only
        let line = make_tcp_line(0, "0100007F", 22, "0A");

        fs::write(proc_net.join("tcp"), format!("{}\n{}\n", header, line)).unwrap();
        fs::write(proc_net.join("tcp6"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp"), format!("{}\n", header)).unwrap();
        fs::write(proc_net.join("udp6"), format!("{}\n", header)).unwrap();

        let cfs = setup_container(&tmp);
        let check = NetworkServicesCheck;
        let findings = check.run(&cfs);

        let ssh = findings.iter().find(|f| f.title.contains("SSH"));
        assert!(ssh.is_some(), "Should detect SSH service");
        assert_eq!(ssh.unwrap().severity, Severity::Info);
    }

    #[test]
    fn test_parse_proc_net_entries() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 00000000:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0";

        let sockets = parse_proc_net_entries(content, "tcp");

        // Should find 2 LISTEN entries (state 0A), not the ESTABLISHED (01) one
        assert_eq!(sockets.len(), 2);

        // Port 22 (0x0016) on all interfaces
        assert_eq!(sockets[0].port, 22);
        assert!(sockets[0].is_all_interfaces);

        // Port 53 (0x0035) on localhost
        assert_eq!(sockets[1].port, 53);
        assert!(!sockets[1].is_all_interfaces);
    }
}
