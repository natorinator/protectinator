//! Open ports check
//!
//! Compares listening ports against allowed_services from fleet config.
//! Flags any service not in the allow list.

use crate::audit::HostContext;
use protectinator_core::{Finding, FindingSource, Severity};

/// Parse an allowed_services entry like "ssh:22" or "http:8090" into port number
fn parse_allowed_port(service: &str) -> Option<u16> {
    // Format: "protocol:port" or just "ssh" (implies 22)
    if service == "ssh" {
        return Some(22);
    }
    service.split(':').last()?.parse().ok()
}

/// Parse ss -tlnp output into (port, process_name) pairs
fn parse_ss_output(output: &str) -> Vec<(u16, String)> {
    let mut ports = Vec::new();
    for line in output.lines().skip(1) { // skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Local address is typically parts[3], format: "0.0.0.0:80" or "*:80" or "[::]:80"
        let local_addr = parts[3];
        let port_str = local_addr.rsplit(':').next().unwrap_or("");
        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip loopback-only listeners (127.0.0.1)
        if local_addr.starts_with("127.") {
            continue;
        }

        // Process name from the last column, format: users:(("nginx",pid=123,fd=4))
        let process = parts.last()
            .map(|p| {
                p.trim_start_matches("users:((\"")
                    .split('"')
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".to_string());

        ports.push((port, process));
    }
    ports
}

pub fn check_open_ports(run: &dyn Fn(&str) -> Option<String>, ctx: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let output = match run("ss -tlnp 2>/dev/null") {
        Some(o) => o,
        None => return findings,
    };

    let listening = parse_ss_output(&output);
    let allowed_ports: Vec<u16> = ctx.allowed_services.iter()
        .filter_map(|s| parse_allowed_port(s))
        .collect();

    for (port, process) in &listening {
        if !allowed_ports.contains(port) {
            findings.push(Finding::new(
                format!("defense-unexpected-port-{}", port),
                format!("Unexpected service on port {} ({})", port, ctx.name),
                format!(
                    "Process '{}' is listening on port {} which is not in allowed_services. \
                     If this service is intentional, add it to fleet.toml. Otherwise, stop the service.",
                    process, port
                ),
                ctx.escalate_severity(Severity::Medium),
                FindingSource::Defense {
                    check_category: "open_ports".to_string(),
                    host: Some(ctx.name.clone()),
                },
            )
            .with_resource(format!("host:{}:{}/{}", ctx.name, port, process))
            .with_remediation(format!(
                "If intentional, add to fleet.toml: allowed_services = [..., \"tcp:{}\"]", port
            )));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allowed_port() {
        assert_eq!(parse_allowed_port("ssh:22"), Some(22));
        assert_eq!(parse_allowed_port("http:8090"), Some(8090));
        assert_eq!(parse_allowed_port("ssh"), Some(22));
        assert_eq!(parse_allowed_port("invalid"), None);
    }

    #[test]
    fn test_parse_ss_output() {
        let output = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nLISTEN 0      128    0.0.0.0:22           0.0.0.0:*     users:((\"sshd\",pid=1234,fd=3))\nLISTEN 0      128    127.0.0.1:8080       0.0.0.0:*     users:((\"node\",pid=5678,fd=4))\nLISTEN 0      128    0.0.0.0:443          0.0.0.0:*     users:((\"nginx\",pid=9012,fd=5))";
        let ports = parse_ss_output(output);
        // Should have 22 and 443 (8080 is loopback, skipped)
        assert_eq!(ports.len(), 2);
        assert!(ports.iter().any(|(p, _)| *p == 22));
        assert!(ports.iter().any(|(p, _)| *p == 443));
    }

    #[test]
    fn test_unexpected_port_flagged() {
        let run = |cmd: &str| -> Option<String> {
            if cmd.contains("ss -tlnp") {
                Some("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\nLISTEN 0 128 0.0.0.0:3306 0.0.0.0:* users:((\"mysqld\",pid=2,fd=4))".to_string())
            } else {
                None
            }
        };
        let ctx = HostContext {
            name: "test".into(),
            tags: vec![],
            allowed_services: vec!["ssh:22".to_string()],
        };
        let findings = check_open_ports(&run, &ctx);
        assert_eq!(findings.len(), 1); // mysql on 3306 is unexpected
        assert!(findings[0].description.contains("3306"));
    }

    #[test]
    fn test_all_ports_allowed() {
        let run = |cmd: &str| -> Option<String> {
            if cmd.contains("ss -tlnp") {
                Some("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))".to_string())
            } else {
                None
            }
        };
        let ctx = HostContext {
            name: "test".into(),
            tags: vec![],
            allowed_services: vec!["ssh:22".to_string()],
        };
        assert!(check_open_ports(&run, &ctx).is_empty());
    }
}
