//! SSH command execution wrapper
//!
//! Uses the system `ssh` command to inherit the user's SSH configuration,
//! agent forwarding, ProxyJump settings, and key management.

use crate::types::RemoteHost;
use std::process::Command;
use tracing::{debug, warn};

/// Execute a command on a remote host via SSH
pub fn ssh_exec(host: &RemoteHost, command: &str) -> Result<String, String> {
    let mut cmd = Command::new("ssh");

    // Batch mode: no interactive prompts
    cmd.arg("-o").arg("BatchMode=yes");
    // Connection timeout
    cmd.arg("-o").arg("ConnectTimeout=10");
    // Suppress warnings
    cmd.arg("-o").arg("LogLevel=ERROR");

    // Port
    if host.port != 22 {
        cmd.arg("-p").arg(host.port.to_string());
    }

    // Key file
    if let Some(ref key) = host.key_path {
        cmd.arg("-i").arg(key);
    }

    // Destination and command
    cmd.arg(host.ssh_dest());
    cmd.arg(command);

    debug!("SSH exec: ssh {} '{}'", host.ssh_dest(), command);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run ssh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.contains("Permission denied") {
            return Err(format!(
                "SSH authentication failed for {}. Check your SSH key or agent.",
                host.ssh_dest()
            ));
        }
        if stderr.contains("Connection refused") || stderr.contains("Connection timed out") {
            return Err(format!(
                "Cannot connect to {} on port {}. Check the host is reachable and SSH is running.",
                host.hostname, host.port
            ));
        }
        return Err(format!("SSH command failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Execute a command on a remote host, returning empty string on failure
pub fn ssh_exec_optional(host: &RemoteHost, command: &str) -> String {
    match ssh_exec(host, command) {
        Ok(output) => output,
        Err(e) => {
            debug!("Optional SSH command failed: {}", e);
            String::new()
        }
    }
}

/// Test SSH connectivity to a host
pub fn test_connection(host: &RemoteHost) -> Result<(), String> {
    ssh_exec(host, "echo ok").map(|_| ())
}

/// Check if protectinator is installed on the remote host
pub fn has_protectinator(host: &RemoteHost) -> bool {
    match ssh_exec(host, "which protectinator 2>/dev/null || command -v protectinator 2>/dev/null") {
        Ok(output) => !output.trim().is_empty(),
        Err(_) => false,
    }
}

/// Read a file from the remote host, returning None if it doesn't exist
pub fn read_remote_file(host: &RemoteHost, path: &str) -> Option<String> {
    match ssh_exec(host, &format!("cat {} 2>/dev/null", path)) {
        Ok(content) if !content.is_empty() => Some(content),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_command_construction() {
        let host = RemoteHost::new("example.com")
            .with_user("admin")
            .with_port(2222)
            .with_key("/home/user/.ssh/id_ed25519");

        // We can't test actual SSH connectivity, but we can verify the host config
        assert_eq!(host.ssh_dest(), "admin@example.com");
        assert_eq!(host.port, 2222);
        assert_eq!(host.key_path.unwrap().display().to_string(), "/home/user/.ssh/id_ed25519");
    }
}
