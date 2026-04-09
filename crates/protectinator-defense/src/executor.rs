//! Remediation plan executor
//!
//! Executes approved plans via SSH with safety checks and stop-on-failure.

use crate::remediate::{RemediationAction, RemediationPlan};
use protectinator_remote::ssh;
use protectinator_remote::types::RemoteHost;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

/// Result of executing a single action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_index: usize,
    pub command: String,
    pub description: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Result of executing a full plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub plan_id: i64,
    pub host: String,
    pub success: bool,
    pub actions_completed: usize,
    pub actions_total: usize,
    pub action_results: Vec<ActionResult>,
    pub duration_ms: u64,
}

/// Execute an approved remediation plan on a remote host
pub fn execute_plan(
    plan: &RemediationPlan,
    plan_id: i64,
    host: &RemoteHost,
    dry_run: bool,
) -> ExecutionResult {
    let start = std::time::Instant::now();
    let actions: Vec<RemediationAction> = plan.actions.clone();
    let mut action_results = Vec::new();
    let mut all_success = true;

    if dry_run {
        info!("Dry-run mode — commands will not be executed");
    }

    // Static safety check: if plan contains firewall enable, verify SSH is in the allow list
    // This runs before any SSH calls to catch dangerous plans immediately.
    let has_fw_enable = actions
        .iter()
        .any(|a| matches!(a, RemediationAction::FirewallEnable { .. }));
    let has_ssh_allow = actions
        .iter()
        .any(|a| matches!(a, RemediationAction::FirewallAllow { port: 22, .. }));
    if has_fw_enable && !has_ssh_allow {
        error!("Safety check failed: plan enables firewall but does not allow SSH port 22");
        return ExecutionResult {
            plan_id,
            host: plan.host.clone(),
            success: false,
            actions_completed: 0,
            actions_total: actions.len(),
            action_results: vec![ActionResult {
                action_index: 0,
                command: String::new(),
                description: "Safety check: SSH must be allowed before enabling firewall"
                    .to_string(),
                success: false,
                output: String::new(),
                error: Some(
                    "Plan would enable firewall without allowing SSH — aborting to prevent lockout"
                        .to_string(),
                ),
                duration_ms: 0,
            }],
            duration_ms: start.elapsed().as_millis() as u64,
        };
    }

    // Pre-flight: verify SSH connectivity
    if !dry_run {
        match ssh::ssh_exec_timeout(host, "echo protectinator-preflight-ok", 15) {
            Ok(output) if output.contains("protectinator-preflight-ok") => {
                info!("Pre-flight SSH check passed for {}", host.display_name());
            }
            Ok(_) => {
                warn!("Pre-flight SSH check returned unexpected output");
            }
            Err(e) => {
                error!(
                    "Pre-flight SSH check failed for {}: {}",
                    host.display_name(),
                    e
                );
                return ExecutionResult {
                    plan_id,
                    host: plan.host.clone(),
                    success: false,
                    actions_completed: 0,
                    actions_total: actions.len(),
                    action_results: vec![ActionResult {
                        action_index: 0,
                        command: "echo protectinator-preflight-ok".to_string(),
                        description: "Pre-flight SSH connectivity check".to_string(),
                        success: false,
                        output: String::new(),
                        error: Some(format!("SSH pre-flight failed: {}", e)),
                        duration_ms: 0,
                    }],
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        }
    }

    // Execute actions sequentially
    for (i, action) in actions.iter().enumerate() {
        let cmd = action.to_command();
        let desc = action.describe().to_string();
        let action_start = std::time::Instant::now();

        if dry_run {
            info!("[{}/{}] Would run: {}", i + 1, actions.len(), cmd);
            action_results.push(ActionResult {
                action_index: i,
                command: cmd,
                description: desc,
                success: true,
                output: "(dry-run)".to_string(),
                error: None,
                duration_ms: 0,
            });
            continue;
        }

        info!("[{}/{}] Executing: {}", i + 1, actions.len(), desc);

        // Use longer timeout for package installs (up to 5 minutes)
        let timeout = match action {
            RemediationAction::InstallPackage { .. } => 300,
            RemediationAction::RunCommand { .. } => 120,
            _ => 60,
        };

        match ssh::ssh_exec_timeout(host, &cmd, timeout) {
            Ok(output) => {
                let duration = action_start.elapsed().as_millis() as u64;
                info!("[{}/{}] Success ({} ms)", i + 1, actions.len(), duration);
                action_results.push(ActionResult {
                    action_index: i,
                    command: cmd,
                    description: desc,
                    success: true,
                    output: output.trim().to_string(),
                    error: None,
                    duration_ms: duration,
                });
            }
            Err(e) => {
                let duration = action_start.elapsed().as_millis() as u64;
                error!("[{}/{}] FAILED: {}", i + 1, actions.len(), e);
                action_results.push(ActionResult {
                    action_index: i,
                    command: cmd,
                    description: desc,
                    success: false,
                    output: String::new(),
                    error: Some(e.to_string()),
                    duration_ms: duration,
                });
                all_success = false;
                break; // Stop on failure
            }
        }
    }

    // Post-flight: verify SSH still works (only if we changed firewall)
    if !dry_run && has_fw_enable && all_success {
        match ssh::ssh_exec_timeout(host, "echo protectinator-postflight-ok", 15) {
            Ok(output) if output.contains("protectinator-postflight-ok") => {
                info!("Post-flight SSH check passed — host still accessible");
            }
            _ => {
                warn!("Post-flight SSH check failed — host may have restricted access");
            }
        }
    }

    let completed = action_results.iter().filter(|r| r.success).count();

    ExecutionResult {
        plan_id,
        host: plan.host.clone(),
        success: all_success,
        actions_completed: completed,
        actions_total: actions.len(),
        action_results,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediate::PlanStatus;

    #[test]
    fn test_ssh_safety_check_blocks_unsafe_plan() {
        // Plan that enables firewall without SSH allow should fail safety check
        let plan = RemediationPlan {
            id: Some(1),
            host: "test".to_string(),
            created_at: "2026-01-01".to_string(),
            status: PlanStatus::Approved,
            actions: vec![RemediationAction::FirewallEnable {
                description: "Enable firewall".to_string(),
            }],
            source_findings: vec![],
        };

        let host = RemoteHost::new("test").with_sudo(true);
        // Non-dry-run would try SSH, so test with dry_run=false but
        // the safety check fires before any SSH call
        let result = execute_plan(&plan, 1, &host, false);
        assert!(!result.success);
        assert_eq!(result.actions_completed, 0);
        assert!(result.action_results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("firewall without allowing SSH"));
    }

    #[test]
    fn test_dry_run_succeeds_all_actions() {
        let plan = RemediationPlan {
            id: Some(2),
            host: "test".to_string(),
            created_at: "2026-01-01".to_string(),
            status: PlanStatus::Approved,
            actions: vec![
                RemediationAction::InstallPackage {
                    package: "sshguard".to_string(),
                    description: "Install sshguard".to_string(),
                },
                RemediationAction::EnableService {
                    service: "sshguard".to_string(),
                    description: "Enable sshguard".to_string(),
                },
            ],
            source_findings: vec![],
        };

        let host = RemoteHost::new("test");
        let result = execute_plan(&plan, 2, &host, true);
        assert!(result.success);
        assert_eq!(result.actions_completed, 2);
        assert_eq!(result.actions_total, 2);
        for ar in &result.action_results {
            assert!(ar.success);
            assert_eq!(ar.output, "(dry-run)");
        }
    }

    #[test]
    fn test_safe_plan_with_ssh_allow_passes_safety_check() {
        // Plan that allows SSH before enabling firewall should pass
        let plan = RemediationPlan {
            id: Some(3),
            host: "test".to_string(),
            created_at: "2026-01-01".to_string(),
            status: PlanStatus::Approved,
            actions: vec![
                RemediationAction::FirewallAllow {
                    port: 22,
                    protocol: "tcp".to_string(),
                    comment: "Allow SSH".to_string(),
                },
                RemediationAction::FirewallEnable {
                    description: "Enable firewall".to_string(),
                },
            ],
            source_findings: vec![],
        };

        let host = RemoteHost::new("test");
        let result = execute_plan(&plan, 3, &host, true);
        assert!(result.success);
        assert_eq!(result.actions_completed, 2);
    }
}
