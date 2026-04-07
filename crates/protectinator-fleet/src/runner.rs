//! Fleet scan orchestration

use crate::config::FleetConfig;
use crate::notify;
use crate::types::*;
use protectinator_container::discover::list_all_containers;
use protectinator_container::types::{ContainerRuntime, ContainerState};
use protectinator_container::ContainerScanner;
use protectinator_core::suppress::Suppressions;
use protectinator_data::ScanStore;
use protectinator_remote::{RemoteScanner, ScanMode};
use rayon::prelude::*;
use std::sync::Mutex;
use std::time::Instant;
use protectinator_supply_chain::enrich;
use tracing::{error, info, warn};

/// Options for filtering what to scan
#[derive(Debug, Clone, Default)]
pub struct FleetScanOptions {
    pub hosts_only: bool,
    pub containers_only: bool,
    pub repos_only: bool,
    pub offline: bool,
}

/// Fleet scanner
pub struct FleetRunner {
    config: FleetConfig,
}

impl FleetRunner {
    pub fn new(config: FleetConfig) -> Self {
        Self { config }
    }

    /// Run a complete fleet scan
    pub fn scan(&self, opts: &FleetScanOptions) -> FleetScanResults {
        let start = Instant::now();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let offline = opts.offline || self.config.settings.offline;

        // Load suppressions
        let suppressions = Suppressions::load_default();

        // Open DB for storing results
        let db = if self.config.settings.save_history {
            protectinator_data::default_data_dir()
                .ok()
                .and_then(|dir| ScanStore::open(&dir.join("scan_history.db")).ok())
        } else {
            None
        };
        let db = Mutex::new(db);

        // Scan hosts in parallel (also returns remote container results)
        let (host_results, remote_container_results) = if !opts.containers_only && !opts.repos_only {
            self.scan_hosts(&db, offline, &suppressions)
        } else {
            (Vec::new(), Vec::new())
        };

        // Scan local containers + merge remote container results
        let mut container_results = if !opts.hosts_only && !opts.repos_only {
            self.scan_containers(&db, offline, &suppressions)
        } else {
            Vec::new()
        };
        container_results.extend(remote_container_results);

        // Scan repos (sequential)
        let repo_results = if !opts.hosts_only && !opts.containers_only {
            self.scan_repos(&db, offline, &suppressions)
        } else {
            Vec::new()
        };

        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = FleetSummary::from_results(
            &host_results,
            &container_results,
            &repo_results,
            duration_ms,
        );

        let results = FleetScanResults {
            timestamp,
            host_results,
            container_results,
            repo_results,
            summary,
        };

        // Send webhook notifications if configured
        if let Some(ref webhook) = self.config.notifications.webhook {
            let notifiable = collect_notifiable(&results);
            if !notifiable.new_critical.is_empty() || !notifiable.new_high.is_empty() {
                if let Err(e) = notify::send_webhook(webhook, &results, &notifiable) {
                    warn!("Failed to send webhook notification: {}", e);
                }
            }
        }

        results
    }

    /// Scan remote hosts in parallel using rayon
    /// Returns (host_results, remote_container_results)
    fn scan_hosts(
        &self,
        db: &Mutex<Option<ScanStore>>,
        offline: bool,
        suppressions: &Suppressions,
    ) -> (Vec<FleetTargetResult>, Vec<FleetTargetResult>) {
        if self.config.hosts.is_empty() {
            return (Vec::new(), Vec::new());
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.settings.parallel)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

        let all_results = pool.install(|| {
            self.config
                .hosts
                .par_iter()
                .map(|entry| {
                    let host = FleetConfig::host_to_remote(entry);
                    info!("Scanning host: {}", entry.name);
                    let start = Instant::now();

                    let scanner = RemoteScanner::new(host, ScanMode::Agentless)
                        .skip_vulnerability(offline);

                    match scanner.scan() {
                        Ok(mut results) => {
                            let duration_ms = start.elapsed().as_millis() as u64;
                            let scan_key = format!("remote:{}", entry.name);

                            // Apply suppressions
                            results.scan_results.findings = suppressions.filter(
                                std::mem::take(&mut results.scan_results.findings),
                                Some(&scan_key),
                            );

                            // Enrich with CVE intelligence
                            if !offline {
                                let enriched = enrich::enrich_findings_with_debian_intel(
                                    &mut results.scan_results.findings,
                                    None,
                                );
                                if enriched > 0 {
                                    info!("Enriched {} findings for host {}", enriched, entry.name);
                                }
                            }

                            // Store results (after suppression)
                            if let Ok(guard) = db.lock() {
                                if let Some(ref store) = *guard {
                                    if let Err(e) = store.store_scan_with_tags(
                                        &scan_key,
                                        &results.scan_results.findings,
                                        0,
                                        &entry.tags,
                                    ) {
                                        warn!("Failed to store scan for {}: {}", entry.name, e);
                                    }
                                }
                            }

                            let result = FleetTargetResult::from_findings(
                                entry.name.clone(),
                                "remote",
                                &results.scan_results.findings,
                                duration_ms,
                            );

                            info!(
                                "Host {} complete: {} findings in {}ms",
                                entry.name, result.total_findings, duration_ms
                            );

                            // Also scan containers on this host if configured
                            let mut all_results = vec![result];
                            if entry.scan_containers {
                                let container_findings =
                                    scan_remote_containers(entry, suppressions, db);
                                all_results.extend(container_findings);
                            }
                            all_results
                        }
                        Err(e) => {
                            error!("Host {} failed: {}", entry.name, e);
                            vec![FleetTargetResult::error(
                                entry.name.clone(),
                                "remote",
                                e.to_string(),
                            )]
                        }
                    }
                })
                .flatten()
                .collect::<Vec<FleetTargetResult>>()
        });

        // Separate host results from remote container results
        let (hosts, containers): (Vec<_>, Vec<_>) = all_results
            .into_iter()
            .partition(|r| r.target_type != "container");
        (hosts, containers)
    }

    /// Scan containers sequentially
    fn scan_containers(
        &self,
        db: &Mutex<Option<ScanStore>>,
        offline: bool,
        suppressions: &Suppressions,
    ) -> Vec<FleetTargetResult> {
        if !self.config.containers.scan_all && self.config.containers.names.is_empty() {
            return Vec::new();
        }

        let containers = list_all_containers();
        if containers.is_empty() {
            return Vec::new();
        }

        let scanner = ContainerScanner::new().skip_vulnerability(offline);

        let targets: Vec<_> = if self.config.containers.scan_all {
            containers.iter().collect()
        } else {
            containers
                .iter()
                .filter(|c| self.config.containers.names.contains(&c.name))
                .collect()
        };

        // Filter by runtime if specified
        let targets: Vec<_> = if let Some(ref rt) = self.config.containers.runtime {
            targets
                .into_iter()
                .filter(|c| {
                    match rt.as_str() {
                        "nspawn" => c.runtime == ContainerRuntime::Nspawn,
                        "docker" => c.runtime == ContainerRuntime::Docker,
                        _ => true,
                    }
                })
                .collect()
        } else {
            targets
        };

        targets
            .iter()
            .filter_map(|target| {
                // Skip inaccessible containers
                if target.runtime == ContainerRuntime::Docker
                    && target.state != ContainerState::Running
                {
                    return None;
                }
                if !target.root_path.is_dir() {
                    return None;
                }

                info!("Scanning container: {}", target.name);
                let start = Instant::now();
                let mut scan_results = scanner.scan(target);
                let duration_ms = start.elapsed().as_millis() as u64;

                let scan_key = format!("container:{}", target.name);

                // Apply suppressions
                scan_results.scan_results.findings = suppressions.filter(
                    std::mem::take(&mut scan_results.scan_results.findings),
                    Some(&scan_key),
                );

                // Enrich with CVE intelligence
                if !offline {
                    let enriched = enrich::enrich_findings_with_debian_intel(
                        &mut scan_results.scan_results.findings,
                        None,
                    );
                    if enriched > 0 {
                        info!("Enriched {} findings for container {}", enriched, target.name);
                    }
                }

                // Store results
                if let Ok(guard) = db.lock() {
                    if let Some(ref store) = *guard {
                        if let Err(e) =
                            store.store_scan(&scan_key, &scan_results.scan_results.findings, 0)
                        {
                            warn!("Failed to store scan for {}: {}", target.name, e);
                        }
                    }
                }

                let result = FleetTargetResult::from_findings(
                    target.name.clone(),
                    "container",
                    &scan_results.scan_results.findings,
                    duration_ms,
                );

                info!(
                    "Container {} complete: {} findings in {}ms",
                    target.name, result.total_findings, duration_ms
                );

                Some(result)
            })
            .collect()
    }

    /// Scan supply-chain repos sequentially
    fn scan_repos(
        &self,
        db: &Mutex<Option<ScanStore>>,
        offline: bool,
        suppressions: &Suppressions,
    ) -> Vec<FleetTargetResult> {
        if self.config.repos.is_empty() {
            return Vec::new();
        }

        self.config
            .repos
            .iter()
            .map(|entry| {
                let path = FleetConfig::expand_path(&entry.path);
                let name = path.display().to_string();

                if !path.exists() {
                    return FleetTargetResult::error(
                        name,
                        "repo",
                        format!("Path does not exist: {}", path.display()),
                    );
                }

                info!("Scanning repo: {}", path.display());
                let start = Instant::now();

                let mut scanner = protectinator_supply_chain::SupplyChainScanner::new(path.clone());
                if offline {
                    scanner = scanner.offline(true);
                }
                if let Some(ref eco) = entry.ecosystem {
                    scanner = scanner.ecosystem(Some(eco.clone()));
                }

                let mut results = scanner.scan();

                // Also run secrets scanning on the repo
                let secrets_findings = protectinator_secrets::SecretsScanner::new(path.clone())
                    .scan();
                results.scan_results.findings.extend(secrets_findings);

                let duration_ms = start.elapsed().as_millis() as u64;
                let scan_key = path
                    .canonicalize()
                    .unwrap_or(path.clone())
                    .display()
                    .to_string();

                // Apply suppressions
                results.scan_results.findings = suppressions.filter(
                    std::mem::take(&mut results.scan_results.findings),
                    Some(&scan_key),
                );

                // Enrich with CVE intelligence
                if !offline {
                    let enriched = enrich::enrich_findings_with_debian_intel(
                        &mut results.scan_results.findings,
                        None,
                    );
                    if enriched > 0 {
                        info!("Enriched {} findings for repo {}", enriched, name);
                    }
                }

                // Store results
                if let Ok(guard) = db.lock() {
                    if let Some(ref store) = *guard {
                        if let Err(e) = store.store_scan(
                            &scan_key,
                            &results.scan_results.findings,
                            results.packages_scanned,
                        ) {
                            warn!("Failed to store scan for {}: {}", name, e);
                        }
                    }
                }

                let result = FleetTargetResult::from_findings(
                    name.clone(),
                    "repo",
                    &results.scan_results.findings,
                    duration_ms,
                );

                info!(
                    "Repo {} complete: {} findings in {}ms",
                    name, result.total_findings, duration_ms
                );

                result
            })
            .collect()
    }
}

/// Scan containers on a remote host by running protectinator remotely
fn scan_remote_containers(
    entry: &crate::config::HostEntry,
    suppressions: &Suppressions,
    db: &Mutex<Option<ScanStore>>,
) -> Vec<FleetTargetResult> {
    let start = Instant::now();

    // Build SSH command
    let port_str = entry.port.to_string();
    let mut ssh_args: Vec<&str> = vec![
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-p", &port_str,
    ];
    let key_str;
    if let Some(ref key) = entry.key {
        key_str = key.display().to_string();
        ssh_args.push("-i");
        ssh_args.push(&key_str);
    }
    let remote = format!("{}@{}", entry.user, entry.host);
    ssh_args.push(&remote);

    let cmd = if entry.sudo {
        "sudo protectinator container scan --all --format json"
    } else {
        "protectinator container scan --all --format json"
    };
    ssh_args.push(cmd);

    let output = match std::process::Command::new("ssh")
        .args(&ssh_args)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to scan containers on {}: {}", entry.name, e);
            return Vec::new();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not found") || stderr.contains("No such file") {
            info!(
                "protectinator not installed on {}, skipping container scan",
                entry.name
            );
        } else {
            warn!(
                "Container scan failed on {}: {}",
                entry.name,
                stderr.trim()
            );
        }
        return Vec::new();
    }

    // Parse JSON output — one JSON object per container (newline-delimited)
    // Each object: {"container": {"name": "...", ...}, "findings": [...]}
    let stdout = String::from_utf8_lossy(&output.stdout);

    use std::collections::HashMap;
    let mut by_container: HashMap<String, Vec<protectinator_core::Finding>> = HashMap::new();

    // Use a streaming JSON deserializer to handle multiple top-level values
    let mut deserializer = serde_json::Deserializer::from_str(&stdout).into_iter::<serde_json::Value>();
    while let Some(Ok(obj)) = deserializer.next() {
        let container_name = obj
            .get("container")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Try both "findings" (flat) and "scan_results.findings" (nested) formats
        let findings_arr = obj.get("findings").and_then(|f| f.as_array())
            .or_else(|| obj.get("scan_results").and_then(|sr| sr.get("findings")).and_then(|f| f.as_array()));
        if let Some(findings_arr) = findings_arr {
            let findings: Vec<protectinator_core::Finding> = findings_arr
                .iter()
                .filter_map(|f| serde_json::from_value(f.clone()).ok())
                .collect();
            by_container.entry(container_name).or_default().extend(findings);
        }
    }

    if by_container.is_empty() {
        info!("No container findings from {}", entry.name);
        return Vec::new();
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut results = Vec::new();

    for (container_name, mut container_findings) in by_container {
        let scan_key = format!("container:{}@{}", container_name, entry.name);

        // Apply suppressions
        container_findings = suppressions.filter(container_findings, Some(&scan_key));

        // Store to DB
        if let Ok(guard) = db.lock() {
            if let Some(ref store) = *guard {
                let store_key = format!("container:{}@{}", container_name, entry.name);
                if let Err(e) = store.store_scan_with_tags(&store_key, &container_findings, 0, &entry.tags) {
                    warn!(
                        "Failed to store container scan for {}: {}",
                        container_name, e
                    );
                }
            }
        }

        let display_name = format!("{}@{}", container_name, entry.name);
        let result = FleetTargetResult::from_findings(
            display_name,
            "container",
            &container_findings,
            duration_ms,
        );

        info!(
            "Container {} on {}: {} findings",
            container_name, entry.name, result.total_findings
        );
        results.push(result);
    }

    results
}

/// Collect findings that should trigger notifications
fn collect_notifiable(results: &FleetScanResults) -> NotifiableFindings {
    let mut notifiable = NotifiableFindings {
        new_critical: Vec::new(),
        new_high: Vec::new(),
    };

    for result in results
        .host_results
        .iter()
        .chain(results.container_results.iter())
        .chain(results.repo_results.iter())
    {
        if result.critical > 0 {
            notifiable.new_critical.push(NotifiableFinding {
                host: result.name.clone(),
                title: format!("{} critical findings", result.critical),
                severity: "critical".to_string(),
                resource: None,
            });
        }
        if result.high > 0 {
            notifiable.new_high.push(NotifiableFinding {
                host: result.name.clone(),
                title: format!("{} high findings", result.high),
                severity: "high".to_string(),
                resource: None,
            });
        }
    }

    notifiable
}
