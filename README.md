# Protectinator

A portable, zero-config security monitoring tool for Linux systems. One binary, no installation required.

## Features

### Host Scanning
- **File Integrity Monitoring** (FIM) — SHA-256/SHA-512/BLAKE3 baselines with parallel verification
- **System Hardening** — SSH config, SUID binaries, service accounts, permissions
- **Sigma Rules** — community detection rules applied to local system
- **Persistence Detection** — cron, systemd, shell profiles, udev, MOTD
- **Rootkit Detection** — hidden files, kernel modules, LD_PRELOAD, deleted binaries
- **Privilege Escalation** — GTFOBins, SUID/SGID, capability analysis
- **Process Monitoring** — running processes and network connections
- **YARA Scanning** — custom pattern matching

### Container Scanning
- **Docker + nspawn** — scan containers from the host via overlay2/filesystem access
- **CVE Scanning** — live vulnerability lookups via OSV API (Debian, Ubuntu, Alpine)
- **SBOM Generation** — CycloneDX 1.5 output with proper PURLs for container packages
- **All host checks** reused against container filesystems (rootkit, persistence, hardening, SUID, OS version)

### Supply Chain Security
- **Vulnerability Scanning** — OSV database queries for 8 lock file formats (Cargo.lock, package-lock.json, requirements.txt, Pipfile.lock, poetry.lock, uv.lock, yarn.lock, pnpm-lock.yaml)
- **SBOM Generation** — CycloneDX 1.5 with cross-repo package search
- **Advisory Feed Monitoring** — proactive OSV polling with new-vs-known tracking
- **CI/CD Scanning** — GitHub Actions misconfigurations, exposed secrets, unpinned actions
- **Malware Signatures** — npm postinstall abuse, pip build hooks, .pth injection
- **Cryptographic Trust** — nono integration for ECDSA file signing/verification
- **Gaol Integration** — sandboxed dependency evaluation and installation

### IoT / Raspberry Pi
- **Three scan modes** — local, mounted SD card, SSHFS
- **11 IoT-specific checks** — binary integrity, boot integrity, default credentials, PAM audit, udev persistence, kernel integrity, device tree validation
- **Plus all container checks** reused for the device

### Remote Scanning
- **Agentless** — gathers system data via SSH, analyzes locally (no installation needed on remote host)
- **Agent mode** — runs protectinator on the remote host, collects JSON results
- **IOC Detection** — hidden files, deleted binaries, LD_PRELOAD hijacking
- **Disk Space Monitoring** — critical/high/medium alerts with remediation suggestions
- **Uptime / Reboot Detection** — flags excessive uptime and pending reboots
- Inherits your `~/.ssh/config` (ProxyJump, keys, agent forwarding)

### Vulnerability Classification
- CVE findings tagged with attack type from CVSS vectors and CWE IDs
- Tags: `[Remote/RCE]`, `[Local/DoS]`, `[Remote/Injection]`, `[Local/PrivEsc]`, etc.
- SQLite cache for OSV enrichment data (fetch once, instant thereafter)

### Automation
- **Daily supply chain scan** — systemd user timer at 7:00 AM (SBOMs, advisory feeds, diff scan)
- **Daily container scan** — systemd system timer at 7:30 AM (container SBOMs, CVE scanning)
- **Desktop notifications** — critical/high findings trigger notify-send alerts
- **Multi-repo scanning** — `--repos-file` for scanning all your projects at once
- **Diff-based alerting** — only report new findings since last scan

## Quick Start

```sh
# Full local security scan
protectinator scan

# Scan a Docker container
sudo protectinator container scan my-container

# Scan a remote host via SSH
protectinator remote scan myserver.com -u admin

# Generate SBOMs for all your repos
protectinator supply-chain sbom --repos-file ~/.config/protectinator/repos.txt --save

# Check for new CVE advisories
protectinator supply-chain watch

# Search for a package across all stored SBOMs
protectinator supply-chain search openssl

# List all containers (Docker + nspawn)
sudo protectinator container list

# Test SSH connectivity
protectinator remote test myserver.com -u admin
```

## Output Formats

```sh
# Human-readable (default)
protectinator scan

# JSON for scripting/CI
protectinator --format json scan

# Filter by severity
protectinator container scan --all --min-severity high
```

## Architecture

Rust workspace with modular crates:

| Crate | Purpose |
|-------|---------|
| `protectinator-core` | Traits, findings, report types |
| `protectinator-engine` | Scan orchestration |
| `protectinator-fim` | File integrity monitoring (usable standalone) |
| `protectinator-container` | Docker + nspawn scanning |
| `protectinator-iot` | Raspberry Pi / ARM IoT |
| `protectinator-supply-chain` | OSV, SBOM, feeds, trust |
| `protectinator-remote` | SSH-based remote scanning |
| `protectinator-agents` | Remote access tool detection |
| `protectinator-hardening` | System hardening checks |
| `protectinator-persistence` | Persistence mechanism detection |
| `protectinator-sigma` | Sigma rule engine |
| `protectinator-yara` | YARA pattern scanning |

### Using protectinator-fim standalone

The FIM crate can be used independently without the full protectinator ecosystem:

```toml
[dependencies]
protectinator-fim = { git = "https://github.com/erewhon/protectinator", path = "crates/protectinator-fim", default-features = false }
```

## License

GPL-3.0-or-later
