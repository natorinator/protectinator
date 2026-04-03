# Protectinator Deployment

Deploy protectinator-web and fleet scanning to a centralized host.

## Prerequisites

- Target host with Tailscale installed and running
- SSH access to the target host
- Rust toolchain (for building)

## Quick Start

```bash
# Build and deploy to Euclid
./deploy/setup-euclid.sh --build
```

## What Gets Deployed

- **protectinator** — CLI tool for scanning (installed to /usr/local/bin)
- **protectinator-web** — Web dashboard (systemd service, port 8080)
- **Fleet scan timer** — Runs `protectinator fleet scan` every 6 hours
- **Tailscale serve** — Exposes dashboard on your tailnet with TLS + identity headers

## Services

| Service | Description | Command |
|---------|-------------|---------|
| protectinator-web | Dashboard | `systemctl status protectinator-web` |
| protectinator-fleet-scan.timer | Scan schedule | `systemctl status protectinator-fleet-scan.timer` |

## Configuration

- Fleet config: `~/.config/protectinator/fleet.toml`
- Suppressions: `~/.config/protectinator/suppressions.toml`
- Scan data: `~/.local/share/protectinator/`

## Authentication

The dashboard uses Tailscale identity headers for authentication.
Only users on your tailnet can access it. The `Tailscale-User-Login`
header identifies the user.

For local development, use `--no-auth`:

```bash
protectinator-web --no-auth
```

## Adding Repos to Scan

Edit `fleet.toml` on the scanning host:

```toml
[[repos]]
path = "~/Projects/my-project"

[[repos]]
path = "~/Projects/another-project"
ecosystem = "python"
```

## Manual Scan

```bash
# Run a fleet scan now
protectinator fleet scan

# Check timer status
systemctl list-timers protectinator-fleet-scan*
```
