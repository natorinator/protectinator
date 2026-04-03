#!/usr/bin/env bash
set -euo pipefail

# Protectinator deployment script for Euclid
# Usage: ./setup-euclid.sh [--build]
#
# Prerequisites:
#   - SSH access to euclid as erewhon
#   - Tailscale installed and running on euclid
#   - Rust toolchain on build machine (if --build)

REMOTE_HOST="euclid"
REMOTE_USER="erewhon"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/home/${REMOTE_USER}/.config/protectinator"
DATA_DIR="/home/${REMOTE_USER}/.local/share/protectinator"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Protectinator Deployment to ${REMOTE_HOST} ==="

# Build if requested
if [[ "${1:-}" == "--build" ]]; then
    echo ""
    echo "--- Building release binaries ---"
    cd "$REPO_DIR"
    cargo build --release -p protectinator -p protectinator-web
    echo "Build complete."
fi

CLI_BIN="$REPO_DIR/target/release/protectinator"
WEB_BIN="$REPO_DIR/target/release/protectinator-web"

if [[ ! -f "$CLI_BIN" ]] || [[ ! -f "$WEB_BIN" ]]; then
    echo "Error: Release binaries not found. Run with --build first."
    exit 1
fi

echo ""
echo "--- Copying binaries to ${REMOTE_HOST} ---"
scp "$CLI_BIN" "$WEB_BIN" "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"
ssh "${REMOTE_USER}@${REMOTE_HOST}" "sudo mv /tmp/protectinator /tmp/protectinator-web ${INSTALL_DIR}/"

echo ""
echo "--- Setting up directories ---"
ssh "${REMOTE_USER}@${REMOTE_HOST}" "
    mkdir -p ${CONFIG_DIR}
    mkdir -p ${DATA_DIR}
"

echo ""
echo "--- Copying configuration ---"
scp "$SCRIPT_DIR/fleet.toml" "${REMOTE_USER}@${REMOTE_HOST}:${CONFIG_DIR}/fleet.toml"

# Copy suppressions if they exist locally
if [[ -f "$HOME/.config/protectinator/suppressions.toml" ]]; then
    scp "$HOME/.config/protectinator/suppressions.toml" "${REMOTE_USER}@${REMOTE_HOST}:${CONFIG_DIR}/suppressions.toml"
fi

echo ""
echo "--- Installing systemd services ---"
scp "$SCRIPT_DIR/protectinator-web.service" \
    "$SCRIPT_DIR/protectinator-fleet-scan.service" \
    "$SCRIPT_DIR/protectinator-fleet-scan.timer" \
    "${REMOTE_USER}@${REMOTE_HOST}:/tmp/"

ssh "${REMOTE_USER}@${REMOTE_HOST}" "
    sudo mv /tmp/protectinator-web.service /etc/systemd/system/
    sudo mv /tmp/protectinator-fleet-scan.service /etc/systemd/system/
    sudo mv /tmp/protectinator-fleet-scan.timer /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now protectinator-web.service
    sudo systemctl enable --now protectinator-fleet-scan.timer
"

echo ""
echo "--- Setting up Tailscale serve ---"
ssh "${REMOTE_USER}@${REMOTE_HOST}" "
    sudo tailscale serve --bg 8080
"

echo ""
echo "--- Running initial fleet scan ---"
ssh "${REMOTE_USER}@${REMOTE_HOST}" "protectinator fleet scan" || true

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Dashboard: https://${REMOTE_HOST}.<your-tailnet>.ts.net"
echo "Fleet scan timer: systemctl status protectinator-fleet-scan.timer"
echo "Web service: systemctl status protectinator-web.service"
echo ""
echo "To add repos, edit: ${CONFIG_DIR}/fleet.toml on ${REMOTE_HOST}"
echo "To view logs: journalctl -u protectinator-web -f"
echo "              journalctl -u protectinator-fleet-scan -f"
