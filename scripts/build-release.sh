#!/bin/bash
# Build release binaries for protectinator
#
# Usage: ./scripts/build-release.sh [target]
#   target: linux-x86, linux-arm, macos-arm, macos-x86, or all (default)

set -e

DIST_DIR="dist"
mkdir -p "$DIST_DIR"

build_linux_x86() {
    echo "Building Linux x86_64..."
    cargo build --release --target x86_64-unknown-linux-musl -p protectinator
    cp target/x86_64-unknown-linux-musl/release/protectinator "$DIST_DIR/protectinator-linux-x86_64"
    echo "Created: $DIST_DIR/protectinator-linux-x86_64"
}

build_linux_arm() {
    echo "Building Linux ARM64..."
    cargo build --release --target aarch64-unknown-linux-musl -p protectinator
    cp target/aarch64-unknown-linux-musl/release/protectinator "$DIST_DIR/protectinator-linux-arm64"
    echo "Created: $DIST_DIR/protectinator-linux-arm64"
}

build_macos_arm() {
    echo "Building macOS ARM64..."
    if [[ "$(uname)" != "Darwin" ]]; then
        echo "Error: macOS builds must be done on macOS due to framework dependencies"
        echo "Please run this on a Mac or use GitHub Actions"
        return 1
    fi
    cargo build --release --target aarch64-apple-darwin -p protectinator
    cp target/aarch64-apple-darwin/release/protectinator "$DIST_DIR/protectinator-macos-arm64"
    echo "Created: $DIST_DIR/protectinator-macos-arm64"
}

build_macos_x86() {
    echo "Building macOS x86_64..."
    if [[ "$(uname)" != "Darwin" ]]; then
        echo "Error: macOS builds must be done on macOS due to framework dependencies"
        echo "Please run this on a Mac or use GitHub Actions"
        return 1
    fi
    cargo build --release --target x86_64-apple-darwin -p protectinator
    cp target/x86_64-apple-darwin/release/protectinator "$DIST_DIR/protectinator-macos-x86_64"
    echo "Created: $DIST_DIR/protectinator-macos-x86_64"
}

case "${1:-all}" in
    linux-x86)
        build_linux_x86
        ;;
    linux-arm)
        build_linux_arm
        ;;
    macos-arm)
        build_macos_arm
        ;;
    macos-x86)
        build_macos_x86
        ;;
    all)
        build_linux_x86
        build_linux_arm
        if [[ "$(uname)" == "Darwin" ]]; then
            build_macos_arm
            build_macos_x86
        else
            echo ""
            echo "Note: Skipping macOS builds (not running on macOS)"
            echo "Run this script on macOS to build macOS binaries"
        fi
        ;;
    *)
        echo "Usage: $0 [linux-x86|linux-arm|macos-arm|macos-x86|all]"
        exit 1
        ;;
esac

echo ""
echo "Build complete. Binaries in $DIST_DIR/:"
ls -lh "$DIST_DIR/"
