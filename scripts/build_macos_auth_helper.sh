#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
SWIFT_SOURCE="${1:-$REPO_ROOT/scripts/macos/envrcctl-macos-auth.swift}"
OUTPUT_PATH="${2:-$REPO_ROOT/src/envrcctl/envrcctl-macos-auth}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This helper can only be built on macOS." >&2
  exit 1
fi

if [ "$(uname -m)" != "arm64" ]; then
  echo "This helper only supports Apple Silicon (arm64) macOS." >&2
  exit 1
fi

if ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc not found. Install Xcode Command Line Tools first." >&2
  exit 1
fi

if [ ! -f "$SWIFT_SOURCE" ]; then
  echo "Swift source not found: $SWIFT_SOURCE" >&2
  echo "Pass the source path as the first argument or create scripts/macos/envrcctl-macos-auth.swift." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

echo "Building macOS auth helper for Apple Silicon (arm64)..."
echo "  source: $SWIFT_SOURCE"
echo "  output: $OUTPUT_PATH"

swiftc \
  -O \
  -framework LocalAuthentication \
  -framework Security \
  "$SWIFT_SOURCE" \
  -o "$OUTPUT_PATH"

chmod 755 "$OUTPUT_PATH"

echo "Build complete: $OUTPUT_PATH"
echo
echo "You can override the helper path at runtime with:"
echo "  ENVRCCTL_MACOS_AUTH_HELPER=$OUTPUT_PATH"
