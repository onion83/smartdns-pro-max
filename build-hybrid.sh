#!/bin/bash
# Build hybrid smartdns and extract binaries directly to /tmp/ via BuildKit --output
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="smartdns-hybrid-x86_64"
TMP_DIR="/tmp"

# Parse optional --no-cache flag
BUILD_ARGS=""
if [[ "$1" == "--no-cache" ]]; then
    BUILD_ARGS="--no-cache"
fi

echo "==> Cleaning old files in ${TMP_DIR}/"
rm -f "${TMP_DIR}/smartdns" "${TMP_DIR}/smartdns_ui.so"
mkdir -p "${TMP_DIR}"

echo "==> Building hybrid image + exporting binaries... ${BUILD_ARGS:+($BUILD_ARGS)}"
# shellcheck disable=SC2086
docker buildx build -f "${SCRIPT_DIR}/Dockerfile.hybrid-x86_64" \
    --platform linux/amd64 \
    -t "${IMAGE}" \
    --target export \
    --output "type=local,dest=${TMP_DIR}" \
    $BUILD_ARGS \
    "${SCRIPT_DIR}"

echo ""
echo "==> Done. Files extracted:"
ls -lh "${TMP_DIR}/smartdns" "${TMP_DIR}/smartdns_ui.so"
file "${TMP_DIR}/smartdns" "${TMP_DIR}/smartdns_ui.so" 2>/dev/null || true
