#!/bin/sh
# Build OpenSSL as a static library for smartdns (musl-compatible).
# Usage: third_party/build_openssl.sh [VERSION]
#   VERSION defaults to 3.3.1
#
# Environment variables:
#   LOCAL_OPENSSL_INSTALL  Override install directory (default: third_party/openssl/install)
#   OPENSSL_DOWNLOAD_DIR   Override download/cache directory (default: third_party/openssl)
#   JOBS                   Number of parallel build jobs (default: nproc)

set -e

OPENSSL_VERSION="${1:-3.3.1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOWNLOAD_DIR="${OPENSSL_DOWNLOAD_DIR:-${SCRIPT_DIR}/openssl}"
INSTALL_DIR="${LOCAL_OPENSSL_INSTALL:-${SCRIPT_DIR}/openssl/install}"
OPENSSL_TAR="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/${OPENSSL_TAR}"
OPENSSL_SRC="${DOWNLOAD_DIR}/openssl-${OPENSSL_VERSION}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

mkdir -p "${DOWNLOAD_DIR}" "${INSTALL_DIR}"

# Download
if [ ! -f "${DOWNLOAD_DIR}/${OPENSSL_TAR}" ]; then
    echo "Downloading openssl ${OPENSSL_VERSION} from ${OPENSSL_URL}..."
    curl -fsSL "${OPENSSL_URL}" -o "${DOWNLOAD_DIR}/${OPENSSL_TAR}"
else
    echo "Using cached ${OPENSSL_TAR}"
fi

# Extract
if [ ! -d "${OPENSSL_SRC}" ]; then
    echo "Extracting..."
    tar xf "${DOWNLOAD_DIR}/${OPENSSL_TAR}" -C "${DOWNLOAD_DIR}"
fi

# Build (no-shared = static only)
echo "Configuring openssl ${OPENSSL_VERSION} (static, install to ${INSTALL_DIR})..."
cd "${OPENSSL_SRC}"

./Configure \
    --prefix="${INSTALL_DIR}" \
    --openssldir="${INSTALL_DIR}/ssl" \
    no-shared \
    no-tests \
    no-docs \
    no-apps \
    linux-musl-generic 2>/dev/null \
    || ./Configure \
    --prefix="${INSTALL_DIR}" \
    --openssldir="${INSTALL_DIR}/ssl" \
    no-shared \
    no-tests \
    no-docs \
    no-apps

echo "Building (jobs=${JOBS})..."
make -j"${JOBS}" > /dev/null 2>&1
make install_sw > /dev/null 2>&1

echo "Done. Static library: ${INSTALL_DIR}/lib/libssl.a, ${INSTALL_DIR}/lib/libcrypto.a"
