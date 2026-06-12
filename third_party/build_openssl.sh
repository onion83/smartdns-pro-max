#!/bin/sh
# Build OpenSSL as both static and shared libraries for smartdns (musl-compatible).
# Usage: third_party/build_openssl.sh [VERSION] [static|shared|both]
#   VERSION  defaults to 3.5.7
#   Mode     defaults to both (build both static and shared)
#
# Environment variables:
#   LOCAL_OPENSSL_INSTALL  Override install directory (default: third_party/openssl/install)
#   OPENSSL_DOWNLOAD_DIR   Override download/cache directory (default: third_party/openssl)
#   JOBS                   Number of parallel build jobs (default: nproc)

set -e

OPENSSL_VERSION="${1:-4.0.1}"
BUILD_MODE="${2:-both}"
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
    wget -q "${OPENSSL_URL}" -O "${DOWNLOAD_DIR}/${OPENSSL_TAR}"
else
    echo "Using cached ${OPENSSL_TAR}"
fi

# Extract
if [ ! -d "${OPENSSL_SRC}" ]; then
    echo "Extracting..."
    tar xf "${DOWNLOAD_DIR}/${OPENSSL_TAR}" -C "${DOWNLOAD_DIR}"
fi

cd "${OPENSSL_SRC}"

# Build static library
if [ "${BUILD_MODE}" = "static" ] || [ "${BUILD_MODE}" = "both" ]; then
    echo "=== Building OpenSSL ${OPENSSL_VERSION} (static, install to ${INSTALL_DIR}) ==="
    make clean > /dev/null 2>&1 || true

    ./Configure \
        --prefix="${INSTALL_DIR}" \
        --openssldir="${INSTALL_DIR}/ssl" \
        no-shared \
        no-tests \
        no-docs \
        linux-musl-generic 2>/dev/null \
        || ./Configure \
            --prefix="${INSTALL_DIR}" \
            --openssldir="${INSTALL_DIR}/ssl" \
            no-shared \
            no-tests \
            no-docs

    echo "Building static (jobs=${JOBS})..."
    make -j"${JOBS}" > /dev/null 2>&1
    make install_sw > /dev/null 2>&1
    echo "Done. Static library: ${INSTALL_DIR}/lib/libssl.a, ${INSTALL_DIR}/lib/libcrypto.a"
fi

# Build shared library
if [ "${BUILD_MODE}" = "shared" ] || [ "${BUILD_MODE}" = "both" ]; then
    echo "=== Building OpenSSL ${OPENSSL_VERSION} (shared, install to ${INSTALL_DIR}) ==="
    make clean > /dev/null 2>&1 || true

    ./Configure \
        --prefix="${INSTALL_DIR}" \
        --openssldir="${INSTALL_DIR}/ssl" \
        shared \
        no-tests \
        no-docs \
        linux-musl-generic 2>/dev/null \
        || ./Configure \
            --prefix="${INSTALL_DIR}" \
            --openssldir="${INSTALL_DIR}/ssl" \
            shared \
            no-tests \
            no-docs

    echo "Building shared (jobs=${JOBS})..."
    make -j"${JOBS}" > /dev/null 2>&1
    make install_sw > /dev/null 2>&1
    echo "Done. Shared library: ${INSTALL_DIR}/lib/libssl.so, ${INSTALL_DIR}/lib/libcrypto.so"
fi

# Ensure lib symlink exists (some platforms install to lib64)
if [ ! -d "${INSTALL_DIR}/lib" ] && [ -d "${INSTALL_DIR}/lib64" ]; then
    ln -sf "${INSTALL_DIR}/lib64" "${INSTALL_DIR}/lib"
fi

# Create symlinks for binaries in /usr/bin for system-wide use
if [ -d "${INSTALL_DIR}/bin" ]; then
    echo "=== Creating symlinks for OpenSSL binaries ==="
    for bin in "${INSTALL_DIR}"/bin/openssl "${INSTALL_DIR}"/bin/c_rehash; do
        if [ -f "$bin" ]; then
            ln -sf "$bin" /usr/bin/ 2>/dev/null || true
        fi
    done
    echo "Symlinks created: /usr/bin/openssl"
fi

# Verify installation
echo "=== Verifying installation ==="
for lib in "libssl.a" "libcrypto.a"; do
    if [ -f "${INSTALL_DIR}/lib/${lib}" ]; then
        echo "Found: ${INSTALL_DIR}/lib/${lib}"
    fi
done
for lib in "libssl.so" "libcrypto.so"; do
    if [ -f "${INSTALL_DIR}/lib/${lib}" ]; then
        echo "Found: ${INSTALL_DIR}/lib/${lib}"
    fi
done

echo "=== OpenSSL build complete ==="
