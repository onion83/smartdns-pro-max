#!/bin/sh
# Build libcurl as both static and shared libraries for smartdns.
# Usage: third_party/build_curl.sh [VERSION] [static|shared|both]
#   VERSION  defaults to 8.20.0
#   Mode     defaults to both (build both static and shared)
#
# Environment variables:
#   LOCAL_CURL_INSTALL   Override install directory (default: third_party/curl/install)
#   LOCAL_OPENSSL_INSTALL Override OpenSSL install directory (default: auto-detect)
#   CURL_DOWNLOAD_DIR    Override download/cache directory (default: third_party/curl)
#   JOBS                 Number of parallel build jobs (default: nproc)

set -e

CURL_VERSION="${1:-8.20.0}"
BUILD_MODE="${2:-both}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOWNLOAD_DIR="${CURL_DOWNLOAD_DIR:-${SCRIPT_DIR}/curl}"
INSTALL_DIR="${LOCAL_CURL_INSTALL:-${SCRIPT_DIR}/curl/install}"
CURL_TAR="curl-${CURL_VERSION}.tar.xz"
CURL_URL="https://curl.se/download/${CURL_TAR}"
CURL_SRC="${DOWNLOAD_DIR}/curl-${CURL_VERSION}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

mkdir -p "${DOWNLOAD_DIR}" "${INSTALL_DIR}"

# Download
if [ ! -f "${DOWNLOAD_DIR}/${CURL_TAR}" ]; then
    echo "Downloading curl ${CURL_VERSION} from ${CURL_URL}..."
    wget -q "${CURL_URL}" -O "${DOWNLOAD_DIR}/${CURL_TAR}"
else
    echo "Using cached ${CURL_TAR}"
fi

# Extract
if [ ! -d "${CURL_SRC}" ]; then
    echo "Extracting..."
    tar xf "${DOWNLOAD_DIR}/${CURL_TAR}" -C "${DOWNLOAD_DIR}"
fi

cd "${CURL_SRC}"

# Auto-detect OpenSSL install dir
if [ -z "${LOCAL_OPENSSL_INSTALL:-}" ]; then
    for dir in "${SCRIPT_DIR}/openssl/install" "/opt/openssl"; do
        # Check both lib/ and lib64/ (OpenSSL 4.x defaults to lib64)
        for libdir in "${dir}/lib" "${dir}/lib64"; do
            if [ -d "${libdir}" ] && ([ -f "${libdir}/libssl.a" ] || [ -f "${libdir}/libssl.so" ]); then
                LOCAL_OPENSSL_INSTALL="${dir}"
                break 2
            fi
        done
    done
fi

if [ -n "${LOCAL_OPENSSL_INSTALL:-}" ]; then
    echo "Using OpenSSL from ${LOCAL_OPENSSL_INSTALL}"
    # OpenSSL 4.x installs to lib64/, 3.x installs to lib/
    if [ -d "${LOCAL_OPENSSL_INSTALL}/lib64" ]; then
        OPENSSL_LIBDIR="${LOCAL_OPENSSL_INSTALL}/lib64"
    else
        OPENSSL_LIBDIR="${LOCAL_OPENSSL_INSTALL}/lib"
    fi
    export PKG_CONFIG_PATH="${OPENSSL_LIBDIR}/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export CFLAGS="${CFLAGS:-} -fPIC -O2 -I${LOCAL_OPENSSL_INSTALL}/include"
    export LDFLAGS="${LDFLAGS:-} -L${OPENSSL_LIBDIR}"
    OPENSSL_OPT="--with-openssl=${LOCAL_OPENSSL_INSTALL}"
else
    echo "WARNING: No OpenSSL found, building without SSL support"
    OPENSSL_OPT="--without-openssl"
fi

COMMON_OPTS="--disable-debug --disable-ares --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-gopher --disable-mqtt --disable-manual --disable-docs --without-librtmp --without-libgsasl --without-libssh2 --without-libpsl ${OPENSSL_OPT}"

# Build static
if [ "${BUILD_MODE}" = "static" ] || [ "${BUILD_MODE}" = "both" ]; then
    echo "=== Building curl ${CURL_VERSION} (static) ==="
    make clean 2>&1 || true
    echo "Configuring static..."
    ./configure --prefix="${INSTALL_DIR}" --disable-shared --enable-static ${COMMON_OPTS}
    echo "Building static (jobs=${JOBS})..."
    make -j"${JOBS}" 2>&1
    echo "Installing static..."
    make install 2>&1
    echo "Done. Static: ${INSTALL_DIR}/lib/libcurl.a"
fi

# Build shared
if [ "${BUILD_MODE}" = "shared" ] || [ "${BUILD_MODE}" = "both" ]; then
    echo "=== Building curl ${CURL_VERSION} (shared) ==="
    make clean 2>&1 || true
    echo "Configuring shared..."
    ./configure --prefix="${INSTALL_DIR}" --enable-shared --disable-static ${COMMON_OPTS}
    echo "Building shared (jobs=${JOBS})..."
    make -j"${JOBS}" 2>&1
    echo "Installing shared..."
    make install 2>&1
    echo "Done. Shared: ${INSTALL_DIR}/lib/libcurl.so"
fi

# Symlink binary
if [ -f "${INSTALL_DIR}/bin/curl" ]; then
    ln -sf "${INSTALL_DIR}/bin/curl" /usr/bin/curl 2>/dev/null || true
    echo "Symlink: /usr/bin/curl"
fi

# Verify
echo "=== Verify ==="
ls -lh "${INSTALL_DIR}"/lib/libcurl.* 2>/dev/null || true
echo "=== Done ==="
