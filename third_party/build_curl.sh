#!/bin/sh
# Build libcurl as a static library for smartdns.
# Usage: third_party/build_curl.sh [VERSION]
#   VERSION defaults to 8.7.1
#
# Environment variables:
#   LOCAL_CURL_INSTALL  Override install directory (default: third_party/curl/install)
#   CURL_DOWNLOAD_DIR   Override download/cache directory (default: third_party/curl)
#   JOBS                Number of parallel build jobs (default: nproc)

set -e

CURL_VERSION="${1:-8.7.1}"
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
    curl -fsSL "${CURL_URL}" -o "${DOWNLOAD_DIR}/${CURL_TAR}"
else
    echo "Using cached ${CURL_TAR}"
fi

# Extract
if [ ! -d "${CURL_SRC}" ]; then
    echo "Extracting..."
    tar xf "${DOWNLOAD_DIR}/${CURL_TAR}" -C "${DOWNLOAD_DIR}"
fi

# Build
echo "Configuring curl ${CURL_VERSION} (static, minimal features, install to ${INSTALL_DIR})..."
cd "${CURL_SRC}"

# Support linking against a custom static OpenSSL
OPENSSL_CFLAGS=""
OPENSSL_LDFLAGS=""
if [ -n "${LOCAL_OPENSSL_INSTALL:-}" ]; then
    echo "Using static OpenSSL from ${LOCAL_OPENSSL_INSTALL}"
    OPENSSL_CFLAGS="-I${LOCAL_OPENSSL_INSTALL}/include"
    OPENSSL_LDFLAGS="-L${LOCAL_OPENSSL_INSTALL}/lib -lssl -lcrypto"
fi

./configure \
    --prefix="${INSTALL_DIR}" \
    --disable-shared \
    --enable-static \
    --disable-debug \
    --disable-curldebug \
    --disable-ares \
    --disable-ldap \
    --disable-ldaps \
    --disable-rtsp \
    --disable-dict \
    --disable-telnet \
    --disable-tftp \
    --disable-pop3 \
    --disable-imap \
    --disable-smb \
    --disable-gopher \
    --disable-mqtt \
    --disable-manual \
    --disable-docs \
    --disable-html-docs \
    --disable-install-docs \
    --disable-tests \
    --without-brotli \
    --without-zstd \
    --without-libpsl \
    --without-librtmp \
    --without-libidn2 \
    --without-libgsasl \
    --without-nghttp2 \
    --without-libssh2 \
    --with-openssl \
    ${OPENSSL_CFLAGS:+CFLAGS="-fPIC -O2 ${OPENSSL_CFLAGS}"} \
    ${OPENSSL_LDFLAGS:+LIBS="${OPENSSL_LDFLAGS}"} \
    > /dev/null 2>&1

echo "Building (jobs=${JOBS})..."
make -j"${JOBS}" > /dev/null 2>&1
make install > /dev/null 2>&1

echo "Done. Static library: ${INSTALL_DIR}/lib/libcurl.a"

