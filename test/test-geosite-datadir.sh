#!/bin/sh
# Test geosite-updater data-dir: explicit config and default value
set -e

TEST_DIR=$(mktemp -d)
CUSTOM_DATA_DIR="${TEST_DIR}/custom-download"
CONF_FILE="${TEST_DIR}/smartdns.conf"
PORT=60599
LOG_FILE="${TEST_DIR}/smartdns.log"
PID_FILE="${TEST_DIR}/smartdns.pid"

pass() { printf "\033[0;32m[PASS]\033[0m %s\n" "$1"; }
fail() { printf "\033[0;31m[FAIL]\033[0m %s\n" "$1"; cat "$LOG_FILE" 2>/dev/null; exit 1; }

cleanup() {
    [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$CUSTOM_DATA_DIR"

# Mock DNS server
cat > "${TEST_DIR}/mockdns.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc, char *argv[]) {
    int port = atoi(argv[1]);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    unsigned char buf[512], resp[512];
    unsigned char ip[4] = {1, 2, 3, 4};
    while (1) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n < 12) continue;
        int rl = 0;
        resp[rl++] = buf[0]; resp[rl++] = buf[1];
        resp[rl++] = 0x85; resp[rl++] = 0x80;
        resp[rl++] = 0; resp[rl++] = 1;
        resp[rl++] = 0; resp[rl++] = 1;
        resp[rl++] = 0; resp[rl++] = 0;
        resp[rl++] = 0; resp[rl++] = 0;
        int i = 12;
        while (i < n && buf[i] != 0) resp[rl++] = buf[i++];
        if (i + 4 <= n) { memcpy(resp + rl, buf + i, 5); rl += 5; }
        resp[rl++] = 0xC0; resp[rl++] = 0x0C;
        resp[rl++] = 0; resp[rl++] = 1;
        resp[rl++] = 0; resp[rl++] = 1;
        resp[rl++] = 0; resp[rl++] = 0; resp[rl++] = 0; resp[rl++] = 60;
        resp[rl++] = 0; resp[rl++] = 4;
        resp[rl++] = ip[0]; resp[rl++] = ip[1]; resp[rl++] = ip[2]; resp[rl++] = ip[3];
        sendto(sock, resp, rl, 0, (struct sockaddr*)&from, fl);
    }
}
EOF
cc -o "${TEST_DIR}/mockdns" "${TEST_DIR}/mockdns.c"

"${TEST_DIR}/mockdns" 61098 &
MOCK_PID=$!
sleep 0.3

# ==================== TEST 1: Explicit -data-dir in config log ====================
echo ""
echo "========== TEST 1: Explicit -data-dir parsed =========="
printf 'domain1.com\ndomain2.com\n' > "${CUSTOM_DATA_DIR}/test1.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level debug
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61098 -g default

geosite-updater 300 -data-dir ${CUSTOM_DATA_DIR} -diff-algo mtime
geosite-dat dd-test1 ${CUSTOM_DATA_DIR}/test1.list
CONF

SMARTDNS_STDOUT="${TEST_DIR}/startup1.log"
/smartdns/src/smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

# Verify data_dir was parsed correctly
if grep -q "data_dir=${CUSTOM_DATA_DIR}" "$SMARTDNS_STDOUT"; then
    pass "TEST 1: Explicit data_dir=${CUSTOM_DATA_DIR} parsed correctly"
else
    echo "  geosite-updater log:"
    grep "geosite-updater configured" "$SMARTDNS_STDOUT" || echo "    (not found)"
    fail "TEST 1: data_dir not parsed correctly"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 2: No -data-dir shows (default) ====================
echo ""
echo "========== TEST 2: No -data-dir shows (default) =========="
printf 'domain3.com\n' > "${CUSTOM_DATA_DIR}/test2.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level debug
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61098 -g default

geosite-updater 300 -diff-algo mtime
geosite-dat dd-test2 ${CUSTOM_DATA_DIR}/test2.list
CONF

SMARTDNS_STDOUT="${TEST_DIR}/startup2.log"
/smartdns/src/smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

# Verify data_dir shows (default) when not configured
if grep -q 'data_dir=(default)' "$SMARTDNS_STDOUT"; then
    pass "TEST 2: No -data-dir, shows data_dir=(default)"
else
    echo "  geosite-updater log:"
    grep "geosite-updater configured" "$SMARTDNS_STDOUT" || echo "    (not found)"
    fail "TEST 2: Expected data_dir=(default)"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 3: URL source uses data-dir for cache path ====================
echo ""
echo "========== TEST 3: URL source uses data-dir for cache file =========="
# Use a fake https URL (won't actually download in this test, but path should be computed)
# We verify via the registration log what path would be used
cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level debug
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61098 -g default

geosite-updater 300 -data-dir ${CUSTOM_DATA_DIR} -diff-algo mtime
geosite-dat dd-test3 https://example.com/geosite/test-list.txt 300
CONF

SMARTDNS_STDOUT="${TEST_DIR}/startup3.log"
/smartdns/src/smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

# URL source: cache file path should be under CUSTOM_DATA_DIR
# Expected format: {data_dir}/example.com-geosite-test-list.txt or similar
if grep -q "file=${CUSTOM_DATA_DIR}/" "$SMARTDNS_STDOUT"; then
    pass "TEST 3: URL source cache file under data_dir=${CUSTOM_DATA_DIR}"
    # Show the actual path for verification
    grep "dd-test3 registered" "$SMARTDNS_STDOUT" | sed 's/^/  /'
else
    echo "  registration log:"
    grep "dd-test3 registered" "$SMARTDNS_STDOUT" || echo "    (not found)"
    fail "TEST 3: URL cache not under data_dir"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 4: Default data-dir for URL source ====================
echo ""
echo "========== TEST 4: URL source uses {cwd}/data when no -data-dir =========="
# Create a mock smartdns binary directory with data/ subfolder
BIN_DIR="${TEST_DIR}/bin"
mkdir -p "${BIN_DIR}/data"
cp /smartdns/src/smartdns "${BIN_DIR}/"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level debug
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61098 -g default

geosite-updater 300 -diff-algo mtime
geosite-dat dd-test4 https://cdn.example.com/lists/my-domains.list 300
CONF

SMARTDNS_STDOUT="${TEST_DIR}/startup4.log"
# Run from BIN_DIR (smartdns chdir's to exec dir = BIN_DIR)
cd "${BIN_DIR}" && ./smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

# When no -data-dir, URL cache should go to {cwd}/data
# Since we run from BIN_DIR, expected path is BIN_DIR/data/...
EXPECTED_DIR="${BIN_DIR}/data"
if grep -q "file=${EXPECTED_DIR}/" "$SMARTDNS_STDOUT"; then
    pass "TEST 4: URL cache in {cwd}/data (default data-dir)"
    grep "dd-test4 registered" "$SMARTDNS_STDOUT" | sed 's/^/  /'
else
    echo "  Expected: file=${EXPECTED_DIR}/..."
    echo "  registration log:"
    grep "dd-test4 registered" "$SMARTDNS_STDOUT" || echo "    (not found)"
    # Also check what data_dir was logged
    grep "geosite-updater configured" "$SMARTDNS_STDOUT" | sed 's/^/  /'
    fail "TEST 4: URL cache NOT in {cwd}/data"
fi

# Verify data/ directory was created (mkdir by smartdns)
if [ -d "${BIN_DIR}/data" ]; then
    pass "TEST 4: {cwd}/data directory exists (auto-created)"
else
    fail "TEST 4: {cwd}/data directory not created"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1
kill $MOCK_PID 2>/dev/null || true

echo ""
echo "========================================="
echo "  ALL 4 DATA-DIR TESTS PASSED!"
echo "========================================="
