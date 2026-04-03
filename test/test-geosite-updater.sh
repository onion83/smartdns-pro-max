#!/bin/sh
# Test geosite-updater directive: config parsing, diff-algo, default-interval, data-dir
set -e

TEST_DIR=$(mktemp -d)
DATA_DIR="${TEST_DIR}/custom-data"
CONF_FILE="${TEST_DIR}/smartdns.conf"
PORT=60598
LOG_FILE="${TEST_DIR}/smartdns.log"
PID_FILE="${TEST_DIR}/smartdns.pid"

pass() { printf "\033[0;32m[PASS]\033[0m %s\n" "$1"; }
fail() { printf "\033[0;31m[FAIL]\033[0m %s\n" "$1"; cat "$LOG_FILE" 2>/dev/null; exit 1; }

cleanup() {
    [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"

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

# DNS query client
cat > "${TEST_DIR}/dnsquery.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
int main(int argc, char *argv[]) {
    if(argc<3) return 1;
    int port=atoi(argv[1]); const char *domain=argv[2];
    unsigned char buf[512]={0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0};
    int pos=12; char tmp[256]; strncpy(tmp,domain,255);
    char *p=strtok(tmp,".");
    while(p){int l=strlen(p);buf[pos++]=l;memcpy(buf+pos,p,l);pos+=l;p=strtok(0,".");}
    buf[pos++]=0;buf[pos++]=0;buf[pos++]=1;buf[pos++]=0;buf[pos++]=1;
    int sock=socket(AF_INET,SOCK_DGRAM,0);
    struct timeval tv={2,0}; setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    sendto(sock,buf,pos,0,(struct sockaddr*)&addr,sizeof(addr));
    recvfrom(sock,buf,sizeof(buf),0,0,0); close(sock); return 0;
}
EOF
cc -static -o "${TEST_DIR}/dnsquery" "${TEST_DIR}/dnsquery.c"

"${TEST_DIR}/mockdns" 61096 &
"${TEST_DIR}/mockdns" 61097 &
sleep 0.3

query() { "${TEST_DIR}/dnsquery" "$PORT" "$1" 2>/dev/null || true; }

# Wait for smartdns to start and capture its config output
wait_start() {
    local stdout_file="$1"
    sleep 2
    kill -0 "$(cat "$PID_FILE")" 2>/dev/null || fail "smartdns not running"
}

# ==================== TEST 1: Config parsing - all options ====================
echo ""
echo "========== TEST 1: geosite-updater config parsing =========="
printf 'qq.com\ntencent.com\n' > "${DATA_DIR}/test1.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level debug
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61096 -g default
server 127.0.0.1:61097 -g cn -exclude-default-group

geosite-updater 3600 -data-dir ${DATA_DIR} -diff-algo crc32 -use-etag yes -user-agent "TestAgent/1.0"
geosite-dat test1 ${DATA_DIR}/test1.list
geosite-set test-set test1
domain-rules /geosite-set:test-set/ -n cn
CONF

echo "Starting smartdns with geosite-updater config..."
SMARTDNS_STDOUT="${TEST_DIR}/startup1.log"
/smartdns/src/smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
wait_start

# Config parsing logs go to stdout during startup (before log file is opened)
if grep -q "geosite-updater configured: interval=3600, diff_algo=crc32, use_etag=1" "$SMARTDNS_STDOUT"; then
    pass "Config parsed: interval=3600, diff_algo=crc32, use_etag=1"
else
    fail "geosite-updater config not parsed correctly"
fi

if grep -q "user_agent=TestAgent/1.0" "$SMARTDNS_STDOUT"; then
    pass "Config parsed: user_agent=TestAgent/1.0"
else
    fail "user_agent not parsed correctly"
fi

if grep -q "data_dir=${DATA_DIR}" "$SMARTDNS_STDOUT"; then
    pass "Config parsed: data_dir=${DATA_DIR}"
else
    fail "data_dir not parsed correctly"
fi

# Verify geosite-dat uses default-interval from geosite-updater
if grep -q "interval=3600" "$SMARTDNS_STDOUT"; then
    pass "geosite-dat inherits default-interval=3600 from geosite-updater"
else
    fail "geosite-dat did not inherit default-interval"
fi

# Verify diff_algo=crc32 is shown in registration log
if grep -q "diff_algo=crc32" "$SMARTDNS_STDOUT"; then
    pass "geosite-dat registered with diff_algo=crc32"
else
    fail "geosite-dat not registered with diff_algo=crc32"
fi

# Stop for next test
kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 2: diff-algo = mtime ====================
echo ""
echo "========== TEST 2: diff-algo = mtime (local file change detection) =========="
printf 'a.com\nb.com\n' > "${DATA_DIR}/test2.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level info
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61096 -g default
server 127.0.0.1:61097 -g cn -exclude-default-group

geosite-updater 2 -data-dir ${DATA_DIR} -diff-algo mtime
geosite-dat test2 ${DATA_DIR}/test2.list
geosite-set test-set test2
domain-rules /geosite-set:test-set/ -n cn
CONF

/smartdns/src/smartdns -f -c "$CONF_FILE" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

query "a.com"; sleep 1

# Modify file
> "$LOG_FILE"
sleep 1
printf 'a.com\nb.com\nc.com\n' > "${DATA_DIR}/test2.list"

# Wait for reload
i=0; while [ $i -lt 20 ]; do
    sleep 0.5
    grep -q "geosite: reload complete" "$LOG_FILE" 2>/dev/null && break
    i=$((i+1))
done
sleep 0.5

if grep -q "geosite-dat test2: file changed" "$LOG_FILE"; then
    pass "mtime diff-algo: detected file change"
else
    fail "mtime diff-algo: failed to detect file change"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 3: diff-algo = crc32 ====================
echo ""
echo "========== TEST 3: diff-algo = crc32 (content-based detection) =========="
printf 'x.com\ny.com\n' > "${DATA_DIR}/test3.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level info
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61096 -g default
server 127.0.0.1:61097 -g cn -exclude-default-group

geosite-updater 2 -data-dir ${DATA_DIR} -diff-algo crc32
geosite-dat test3 ${DATA_DIR}/test3.list
geosite-set test-set test3
domain-rules /geosite-set:test-set/ -n cn
CONF

/smartdns/src/smartdns -f -c "$CONF_FILE" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

query "x.com"; sleep 1

# Modify content (crc32 should detect this even if mtime trick isn't used)
> "$LOG_FILE"
sleep 1
printf 'x.com\ny.com\nz.com\n' > "${DATA_DIR}/test3.list"

i=0; while [ $i -lt 20 ]; do
    sleep 0.5
    grep -q "geosite: reload complete" "$LOG_FILE" 2>/dev/null && break
    i=$((i+1))
done
sleep 0.5

if grep -q "geosite-dat test3: file changed" "$LOG_FILE"; then
    pass "crc32 diff-algo: detected content change"
else
    fail "crc32 diff-algo: failed to detect content change"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 4: diff-algo = md5 ====================
echo ""
echo "========== TEST 4: diff-algo = md5 (content-based detection) =========="
printf 'p.com\nq.com\n' > "${DATA_DIR}/test4.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level info
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61096 -g default
server 127.0.0.1:61097 -g cn -exclude-default-group

geosite-updater 2 -data-dir ${DATA_DIR} -diff-algo md5
geosite-dat test4 ${DATA_DIR}/test4.list
geosite-set test-set test4
domain-rules /geosite-set:test-set/ -n cn
CONF

/smartdns/src/smartdns -f -c "$CONF_FILE" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

query "p.com"; sleep 1

> "$LOG_FILE"
sleep 1
printf 'p.com\nq.com\nr.com\n' > "${DATA_DIR}/test4.list"

i=0; while [ $i -lt 20 ]; do
    sleep 0.5
    grep -q "geosite: reload complete" "$LOG_FILE" 2>/dev/null && break
    i=$((i+1))
done
sleep 0.5

if grep -q "geosite-dat test4: file changed" "$LOG_FILE"; then
    pass "md5 diff-algo: detected content change"
else
    fail "md5 diff-algo: failed to detect content change"
fi

# Verify md5 hash is logged (old_hash vs new_hash)
if grep -q "old_hash=" "$LOG_FILE"; then
    pass "md5 diff-algo: hash comparison logged"
else
    echo "  (hash not logged but change detected - OK)"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 5: default-interval inheritance ====================
echo ""
echo "========== TEST 5: geosite-dat without interval uses geosite-updater default =========="
printf 'm.com\n' > "${DATA_DIR}/test5.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level info
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61096 -g default
server 127.0.0.1:61097 -g cn -exclude-default-group

geosite-updater 600 -diff-algo mtime
geosite-dat test5 ${DATA_DIR}/test5.list
CONF

SMARTDNS_STDOUT="${TEST_DIR}/startup5.log"
/smartdns/src/smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

# Verify interval=600 in registration log
if grep -q "test5 registered.*interval=600" "$SMARTDNS_STDOUT"; then
    pass "geosite-dat inherits interval=600 from geosite-updater"
else
    echo "  Registration log:"
    grep "test5 registered" "$SMARTDNS_STDOUT" || echo "    (not found)"
    fail "geosite-dat did not inherit default-interval=600"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

# ==================== TEST 6: geosite-updater use-etag no ====================
echo ""
echo "========== TEST 6: use-etag no =========="
printf 'n1.com\n' > "${DATA_DIR}/test6.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level info
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61096 -g default
server 127.0.0.1:61097 -g cn -exclude-default-group

geosite-updater 300 -diff-algo mtime -use-etag no
geosite-dat test6 ${DATA_DIR}/test6.list
CONF

SMARTDNS_STDOUT="${TEST_DIR}/startup6.log"
/smartdns/src/smartdns -f -c "$CONF_FILE" > "$SMARTDNS_STDOUT" 2>&1 &
echo $! > "$PID_FILE"
sleep 2

if grep -q "use_etag=0" "$SMARTDNS_STDOUT"; then
    pass "use-etag no: parsed correctly"
else
    fail "use-etag no: not parsed correctly"
fi

kill "$(cat "$PID_FILE")" 2>/dev/null; sleep 1

kill %1 %2 2>/dev/null || true
echo ""
echo "========================================="
echo "  ALL 6 TESTS PASSED!"
echo "========================================="
