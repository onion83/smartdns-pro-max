#!/bin/sh
# Exact reproduction steps for the geosite reload bug:
# 1. baidu.com not in list -> default
# 2. Add baidu.com to list -> cn (reload)
# 3. Remove baidu.com from list -> default (was stuck at cn before fix)
set -e

TEST_DIR=$(mktemp -d)
DATA_DIR="${TEST_DIR}/data"
CONF_FILE="${TEST_DIR}/smartdns.conf"
PORT=60599
LOG_FILE="${TEST_DIR}/smartdns.log"
PID_FILE="${TEST_DIR}/smartdns.pid"

DOMAIN="baidu.com"

pass() { printf "\033[0;32m[PASS]\033[0m %s\n" "$1"; }
fail() { printf "\033[0;31m[FAIL]\033[0m %s\n" "$1"; cat "$LOG_FILE" 2>/dev/null; exit 1; }

cleanup() {
    [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"

# Mock DNS server - sends valid DNS responses
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
    
    unsigned char buf[512];
    unsigned char resp[512];
    unsigned char ip[4] = {1, 2, 3, 4};
    
    while (1) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n < 12) continue;
        
        /* Build response */
        int resp_len = 0;
        /* ID from query */
        resp[resp_len++] = buf[0];
        resp[resp_len++] = buf[1];
        /* QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=0 */
        resp[resp_len++] = 0x85;
        resp[resp_len++] = 0x80;
        /* QDCOUNT = 1 */
        resp[resp_len++] = 0;
        resp[resp_len++] = 1;
        /* ANCOUNT = 1 */
        resp[resp_len++] = 0;
        resp[resp_len++] = 1;
        /* NSCOUNT = 0 */
        resp[resp_len++] = 0;
        resp[resp_len++] = 0;
        /* ARCOUNT = 0 */
        resp[resp_len++] = 0;
        resp[resp_len++] = 0;
        
        /* Copy question section from query */
        int i = 12;
        while (i < n && buf[i] != 0) {
            resp[resp_len++] = buf[i++];
        }
        /* Copy null byte, QTYPE, QCLASS (4 bytes total) */
        if (i + 4 <= n) {
            memcpy(resp + resp_len, buf + i, 5);
            resp_len += 5;
        }
        
        /* Answer section - pointer to question domain (0xC0 0x0C) */
        resp[resp_len++] = 0xC0;
        resp[resp_len++] = 0x0C;
        /* TYPE A */
        resp[resp_len++] = 0;
        resp[resp_len++] = 1;
        /* CLASS IN */
        resp[resp_len++] = 0;
        resp[resp_len++] = 1;
        /* TTL 60 seconds */
        resp[resp_len++] = 0;
        resp[resp_len++] = 0;
        resp[resp_len++] = 0;
        resp[resp_len++] = 60;
        /* RDLENGTH = 4 */
        resp[resp_len++] = 0;
        resp[resp_len++] = 4;
        /* RDATA - IP address */
        resp[resp_len++] = ip[0];
        resp[resp_len++] = ip[1];
        resp[resp_len++] = ip[2];
        resp[resp_len++] = ip[3];
        
        sendto(sock, resp, resp_len, 0, (struct sockaddr*)&from, fl);
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

"${TEST_DIR}/mockdns" 61098 &
"${TEST_DIR}/mockdns" 61099 &
sleep 0.3

# Step 1: tencent.list WITHOUT baidu.com
printf 'qq.com\ntencent.com\n' > "${DATA_DIR}/test.list"

cat > "$CONF_FILE" << CONF
bind 127.0.0.1:${PORT} -no-cache -no-speed-check
log-console yes
log-level debug
cache-size 0
speed-check-mode none
pid-file ${PID_FILE}
log-file ${LOG_FILE}

server 127.0.0.1:61098 -g default
server 127.0.0.1:61099 -g cn -exclude-default-group

geosite-dat test-geosite ${DATA_DIR}/test.list 2
geosite-set test-set test-geosite
domain-rules /geosite-set:test-set/ -n cn
CONF

echo "Starting smartdns..."
/smartdns/src/smartdns -f -c "$CONF_FILE" &
echo $! > "$PID_FILE"
sleep 2

kill -0 "$(cat "$PID_FILE")" 2>/dev/null || fail "smartdns not running"

check_group() {
    domain="$1"; group="$2"
    grep "result:.*${domain}.*group: ${group}" "$LOG_FILE" | grep -v "request:" | tail -1 | grep -q "group: ${group}"
}
query() { "${TEST_DIR}/dnsquery" "$PORT" "$1" 2>/dev/null || true; }

# ======== STEP 1: baidu.com NOT in list -> default ========
echo ""
echo "=== STEP 1: ${DOMAIN} not in list -> should be default ==="
query "$DOMAIN"; sleep 1

if check_group "$DOMAIN" "default"; then
    pass "Step 1: ${DOMAIN} -> default (no rule)"
else
    fail "Step 1: ${DOMAIN} should be default (not in list)"
fi

# ======== STEP 2: ADD baidu.com -> cn ========
echo ""
echo "=== STEP 2: Add ${DOMAIN} to list -> should be cn ==="
> "$LOG_FILE"
printf 'qq.com\ntencent.com\n%s\n' "$DOMAIN" > "${DATA_DIR}/test.list"

echo "Waiting for reload..."
i=0; while [ $i -lt 20 ]; do
    sleep 0.5
    grep -q "geosite: reloaded domain rules" "$LOG_FILE" 2>/dev/null && break
    i=$((i+1))
done
sleep 0.5
query "$DOMAIN"; sleep 1

if check_group "$DOMAIN" "cn"; then
    pass "Step 2: ${DOMAIN} -> cn (rule added after file change)"
else
    fail "Step 2: ${DOMAIN} should be cn (after adding to list)"
fi

# ======== STEP 3: REMOVE baidu.com -> default ========
echo ""
echo "=== STEP 3: Remove ${DOMAIN} from list -> should be default ==="
> "$LOG_FILE"
printf 'qq.com\ntencent.com\n' > "${DATA_DIR}/test.list"

echo "Waiting for reload..."
i=0; while [ $i -lt 20 ]; do
    sleep 0.5
    grep -q "geosite: reloaded domain rules" "$LOG_FILE" 2>/dev/null && break
    i=$((i+1))
done

if grep -q "removing stale rule for domain '${DOMAIN}'" "$LOG_FILE" 2>/dev/null; then
    pass "Stale rule for ${DOMAIN} removed"
fi

sleep 0.5
query "$DOMAIN"; sleep 1

if check_group "$DOMAIN" "default"; then
    pass "Step 3: ${DOMAIN} -> default (rule removed, FIX VERIFIED!)"
elif check_group "$DOMAIN" "cn"; then
    fail "Step 3: ${DOMAIN} still cn (BUG: stale rule NOT removed!)"
else
    echo "  Last result lines for ${DOMAIN}:"
    grep "result:.*${DOMAIN}" "$LOG_FILE" | grep -v "request:" | tail -3
    fail "Step 3: Cannot determine group for ${DOMAIN}"
fi

kill %1 %2 2>/dev/null || true
echo ""
echo "========================================="
echo "  ALL STEPS PASSED!"
echo "========================================="
