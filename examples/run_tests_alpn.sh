#!/bin/bash

# TLS/DTLS ALPN negotiation test.
#
# RFC 7301 Section 3.2: when the server supports none of the protocols the
# client offers, it must answer with a fatal no_application_protocol alert.
#
#   stun.turn / stun.nat-discovery offered -> selected, unless --stun-only or
#                                             --no-stun turns that service off.
#   only foreign protocols offered          -> handshake aborted with the alert.
#   no ALPN extension at all                -> handshake completes, no ALPN.
#   http/1.1 offered                        -> selected only with --web-admin or
#                                             --respond-http-unsupported.
#
# Ports are offset from the defaults so a concurrent run_tests.sh cannot be
# mistaken for this suite's server.

ALPN_LOG="/tmp/run_tests_alpn.$$.turnserver.log"
CLIENT_LOG="/tmp/run_tests_alpn.$$.s_client.log"
turnserver_pid=""

SERVER_PORT=3493
TLS_PORT=3494
WEB_ADMIN_PORT=3495

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -f "$ALPN_LOG" "$CLIENT_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "SKIP: openssl command line tool not found"
    exit 0
fi

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$ALPN_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            echo "--- turnserver log ---"
            cat "$ALPN_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$ALPN_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}

start_turnserver() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
        turnserver_pid=""
    fi
    : > "$ALPN_LOG"
    "$BINDIR/turnserver" --use-auth-secret --static-auth-secret=secret --realm=north.gov \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
        --listening-port="$SERVER_PORT" --tls-listening-port="$TLS_PORT" \
        --cert ../examples/ca/turn_server_cert.pem \
        --pkey ../examples/ca/turn_server_pkey.pem \
        --log-file=stdout \
        "$@" > "$ALPN_LOG" 2>&1 &
    turnserver_pid="$!"
    wait_for_turnserver
}

# Handshake against the TLS/DTLS listener; extra arguments go to s_client.
handshake() {
    openssl s_client -connect "127.0.0.1:$TLS_PORT" "$@" < /dev/null > "$CLIENT_LOG" 2>&1
}

selected() {
    grep -q "ALPN protocol: $1" "$CLIENT_LOG"
}

# no_application_protocol is TLS alert 120. OpenSSL 3.0 prints only the
# number, LibreSSL and newer OpenSSL print the name.
rejected_no_app_protocol() {
    grep -Eqi "alert number 120|no application protocol" "$CLIENT_LOG"
}

fail() {
    echo "FAIL: $1"
    echo "--- s_client output (last 20 lines) ---"
    tail -20 "$CLIENT_LOG" 2>/dev/null || echo "(no s_client output)"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$ALPN_LOG"
    exit 1
}

echo "Running ALPN without web admin"
start_turnserver || exit 1

handshake -alpn stun.turn || fail "handshake with stun.turn failed"
selected stun.turn || fail "stun.turn not selected"

handshake -alpn h2,stun.nat-discovery || fail "handshake with stun.nat-discovery failed"
selected stun.nat-discovery || fail "stun.nat-discovery not selected"

handshake -alpn h2 && fail "handshake with only h2 offered succeeded"
rejected_no_app_protocol || fail "no no_application_protocol alert for h2"

handshake -alpn http/1.1 && fail "http/1.1 accepted without --web-admin"
rejected_no_app_protocol || fail "no no_application_protocol alert for http/1.1"

handshake || fail "handshake without ALPN failed"
grep -q "ALPN protocol:" "$CLIENT_LOG" && fail "ALPN negotiated although the client sent none"
echo OK

echo "Running ALPN with web admin"
start_turnserver --web-admin --web-admin-ip=127.0.0.1 --web-admin-port="$WEB_ADMIN_PORT" || exit 1

handshake -alpn h2,http/1.1 || fail "handshake with http/1.1 failed under --web-admin"
selected http/1.1 || fail "http/1.1 not selected under --web-admin"

handshake -alpn h2 && fail "handshake with only h2 offered succeeded under --web-admin"
rejected_no_app_protocol || fail "no no_application_protocol alert for h2 under --web-admin"
echo OK

# HTTPS health checks of a load balancer rely on the 400 answer, and curl
# offers h2,http/1.1 by default.
echo "Running ALPN with --respond-http-unsupported"
start_turnserver --respond-http-unsupported || exit 1

handshake -alpn h2,http/1.1 || fail "handshake with http/1.1 failed under --respond-http-unsupported"
selected http/1.1 || fail "http/1.1 not selected under --respond-http-unsupported"

handshake -alpn h2 && fail "handshake with only h2 offered succeeded under --respond-http-unsupported"
rejected_no_app_protocol || fail "no no_application_protocol alert for h2 under --respond-http-unsupported"
echo OK

echo "Running ALPN with --stun-only"
start_turnserver --stun-only || exit 1

handshake -alpn stun.turn && fail "stun.turn accepted under --stun-only"
rejected_no_app_protocol || fail "no no_application_protocol alert for stun.turn under --stun-only"

handshake -alpn stun.turn,stun.nat-discovery || fail "handshake with stun.nat-discovery failed under --stun-only"
selected stun.nat-discovery || fail "stun.nat-discovery not selected under --stun-only"
echo OK

echo "Running ALPN with --no-stun"
start_turnserver --no-stun || exit 1

handshake -alpn stun.nat-discovery && fail "stun.nat-discovery accepted under --no-stun"
rejected_no_app_protocol || fail "no no_application_protocol alert for stun.nat-discovery under --no-stun"

handshake -alpn stun.nat-discovery,stun.turn || fail "handshake with stun.turn failed under --no-stun"
selected stun.turn || fail "stun.turn not selected under --no-stun"
echo OK

echo "Running ALPN over DTLS"
start_turnserver --dtls || exit 1

handshake -dtls -alpn stun.turn || fail "DTLS handshake with stun.turn failed"
selected stun.turn || fail "stun.turn not selected over DTLS"

handshake -dtls -alpn h2 && fail "DTLS handshake with only h2 offered succeeded"
rejected_no_app_protocol || fail "no no_application_protocol alert for h2 over DTLS"
echo OK
