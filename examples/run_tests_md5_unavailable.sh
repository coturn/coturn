#!/bin/bash

# --use-auth-secret without MD5.
#
# REST-API (auth-secret) users are authenticated with an MD5-derived long-term
# key computed per request. When the OpenSSL providers cannot supply MD5 (a
# FIPS-only provider set), no such user can ever authenticate, so the server
# must refuse to start instead of answering 401 to everyone.
#
#   control:     normal OpenSSL configuration -> server starts.
#   restricted:  OPENSSL_CONF activating only the "base" provider -> server
#                exits with a CONFIG error naming MD5.
#
# Needs OpenSSL 3+ (provider configuration); SKIPs otherwise. Ports are offset
# from the defaults so a concurrent run_tests.sh cannot be mistaken for this
# suite's server.

SERVER_LOG="/tmp/run_tests_md5_unavailable.$$.turnserver.log"
OSSL_CONF="/tmp/run_tests_md5_unavailable.$$.openssl.cnf"
SERVER_PORT=3493
turnserver_pid=""

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -f "$SERVER_LOG" "$OSSL_CONF"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

start_turnserver() {
    "$BINDIR/turnserver" -n --use-auth-secret --static-auth-secret=secret --realm=north.gov \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --listening-port=$SERVER_PORT \
        --no-tls --log-file=stdout > "$SERVER_LOG" 2>&1 &
    turnserver_pid=$!
}

# Echoes "started" or "exited" once the server has settled either way.
wait_for_outcome() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$SERVER_LOG" 2>/dev/null; then
            echo started
            return
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo exited
            return
        fi
        sleep 0.5
    done
    echo timeout
}

stop_turnserver() {
    kill "$turnserver_pid" 2>/dev/null
    wait "$turnserver_pid" 2>/dev/null
    turnserver_pid=""
}

rc=0

echo 'Running turnserver (--use-auth-secret, default OpenSSL configuration)'
start_turnserver
outcome=$(wait_for_outcome)
# Skip only on a positively identified pre-3 / non-OpenSSL build; a missing
# banner means the server never got that far, which is a failure.
if ! grep -q "OpenSSL compile-time version:" "$SERVER_LOG"; then
    echo "FAIL: server printed no OpenSSL version banner ($outcome)"
    cat "$SERVER_LOG"
    exit 1
fi
if ! grep -qE "OpenSSL compile-time version: OpenSSL ([3-9]|[1-9][0-9])\." "$SERVER_LOG"; then
    echo "SKIP: provider configuration needs OpenSSL 3+"
    exit 0
fi
if [ "$outcome" = "started" ]; then
    echo OK
else
    echo "FAIL: server did not start with MD5 available ($outcome)"
    tail -20 "$SERVER_LOG"
    rc=1
fi
stop_turnserver

cat > "$OSSL_CONF" <<'CNF'
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
base = base_sect
[base_sect]
activate = 1
CNF

echo 'Running turnserver (--use-auth-secret, MD5 unavailable)'
export OPENSSL_CONF="$OSSL_CONF"
start_turnserver
outcome=$(wait_for_outcome)
unset OPENSSL_CONF
if [ "$outcome" = "exited" ] && grep -q "CONFIG: MD5 is unavailable" "$SERVER_LOG"; then
    echo OK
else
    echo "FAIL: server did not refuse to start without MD5 ($outcome)"
    tail -20 "$SERVER_LOG"
    rc=1
fi
[ "$outcome" = "exited" ] && turnserver_pid="" || stop_turnserver

exit $rc
