#!/bin/bash

# Plaintext datagrams on an established DTLS 5-tuple must not be treated as
# TURN input. After Allocate/CreatePermission/ChannelBind over DTLS, inject
# plaintext Send/ChannelData/Binding on the same tuple: encrypted Send is
# delivered; plaintext payloads and Binding are not.
#
# Exit 0 = PASS. Needs OpenSSL, python3, and --dtls.

set -u

LOG="/tmp/run_tests_dtls_plaintext_reject.$$.log"
PROXY_LOG="/tmp/run_tests_dtls_plaintext_reject.$$.proxy.log"
DRIVER_LOG="/tmp/run_tests_dtls_plaintext_reject.$$.driver.log"
turnserver_pid=""
proxy_pid=""
SERVER_PORT=5359
PROXY_BIND=40010
PEER_PORT=9998
WORKDIR="/tmp/run_tests_dtls_plaintext_reject.$$"
FAIL=0

cleanup() {
    if [ -n "$proxy_pid" ]; then
        kill "$proxy_pid" 2>/dev/null
        wait "$proxy_pid" 2>/dev/null
    fi
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -rf "$WORKDIR"
    rm -f "$LOG" "$PROXY_LOG" "$DRIVER_LOG"
}
trap cleanup EXIT

BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DRIVER_DIR="$SCRIPT_DIR/scripts/dtls_plaintext"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Skipping DTLS plaintext-reject test (no python3)"
    exit 0
fi

mkdir -p "$WORKDIR"

# Prefer pkg-config openssl; fall back to common Homebrew/MacPorts paths.
OPENSSL_CFLAGS=""
OPENSSL_LIBS="-lssl -lcrypto"
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
    OPENSSL_CFLAGS="$(pkg-config --cflags openssl)"
    OPENSSL_LIBS="$(pkg-config --libs openssl)"
fi

if ! cc -O2 $OPENSSL_CFLAGS -o "$WORKDIR/dtls_proxy" "$DRIVER_DIR/dtls_proxy.c" $OPENSSL_LIBS 2>"$WORKDIR/cc.err"; then
    echo "Skipping DTLS plaintext-reject test (cannot build dtls_proxy)"
    cat "$WORKDIR/cc.err" 2>/dev/null | tail -5
    exit 0
fi

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver exited before init"
            cat "$LOG" 2>/dev/null || true
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:'"
    tail -30 "$LOG" 2>/dev/null || true
    return 1
}

: > "$LOG"
"$BINDIR/turnserver" --lt-cred-mech --user alice:secret --realm=example.org \
    --allow-loopback-peers --dtls \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --listening-port=3479 --tls-listening-port="$SERVER_PORT" \
    --cert "$SCRIPT_DIR/ca/turn_server_cert.pem" \
    --pkey "$SCRIPT_DIR/ca/turn_server_pkey.pem" \
    --log-file=stdout \
    > "$LOG" 2>&1 &
turnserver_pid="$!"
wait_for_turnserver || exit 1

grep -q "DTLS cipher suite:" "$LOG" || {
    echo "Skipping DTLS plaintext-reject test (no DTLS listener)"
    exit 0
}

"$WORKDIR/dtls_proxy" 127.0.0.1 "$SERVER_PORT" "$PROXY_BIND" >"$PROXY_LOG" 2>&1 &
proxy_pid="$!"
# Wait for handshake
for i in $(seq 1 30); do
    if grep -q "DTLS handshake done" "$PROXY_LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
        echo "FAIL: DTLS proxy exited during handshake"
        cat "$PROXY_LOG"
        exit 1
    fi
    sleep 0.2
done
grep -q "DTLS handshake done" "$PROXY_LOG" || {
    echo "FAIL: DTLS handshake did not complete"
    cat "$PROXY_LOG"
    exit 1
}

# The driver hard-codes 7001/7002; the proxy always binds those. Run it.
python3 "$DRIVER_DIR/turn_over_dtls.py" 127.0.0.1 "$PEER_PORT" alice secret >"$DRIVER_LOG" 2>&1
rc=$?
cat "$DRIVER_LOG"

if [ "$rc" -eq 1 ]; then
    echo "OK: DTLS plaintext injection rejected"
    exit 0
fi

if [ "$rc" -eq 0 ]; then
    echo "FAIL: plaintext datagrams on the DTLS 5-tuple were processed as TURN input"
    echo "--- proxy log ---"
    cat "$PROXY_LOG"
    echo "--- turnserver log (last 40) ---"
    tail -40 "$LOG"
    exit 1
fi

echo "FAIL: driver harness error (exit $rc)"
cat "$PROXY_LOG"
exit 1
