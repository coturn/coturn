#!/bin/bash

# One cookie-verified host must not exhaust the DTLS half-open cap for
# everyone. Fills TURN_DTLS_HALF_OPEN_PER_SOURCE stalls from one bind address,
# asserts a further stall from that host is rejected, and that a second bind
# address can still complete a handshake.
#
# Needs OpenSSL, two bindable IPv4 addresses (127.0.0.1 and 127.0.0.2 on Linux;
# on macOS 127.0.0.2 may need an alias — the script SKIPs if bind fails), and
# --dtls. Exit 0 = PASS.

set -u

LOG="/tmp/run_tests_dtls_half_open.$$.log"
DRIVER_LOG="/tmp/run_tests_dtls_half_open.$$.driver.log"
WORKDIR="/tmp/run_tests_dtls_half_open.$$"
turnserver_pid=""
SERVER_PORT=5361
PER_SOURCE=4

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -rf "$WORKDIR"
    rm -f "$LOG" "$DRIVER_LOG"
}
trap cleanup EXIT

BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DRIVER_DIR="$SCRIPT_DIR/scripts/dtls_half_open"

mkdir -p "$WORKDIR"

OPENSSL_CFLAGS=""
OPENSSL_LIBS="-lssl -lcrypto"
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
    OPENSSL_CFLAGS="$(pkg-config --cflags openssl)"
    OPENSSL_LIBS="$(pkg-config --libs openssl)"
fi

if ! cc -O2 $OPENSSL_CFLAGS -o "$WORKDIR/dtls_per_source" "$DRIVER_DIR/dtls_per_source.c" $OPENSSL_LIBS \
    2>"$WORKDIR/cc.err"; then
    echo "Skipping DTLS half-open per-source test (cannot build driver)"
    tail -5 "$WORKDIR/cc.err" 2>/dev/null || true
    exit 0
fi

# Probe whether 127.0.0.2 is bindable (native on Linux; often missing on macOS).
if ! python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind(("127.0.0.2", 0))
except OSError:
    sys.exit(1)
sys.exit(0)
PY
then
    echo "Skipping DTLS half-open per-source test (127.0.0.2 not bindable)"
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
    --allow-loopback-peers --dtls --relay-threads 1 \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --listening-port=3481 --tls-listening-port="$SERVER_PORT" \
    --cert "$SCRIPT_DIR/ca/turn_server_cert.pem" \
    --pkey "$SCRIPT_DIR/ca/turn_server_pkey.pem" \
    --log-file=stdout \
    > "$LOG" 2>&1 &
turnserver_pid="$!"
wait_for_turnserver || exit 1

grep -q "DTLS cipher suite:" "$LOG" || {
    echo "Skipping DTLS half-open per-source test (no DTLS listener)"
    exit 0
}

# Attacker = 127.0.0.1, victim = 127.0.0.2, server on 127.0.0.1:SERVER_PORT
"$WORKDIR/dtls_per_source" 127.0.0.1 "$SERVER_PORT" 127.0.0.1 127.0.0.2 "$PER_SOURCE" \
    >"$DRIVER_LOG" 2>&1
rc=$?
cat "$DRIVER_LOG"

if [ "$rc" -eq 0 ]; then
    echo "OK: DTLS half-open per-source share"
    exit 0
fi

echo "FAIL: DTLS half-open per-source share"
echo "--- turnserver log (last 40) ---"
tail -40 "$LOG"
exit 1
