#!/bin/bash

# Relayed IP TTL must not leak into the server's own UDP replies.
#
# coturn relays a peer datagram to its client with the arriving TTL minus one,
# by setting IP_TTL on the client socket. UDP client sockets share the
# listener's fd, so that setting outlives the relayed datagram. This suite
# relays a TTL-2 peer datagram (sent to the client with TTL 1) and then checks
# that a response to another session and Binding responses to new clients
# still leave with the default TTL. One relay thread puts every client on the
# same listener.

TURNSERVER_LOG="/tmp/run_tests_relay_ttl.$$.turnserver.log"
turnserver_pid=""

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -f "$TURNSERVER_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not available (needed to drive raw STUN/TURN)"
    exit 0
fi

PORT=3478

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$TURNSERVER_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            cat "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}

echo "Running turnserver (no-auth, one relay thread) on 127.0.0.1:$PORT"
"$BINDIR/turnserver" --no-auth --allow-loopback-peers --no-tls \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --listening-port=$PORT --relay-threads=1 \
    --log-file=stdout > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid="$!"
wait_for_turnserver || exit 1

python3 scripts/relay_ttl_probe.py 127.0.0.1 $PORT
rc=$?
if [ "$rc" -eq 77 ]; then
    exit 0
elif [ "$rc" -ne 0 ]; then
    echo "FAIL: relayed TTL leaked into the server's own replies"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$TURNSERVER_LOG"
    exit 1
fi

echo "OK: relayed TTL suite passed"
