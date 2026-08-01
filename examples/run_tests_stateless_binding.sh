#!/bin/bash

# Listener-side STUN Binding regression suite.
#
# A Binding request from an unknown UDP source is answered by the listener
# itself (udp_stateless_binding_fast_path in dtls_listener.c) instead of
# costing a child socket plus a session held for the to-be-allocated timeout.
# The point is that nothing about the reply changes, so this suite asserts
# both halves:
#
#   - wire: the success response and its XOR-MAPPED-ADDRESS, the 420
#     UNKNOWN-ATTRIBUTES list, the attributes ICE clients attach, and the
#     RFC 5780 probes (CHANGE-REQUEST / RESPONSE-PORT / PADDING), which must
#     still reach the relay because only it owns the alternate sockets;
#   - configuration: --no-stun stays silent, --secure-stun still challenges;
#   - memory: one Binding per source port must not grow the server. Before the
#     fast path, 3000 such requests cost ~67MB of live sessions.

TURNSERVER_LOG="/tmp/run_tests_stateless_binding.$$.turnserver.log"
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
    echo "SKIP: python3 not available (needed to drive raw STUN Binding shapes)"
    exit 0
fi

PORT=3479

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

run_server() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    : > "$TURNSERVER_LOG"
    "$BINDIR/turnserver" --use-auth-secret --static-auth-secret=secret --realm=north.gov \
        --allow-loopback-peers --no-cli --no-tls \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
        --listening-port=$PORT \
        --log-file=stdout --simple-log \
        "$@" > "$TURNSERVER_LOG" 2>&1 &
    turnserver_pid="$!"
    wait_for_turnserver
}

fail() {
    echo "FAIL: $1"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$TURNSERVER_LOG"
    exit 1
}

echo "Running Binding wire shapes (default configuration)"
run_server || exit 1
python3 scripts/stateless_binding_probe.py 127.0.0.1 $PORT wire || fail "Binding wire shapes"

echo "Running Binding with --no-stun"
run_server --no-stun || exit 1
python3 scripts/stateless_binding_probe.py 127.0.0.1 $PORT silent || fail "--no-stun"

echo "Running Binding with --secure-stun"
run_server --secure-stun || exit 1
python3 scripts/stateless_binding_probe.py 127.0.0.1 $PORT challenge || fail "--secure-stun"

# Memory: 2000 Binding requests, each from its own source port. Every one of
# them used to leave a session behind for TURN_MAX_ALLOCATE_TIMEOUT (~22KB
# each, so ~44MB); the listener path leaves nothing but buffers. The threshold
# is deliberately loose - it is there to catch the sessions coming back, not to
# pin an allocator. A warm-up flood first, so the per-thread receive buffers
# (which scale with core count) are already charged to the baseline.
FLOOD=2000
FLOOD_WARMUP=200
FLOOD_MAX_GROWTH_KB=16384

echo "Running Binding flood ($FLOOD requests from distinct source ports)"
run_server || exit 1
python3 scripts/stateless_binding_probe.py 127.0.0.1 $PORT flood "$FLOOD_WARMUP" > /dev/null || fail "Binding warm-up"
sleep 1
rss_before="$(ps -o rss= -p "$turnserver_pid" | tr -d ' ')"
python3 scripts/stateless_binding_probe.py 127.0.0.1 $PORT flood "$FLOOD" || fail "Binding flood"
sleep 2
rss_after="$(ps -o rss= -p "$turnserver_pid" | tr -d ' ')"
growth=$((rss_after - rss_before))

if [ -z "$rss_before" ] || [ -z "$rss_after" ]; then
    echo "SKIP: could not read turnserver RSS on this platform"
elif [ "$growth" -lt "$FLOOD_MAX_GROWTH_KB" ]; then
    echo "OK (RSS ${rss_before}KB -> ${rss_after}KB, +${growth}KB for $FLOOD requests)"
else
    fail "Binding flood grew RSS by ${growth}KB (limit ${FLOOD_MAX_GROWTH_KB}KB) - sessions are being created again"
fi

echo "OK: stateless Binding suite passed"
