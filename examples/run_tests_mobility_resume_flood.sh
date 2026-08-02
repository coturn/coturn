#!/bin/bash

# Chained-mobility-resume exhaustion regression (GHSA-hpq3-g7x4-h7xx).
#
# With --mobility, an authenticated user can resume one allocation repeatedly
# from fresh 5-tuples without ever completing a handoff. Each resume opens a new
# pending dual-5-tuple transition in handle_turn_refresh
# (src/server/ns_turn_server.c). The allocation holds a single backlink to its
# pending resume; if a new resume overwrites it without tearing down the prior
# pending session, every superseded pending is orphaned — its un-allocated
# watchdog was disarmed and the transition-deadline sweep can no longer reach it,
# so it stays allocated indefinitely. One user could then grow server memory
# without bound, and --user-quota does not stop it (the pending sessions hold no
# quota unit).
#
# scripts/mobility_resume_flood.py drives that exact pattern with raw STUN
# (turnutils_uclient completes handoffs and does not model it). This test asserts
# that every resume after the first tears down the previous pending session, so
# live sessions stay bounded at one pending per allocation.

TURNSERVER_LOG="/tmp/run_tests_mobility_resume_flood.$$.turnserver.log"
CLIENT_LOG="/tmp/run_tests_mobility_resume_flood.$$.client.log"

turnserver_pid=""
cleanup() {
    [ -n "$turnserver_pid" ] && kill "$turnserver_pid" 2>/dev/null
    [ -n "$turnserver_pid" ] && wait "$turnserver_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$CLIENT_LOG"
}
trap cleanup EXIT

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not available (needed to drive the raw-STUN resume flood)"
    exit 0
fi

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

REALM="north.gov"
USER="user"
PASS="pass"
PORT=3478
RESUMES=50

echo 'Running turnserver (--mobility --user-quota=1)'
# --verbose so shutdown emits the per-session close reason the assertion greps.
# --user-quota=1 proves the quota does not bound the chain. Long-term
# credentials (--user) match the raw-STUN client's MD5 key derivation.
$BINDIR/turnserver --realm="$REALM" --user="$USER:$PASS" --user-quota=1 --mobility \
    --listening-port="$PORT" --no-tls --no-cli --relay-threads=1 \
    --verbose --log-file=stdout > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid="$!"

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
wait_for_turnserver || exit 1
sleep 1

echo "Running chained-resume flood ($RESUMES resumes from fresh 5-tuples)"
python3 scripts/mobility_resume_flood.py 127.0.0.1 "$PORT" "$USER" "$PASS" "$RESUMES" > "$CLIENT_LOG" 2>&1
client_rc="$?"
cat "$CLIENT_LOG"

if [ "$client_rc" -ne 0 ] || ! grep -q "RESULT resumes=$RESUMES" "$CLIENT_LOG"; then
    echo "FAIL: server did not accept all $RESUMES legitimate resumes"
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null
    exit 1
fi

if ! kill -0 "$turnserver_pid" 2>/dev/null; then
    echo "FAIL: turnserver exited during the resume flood"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null
    exit 1
fi

# Each resume after the first must tear down the pending session the previous
# resume left behind. A vulnerable server never emits this marker (it orphans
# them instead), so the count is the regression signal.
echo "Checking that superseded pending sessions are torn down"
n=$(grep -c "superseded by newer mobility resume" "$TURNSERVER_LOG" 2>/dev/null)
expected=$((RESUMES - 1))
if [ "${n:-0}" -ge "$expected" ]; then
    echo "OK (superseded pending teardowns: $n >= $expected)"
else
    echo "FAIL: only $n superseded-pending teardowns, expected >= $expected"
    echo "  Orphaned pending sessions accumulate: the chained-resume memory"
    echo "  exhaustion (GHSA-hpq3-g7x4-h7xx) is not bounded."
    echo "--- turnserver mobility/close lines (last 20) ---"
    grep -iE "mobil|handoff|closed|superseded" "$TURNSERVER_LOG" 2>/dev/null | tail -20
    exit 1
fi

echo "OK"
