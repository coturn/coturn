#!/bin/bash

# Mobility quota-bypass regression test (GHSA-f6hc-79w3-p8pq).
#
# Starts the server with --mobility and strict --user-quota=1 --total-quota=1 on
# a small relay-port pool, then drives examples/scripts/mobility_quota_flood.py.
# The driver repeatedly creates a mobility-enabled allocation over TCP and
# disconnects: a fixed server keeps the allocation's quota charge across the
# first-stage mobility close, so it admits exactly one allocation and rejects the
# next with 486; a vulnerable server released the charge on disconnect and
# admitted many until the relay port pool was exhausted (508). The driver also
# checks that the legitimate mobility flow (allocate, disconnect, resume from a
# fresh 5-tuple) still succeeds under quota=1 — the fix must not double-charge
# the resuming session.
#
# Raw STUN over TCP on loopback, so this is deterministic on both Linux and
# macOS (no SSL reconnect, unlike the -M TLS/DTLS paths).

TURNSERVER_LOG="/tmp/run_tests_mobility_quota.$$.turnserver.log"
CLIENT_LOG="/tmp/run_tests_mobility_quota.$$.client.log"

cleanup() {
    kill "$turnserver_pid" 2>/dev/null
    wait "$turnserver_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$CLIENT_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

# Ten relay ports so a vulnerable server visibly overruns quota=1 before it hits
# 508; --relay-threads=1 keeps quota accounting and port assignment deterministic.
echo 'Running turnserver (--mobility --user-quota=1 --total-quota=1)'
$BINDIR/turnserver --realm=north.gov --user=user:pass \
    --user-quota=1 --total-quota=1 --mobility \
    --listening-port=3478 --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --min-port=53000 --max-port=53009 \
    --no-tls --no-dtls --no-cli --relay-threads=1 \
    --verbose --log-file=stdout --simple-log > "$TURNSERVER_LOG" 2>&1 &
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

echo 'Running mobility quota flood driver'
python3 ./scripts/mobility_quota_flood.py 127.0.0.1 3478 user pass 8 > "$CLIENT_LOG" 2>&1
result=$(grep "^RESULT" "$CLIENT_LOG" 2>/dev/null | tail -1)

diagnose() {
    echo "FAIL: $1"
    echo "--- client output ---"
    cat "$CLIENT_LOG" 2>/dev/null || echo "(client log missing)"
    echo "--- turnserver: quota / capacity / mobility lines ---"
    grep -iE "486|508|1st stage|2nd stage|handoff|quota|no available ports" "$TURNSERVER_LOG" 2>/dev/null | tail -30
    exit 1
}

echo "Client: $result"
[ -n "$result" ] || diagnose "driver produced no RESULT line"

# A fixed server admits exactly one, rejects the next with 486, and still
# resumes. Any other shape is the bypass (or a broken resume).
echo "$result" | grep -q "flood_accepted=1 " || diagnose "quota not enforced across mobility disconnect (expected flood_accepted=1)"
echo "$result" | grep -q "flood_reject=486" || diagnose "second allocation not rejected by quota (expected flood_reject=486)"
echo "$result" | grep -q "resume=OK" || diagnose "legitimate mobility resume broken under quota=1"

# Server-side corroboration: the port pool must never have been exhausted.
if grep -q "no available ports" "$TURNSERVER_LOG" 2>/dev/null; then
    diagnose "server exhausted its relay port pool (508) — quota was bypassed"
fi

echo OK
exit 0
