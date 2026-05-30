#!/bin/bash

# Functional test for the lazy permission/channel expiry sweep.
#
# Background: permission and channel expiry used to be driven by one
# libevent timer per permission and per channel. That was replaced by a
# single per-thread sweep (timer_timeout_handler -> turn_server_sweep_timed_events
# in src/server/ns_turn_server.c) that walks every session once a second and
# reaps entries whose expiration_time has passed. This test proves the sweep
# actually fires and reaps mid-session, without breaking the relay or the
# rest of the session.
#
# How it forces the sweep to act:
#   * The server uses its OWN --permission-lifetime / --channel-lifetime for
#     every CreatePermission / ChannelBind (it ignores the lifetime the client
#     asks for: see update_turn_permission_lifetime / update_channel_lifetime).
#   * turnutils_uclient only re-sends CreatePermission + ChannelBind every 30s
#     (refresh_channel() in src/apps/uclient/uclient.c). Plain channel data does
#     NOT refresh the permission.
#   * With server lifetimes set to 4s and a ~18s run, the permission+channel are
#     created at t=0, then reaped by the sweep at t~=4 — well before the next
#     client refresh. The only code path that logs "peer ... deleted" for a live,
#     un-torn-down session is turn_permission_clean() invoked by the sweep, so a
#     "deleted" line during the run is proof the sweep ran and reaped.
#
# A regression where the sweep never fires => no "deleted" line => FAIL.
# A regression where it reaps too eagerly / crashes => server dies or never logs
# the creation => FAIL.

TURNSERVER_LOG="/tmp/run_tests_expiry.$$.turnserver.log"
PEER_LOG="/tmp/run_tests_expiry.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests_expiry.$$.uclient.log"

turnserver_pid=""
peer_pid=""

cleanup() {
    kill "$turnserver_pid" "$peer_pid" 2>/dev/null
    wait "$turnserver_pid" "$peer_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$PEER_LOG" "$UCLIENT_LOG"
}
trap cleanup EXIT

BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

# Short lifetimes force the sweep to reap between the client's 30s refreshes.
PERM_LIFETIME=4
CHAN_LIFETIME=4
RUN_SECONDS=18

echo "Running turnserver (verbose, permission/channel lifetime ${PERM_LIFETIME}s)"
# Pin loopback explicitly: without --listening-ip the server auto-detects every
# interface address, which intermittently includes transient IPv6 privacy
# addresses it cannot bind (errno=22), stalling startup. The test only needs
# loopback.
$BINDIR/turnserver --verbose --use-auth-secret --static-auth-secret=secret \
    --realm=north.gov --allow-loopback-peers \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --no-dtls --no-tls \
    --permission-lifetime=$PERM_LIFETIME --channel-lifetime=$CHAN_LIFETIME \
    --log-file=stdout --simple-log \
    --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem \
    > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid="$!"

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$TURNSERVER_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver exited before init completed"
            tail -30 "$TURNSERVER_LOG" 2>/dev/null
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' within 20s"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null
    return 1
}
wait_for_turnserver || exit 1
sleep 1

echo 'Running peer client'
$BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > "$PEER_LOG" 2>&1 &
peer_pid="$!"
sleep 1

echo "Running turn client UDP for ${RUN_SECONDS}s (creates a permission + channel, then idles past the lifetime)"
# -n large so the client keeps the session up for the whole window; timeout
# stops it. We do NOT assert on relayed byte counts here: once the permission
# expires mid-run the relay intentionally drops traffic, so loss is expected
# and is not the property under test. The property is the server-side lifecycle
# in the log, asserted below.
timeout -s INT ${RUN_SECONDS}s "$BINDIR/turnutils_uclient" \
    -n 1000000 -m 1 -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 \
    > "$UCLIENT_LOG" 2>&1
rc=$?
# 124 (SIGTERM by timeout) / 130 (SIGINT clean exit) are the expected stop codes.
if [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 130 ]; then
    echo "FAIL: turnutils_uclient exited unexpectedly with $rc"
    tail -20 "$UCLIENT_LOG"
    exit 1
fi

fail() {
    echo "FAIL: $1"
    echo "--- turnserver log: permission lifecycle lines ---"
    grep -iE "lifetime updated|deleted" "$TURNSERVER_LOG" 2>/dev/null | head -20
    echo "--- turnserver log (last 20 lines) ---"
    tail -20 "$TURNSERVER_LOG" 2>/dev/null
    exit 1
}

# 1. The server must still be alive (the sweep ran on its event loop every 1s
#    for the whole run; a crash/UAF in the sweep would have taken it down).
if ! kill -0 "$turnserver_pid" 2>/dev/null; then
    fail "turnserver is no longer running after the expiry run (possible crash in the sweep)"
fi

# 2. A permission must have been created (verbose 'lifetime updated' line). This
#    confirms the client reached the server and the lifecycle started.
if ! grep -q "lifetime updated" "$TURNSERVER_LOG"; then
    fail "no 'lifetime updated' line — permission was never created; cannot test expiry"
fi

# 3. A permission must have been reaped mid-session by the sweep ('deleted'
#    line). For a live (un-torn-down) session this is reachable only via the
#    sweep, so its presence proves lazy expiry fired.
deleted_count=$(grep -c "deleted" "$TURNSERVER_LOG")
if [ "${deleted_count:-0}" -lt 1 ]; then
    fail "no 'deleted' line — the sweep did not reap the expired permission/channel"
fi

echo "OK (sweep reaped ${deleted_count} expired permission(s)/channel(s); server healthy)"
