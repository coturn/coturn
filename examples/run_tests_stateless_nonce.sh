#!/bin/bash

# Stateless-nonce regression suite (issue #1999).
#
# Starts the server with --stateless-nonce and drives the same relay
# workload as run_tests.sh over UDP and TCP (plus TLS/DTLS on Linux).
# With the flag on:
#   - a first MESSAGE-INTEGRITY-less UDP request is answered with a
#     derived-nonce 401 straight from the listener, with no session
#     allocated (udp_stateless_nonce_fast_path in dtls_listener.c);
#   - the client's authenticated retry lands on a brand-new session whose
#     check_stun_auth accepts the derived nonce (window +/- 1);
#   - UDP sessions that only carried a challenge are torn down right after
#     the response instead of lingering for the to-be-allocated timeout.
# The whole point of the feature is wire-transparency, so the assertion is
# simply that the standard client workload succeeds end-to-end, plus a
# server-log marker proving the listener fast path actually engaged (rather
# than silently falling back to the per-session path).

TURNSERVER_LOG="/tmp/run_tests_stateless_nonce.$$.turnserver.log"
PEER_LOG="/tmp/run_tests_stateless_nonce.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests_stateless_nonce.$$.uclient.log"

cleanup() {
    kill "$turnserver_pid" "$peer_pid" 2>/dev/null
    wait "$turnserver_pid" "$peer_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$PEER_LOG" "$UCLIENT_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

IS_DARWIN=0
if [ "$(uname -s)" = "Darwin" ]; then
    IS_DARWIN=1
fi

TURNSERVER_EXTRA_ARGS="--relay-threads=1"
if [ "$(uname -s)" = "Linux" ]; then
    TURNSERVER_EXTRA_ARGS="$TURNSERVER_EXTRA_ARGS  --udp-recvmmsg "
    echo "Using TURNSERVER_EXTRA_ARGS=\"$TURNSERVER_EXTRA_ARGS\""
fi

echo 'Running turnserver (--stateless-nonce)'
$BINDIR/turnserver --use-auth-secret --sock-buf-size=1048576 --static-auth-secret=secret --realm=north.gov --allow-loopback-peers --stateless-nonce --log-file=stdout --simple-log $TURNSERVER_EXTRA_ARGS --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid="$!"

echo 'Running peer client'
if [ $IS_DARWIN -eq 1 ]; then
    $BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &
else
    $BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > "$PEER_LOG" 2>&1 &
fi
peer_pid="$!"

# Poll OUR uniquely-named log for a known late-startup line before driving
# clients (see run_tests.sh for the rationale behind not probing the port).
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
        if ! kill -0 "$peer_pid" 2>/dev/null; then
            echo "FATAL: turnutils_peer (pid $peer_pid) exited before tests started"
            cat "$PEER_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}
wait_for_turnserver || exit 1
sleep 2

diagnose_failure() {
    local label="$1"
    echo "=== Diagnostics for failed test: $label ==="
    echo "--- uclient: tot_send/tot_recv progress (last 6 lines) ---"
    grep "start_mclient: tot_send_msgs" "$UCLIENT_LOG" 2>/dev/null | tail -6
    echo "--- uclient: auth / errors ---"
    grep -iE "401|438|nonce|error|warning|fail|cannot" "$UCLIENT_LOG" 2>/dev/null | tail -10
    echo "--- turnserver: auth / session lines (last 40 lines) ---"
    grep -iE "401|438|nonce|session|error" "$TURNSERVER_LOG" 2>/dev/null | tail -40
    echo "--- turnserver log (last 20 lines) ---"
    tail -20 "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
    echo "==="
}

# Same canonical workload and success line as run_tests.sh: each client run
# relays 1000 bytes each way through an allocation obtained via the
# 401-challenge/re-auth dance, which is exactly the path the stateless
# nonce changes.
run_uclient() {
    local label="$1"
    shift
    echo "Running $label"
    "$BINDIR/turnutils_uclient" "$@" -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 > "$UCLIENT_LOG" 2>&1
    if grep -q "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" "$UCLIENT_LOG"; then
        echo OK
    else
        echo FAIL
        diagnose_failure "$label"
        exit 1
    fi
}

# Legacy single-threaded uclient across the transports.
run_uclient "stateless-nonce turn client UDP"
run_uclient "stateless-nonce turn client TCP" -t

# The UDP run above must have gone through the listener fast path: the first
# ALLOCATE has no MESSAGE-INTEGRITY, so the 401 challenge is emitted without
# creating a session, and the server logs this one-time marker.
echo "Checking listener fast-path marker"
if grep -q "stateless-nonce: listener fast-path challenge active" "$TURNSERVER_LOG"; then
    echo "OK (listener fast path engaged)"
else
    echo "FAIL: no listener fast-path marker in server log"
    diagnose_failure "fast-path marker"
    exit 1
fi

if [ $IS_DARWIN -eq 1 ]; then
    # Match the other suites: keep the Darwin run to the deterministic subset.
    sleep 2
    exit 0
fi

# TLS and DTLS keep their per-connection sessions; with the flag on they
# must still authenticate and relay exactly as before (derived nonces are
# handed out by the session path there).
run_uclient "stateless-nonce turn client TLS" -t -S
run_uclient "stateless-nonce turn client DTLS" -S

# Threaded worker pools engaged.
run_uclient "stateless-nonce turn client UDP (threaded)" --listener-threads 1 --sender-threads 1
run_uclient "stateless-nonce turn client TCP (threaded)" -t --listener-threads 1 --sender-threads 1

sleep 2
