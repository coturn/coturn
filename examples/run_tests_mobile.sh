#!/bin/bash

# Mobility (MICE) regression suite.
#
# Exercises the MOBILITY-TICKET session-resume path in handle_turn_refresh
# (src/server/ns_turn_server.c). The stock run_tests.sh never passes
# --mobility, so that whole resume branch — including the credential
# adoption that authorizes a resume against the original allocation's
# owner — otherwise gets zero automated coverage. This script starts the
# server with --mobility and drives turnutils_uclient with -M, which
# allocates, obtains a MOBILITY-TICKET, reopens on a fresh 5-tuple, and
# sends a REFRESH carrying that ticket. That REFRESH lands in the resume
# branch and runs copy_auth_parameters(orig_ss, ss) + check_stun_auth, so
# a regression that breaks legitimate same-user resume fails CI here.
#
# Protocol scope: UDP and TCP only. -M over TLS/DTLS randomly tears down
# and re-handshakes the SSL connection mid-run
# (src/apps/uclient/startuclient.c), which is non-deterministic on a
# loopback harness and would make this suite flaky. UDP and TCP drive the
# same resume branch without an SSL reconnect, so they are the reliable
# signal. This exercises the legitimate same-user resume; turnutils_uclient
# does not model a resume driven from a separately-authenticated session.

# Per-run log paths; $$ keeps concurrent invocations from clobbering each
# other. cleanup() removes them on exit.
TURNSERVER_LOG="/tmp/run_tests_mobile.$$.turnserver.log"
PEER_LOG="/tmp/run_tests_mobile.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests_mobile.$$.uclient.log"

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

# Match run_tests.sh: enable the Linux-only recvmmsg drain path so the
# mobility run also exercises it.
TURNSERVER_EXTRA_ARGS="--relay-threads=1"
if [ "$(uname -s)" = "Linux" ]; then
    TURNSERVER_EXTRA_ARGS="$TURNSERVER_EXTRA_ARGS  --udp-recvmmsg "
    echo "Using TURNSERVER_EXTRA_ARGS=\"$TURNSERVER_EXTRA_ARGS\""
fi

echo 'Running turnserver (--mobility)'
# Always capture the server log (both platforms): the handoff assertion below
# greps it for the RFC 8016 dual-5-tuple transition marker.
$BINDIR/turnserver --use-auth-secret --sock-buf-size=1048576 --static-auth-secret=secret --realm=north.gov --allow-loopback-peers --mobility --log-file=stdout --simple-log $TURNSERVER_EXTRA_ARGS --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > "$TURNSERVER_LOG" 2>&1 &
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
if [ $IS_DARWIN -eq 1 ]; then
    sleep 2
else
    wait_for_turnserver || exit 1
    sleep 2
fi

diagnose_failure() {
    local label="$1"
    echo "=== Diagnostics for failed test: $label ==="
    echo "--- uclient: tot_send/tot_recv progress (last 6 lines) ---"
    grep "start_mclient: tot_send_msgs" "$UCLIENT_LOG" 2>/dev/null | tail -6
    echo "--- uclient: mobility / errors ---"
    grep -iE "smid=|mobil|refresh|error|warning|fail|cannot" "$UCLIENT_LOG" 2>/dev/null | tail -10
    echo "--- turnserver: mobility / auth / relay errors (last 40 lines) ---"
    grep -iE "mobil|401|438|441|socket|relay|allocation" "$TURNSERVER_LOG" 2>/dev/null | tail -40
    echo "--- turnserver log (last 20 lines) ---"
    tail -20 "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
    echo "==="
}

# -M drives the mobility allocate + reopen + REFRESH-with-ticket dance. The
# workload is otherwise identical to run_tests.sh (-m 1, default -n),
# totalling 1000 bytes each way, so the same canonical success line applies.
run_uclient() {
    local label="$1"
    shift
    echo "Running $label"
    "$BINDIR/turnutils_uclient" -M "$@" -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 > "$UCLIENT_LOG" 2>&1
    if grep -q "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" "$UCLIENT_LOG"; then
        echo OK
    else
        echo FAIL
        diagnose_failure "$label"
        exit 1
    fi
}

# Assert the RFC 8016 dual-5-tuple handoff actually executed on the server. Each
# -M resume drives handle_turn_refresh into the transition path, and the client's
# first packet on the new 5-tuple promotes the allocation, emitting this marker.
# Its presence proves the handoff code ran end-to-end, not merely that a resume
# response was returned.
assert_handoff() {
    echo "Checking mobility handoff marker"
    local n
    n=$(grep -c "mobility handoff completed" "$TURNSERVER_LOG" 2>/dev/null)
    if [ "${n:-0}" -ge 1 ]; then
        echo "OK (mobility handoff x$n)"
    else
        echo "FAIL: no 'mobility handoff completed' marker in server log"
        echo "--- turnserver log (mobility lines) ---"
        grep -iE "mobil|handoff|refresh" "$TURNSERVER_LOG" 2>/dev/null | tail -20
        exit 1
    fi
}

# Legacy single-threaded uclient.
run_uclient "mobile turn client UDP"
run_uclient "mobile turn client TCP" -t

assert_handoff

if [ $IS_DARWIN -eq 1 ]; then
    # macOS loopback is unreliable for the mobility reopen beyond plain UDP;
    # keep the Darwin run to the deterministic subset.
    sleep 2
    exit 0
fi

# Threaded worker pools engaged, to exercise the resume path under the
# threaded recv/send loops as well.
run_uclient "mobile turn client UDP (threaded)" --listener-threads 1 --sender-threads 1
run_uclient "mobile turn client TCP (threaded)" -t --listener-threads 1 --sender-threads 1

sleep 2
