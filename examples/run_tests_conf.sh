#!/bin/bash

TURNSERVER_LOG="/tmp/run_tests_conf.$$.turnserver.log"
PEER_LOG="/tmp/run_tests_conf.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests_conf.$$.uclient.log"
LOADGEN_LOG="/tmp/run_tests_conf.$$.loadgen.log"

cleanup() {
    kill "$turnserver_pid" "$peer_pid" 2>/dev/null
    wait "$turnserver_pid" "$peer_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$PEER_LOG" "$UCLIENT_LOG" "$LOADGEN_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

IS_DARWIN=0
if [ "$(uname -s)" = "Darwin" ]; then
    IS_DARWIN=1
fi

echo "Creating $BINDIR/turnserver.conf file"
echo "use-auth-secret" > $BINDIR/turnserver.conf
echo "static-auth-secret=secret" >> $BINDIR/turnserver.conf
echo "realm=north.gov" >> $BINDIR/turnserver.conf
echo "allow-loopback-peers" >> $BINDIR/turnserver.conf
if [ $IS_DARWIN -eq 0 ]; then
    echo "sock-buf-size=1048576" >> $BINDIR/turnserver.conf
fi
echo "cert=../examples/ca/turn_server_cert.pem" >> $BINDIR/turnserver.conf
echo "pkey=../examples/ca/turn_server_pkey.pem" >> $BINDIR/turnserver.conf
if [ $IS_DARWIN -eq 0 ]; then
    # Force log output to stdout (which we redirect to $TURNSERVER_LOG below).
    # Without this, turnserver writes to its platform-default location
    # (syslog or /var/log/turn_*.log) and our log file stays empty, which
    # breaks wait_for_turnserver's "Total relay threads:" probe and leaves
    # the FAIL diagnostics useless. simple-log keeps the format compact.
    echo "log-file=stdout" >> $BINDIR/turnserver.conf
    echo "simple-log" >> $BINDIR/turnserver.conf
    # Server-side fast paths: enable on Linux so the conf-driven test cycle
    # also exercises recvmmsg drain + sendmmsg batching + UDP-GSO send.
    # These keys map 1:1 to the --udp-recvmmsg / --udp-sendmmsg / --udp-gso
    # CLI flags (see mainrelay.c long_options). udp-gso is a no-op without
    # udp-sendmmsg, so the three keys travel together.
    if [ "$(uname -s)" = "Linux" ]; then
        echo "udp-recvmmsg" >> $BINDIR/turnserver.conf
        echo "udp-sendmmsg" >> $BINDIR/turnserver.conf
        echo "udp-gso" >> $BINDIR/turnserver.conf
    fi
fi

echo 'Running turnserver'
if [ $IS_DARWIN -eq 1 ]; then
    $BINDIR/turnserver -c $BINDIR/turnserver.conf > /dev/null &
else
    $BINDIR/turnserver -c $BINDIR/turnserver.conf > "$TURNSERVER_LOG" 2>&1 &
fi
turnserver_pid="$!"
echo 'Running peer client'
if [ $IS_DARWIN -eq 1 ]; then
    $BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &
else
    $BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > "$PEER_LOG" 2>&1 &
fi
peer_pid="$!"

# Wait for OUR turnserver instance to finish init -- see run_tests.sh
# for the rationale. We poll the per-invocation log (uniquely named via
# $$) for "Total auth threads:" so a stale turnserver from a prior
# script invocation can't false-positive us.
wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$TURNSERVER_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            echo "--- turnserver log ---"
            cat "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        if ! kill -0 "$peer_pid" 2>/dev/null; then
            echo "FATAL: turnutils_peer (pid $peer_pid) exited before tests started"
            echo "--- peer log ---"
            cat "$PEER_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}
if [ $IS_DARWIN -eq 1 ]; then
    sleep 5
else
    wait_for_turnserver || exit 1
    # No-barrier builds can log readiness before all worker event loops have
    # had a scheduling turn. Keep the old startup cushion after the active
    # per-process readiness check.
    sleep 2
fi

# See run_tests.sh for rationale — same shape, mirrored here so the
# conf-driven test produces the same actionable failure output.
diagnose_failure() {
    local label="$1"
    echo "=== Diagnostics for failed test: $label ==="
    echo "--- uclient: tot_send/tot_recv progress (last 6 lines) ---"
    grep "start_mclient: tot_send_msgs" "$UCLIENT_LOG" 2>/dev/null | tail -6
    echo "--- uclient: errors / warnings ---"
    grep -iE "error|warning|fail|broken|drop" "$UCLIENT_LOG" 2>/dev/null | tail -10
    echo "--- turnserver: socket / relay / allocation errors (last 40 lines) ---"
    grep -iE "508|capacity|socket|bind|available ports|relay|allocation" "$TURNSERVER_LOG" 2>/dev/null | tail -40
    echo "--- turnserver log (last 20 lines) ---"
    if [ -s "$TURNSERVER_LOG" ]; then
        tail -20 "$TURNSERVER_LOG"
    elif [ -e "$TURNSERVER_LOG" ]; then
        echo "(turnserver log exists but is empty — likely never produced output)"
    else
        echo "(turnserver log missing — redirect path: $TURNSERVER_LOG)"
    fi
    echo "--- peer log (last 10 lines) ---"
    if [ -s "$PEER_LOG" ]; then
        tail -10 "$PEER_LOG"
    elif [ -e "$PEER_LOG" ]; then
        echo "(peer log exists but is empty)"
    else
        echo "(peer log missing — redirect path: $PEER_LOG)"
    fi
    echo "==="
}

# Same factoring as run_tests.sh: function-per-test, run each protocol
# with the legacy single-threaded uclient and again with the listener +
# sender thread pools engaged. Total bytes stay at 1000 either way at
# -m 1 -n 5.
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

# Legacy single-threaded uclient.
run_uclient "turn client TCP"   -t
run_uclient "turn client TLS"   -t -S
run_uclient "turn client UDP"
run_uclient "turn client DTLS"  -S

if [ $IS_DARWIN -eq 1 ]; then
    sleep 2
    exit 0
fi

# Listener + sender thread pools engaged at minimum non-zero size.
run_uclient "turn client TCP (threaded)"  -t      --listener-threads 1 --sender-threads 1
run_uclient "turn client TLS (threaded)"  -t -S   --listener-threads 1 --sender-threads 1
run_uclient "turn client UDP (threaded)"          --listener-threads 1 --sender-threads 1
run_uclient "turn client DTLS (threaded)" -S      --listener-threads 1 --sender-threads 1

# Linux-only load-gen smoke (see comment in run_tests.sh for rationale).
if [ "$(uname -s)" = "Linux" ]; then
    echo "Running turn client UDP load-gen smoke (-Y packet, threaded)"
    timeout -s INT 6s "$BINDIR/turnutils_uclient" \
        -Y packet -m 4 -l 100 -c -e 127.0.0.1 -g \
        --listener-threads 1 --sender-threads 2 \
        -u user -W secret 127.0.0.1 > "$LOADGEN_LOG" 2>&1
    rc=$?
    if [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 130 ]; then
        echo "FAIL: uclient exited with $rc"
        echo "--- load-gen log ---"
        cat "$LOADGEN_LOG"
        echo "--- turnserver log (last 20 lines) ---"
        tail -20 "$TURNSERVER_LOG"
        exit 1
    fi
    if grep -qE "send_pps=[1-9][0-9]*\.[0-9]+, recv_pps=[1-9][0-9]*\.[0-9]+" "$LOADGEN_LOG"; then
        echo OK
    else
        echo "FAIL: no non-zero send_pps/recv_pps line in load-gen output"
        echo "--- load-gen log (last 20 lines) ---"
        tail -20 "$LOADGEN_LOG"
        echo "--- turnserver log (last 20 lines) ---"
        tail -20 "$TURNSERVER_LOG"
        exit 1
    fi
fi

sleep 2
