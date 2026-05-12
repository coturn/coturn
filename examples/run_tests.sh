#!/bin/bash

cleanup() {
    kill "$turnserver_pid" "$peer_pid" 2>/dev/null
    rm -f /tmp/run_tests_loadgen.$$.log
}
trap cleanup EXIT

# Detect cmake build and adjust path
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

# Server-side fast paths that we ship as Linux-only: enable them in the
# default test run so every CI cycle exercises recvmmsg drain + GSO send.
# Stays off on non-Linux because the kernel APIs aren't available.
TURNSERVER_EXTRA_ARGS=""
if [ "$(uname -s)" = "Linux" ]; then
    TURNSERVER_EXTRA_ARGS="--udp-recvmmsg --udp-gso"
    echo "Using TURNSERVER_EXTRA_ARGS=\"$TURNSERVER_EXTRA_ARGS\""
fi

echo 'Running turnserver'
$BINDIR/turnserver --use-auth-secret --sock-buf-size=1048576 --static-auth-secret=secret --realm=north.gov --allow-loopback-peers $TURNSERVER_EXTRA_ARGS --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > /dev/null &
turnserver_pid="$!"

echo 'Running peer client'
$BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &
peer_pid="$!"

sleep 2

# Each protocol test runs turnutils_uclient with the supplied flags and
# greps for the canonical end-of-run line. Factoring the loop body into a
# function lets us run each protocol once with the legacy single-threaded
# defaults and a second time with the listener+sender thread pools
# explicitly engaged, so a regression in either path fails CI rather than
# only being caught at -m >= auto-bump thresholds. The grep target stays
# stable across both variants because the workload (-m 1, -n default=5,
# 200 B msg) totals 1000 bytes each way regardless of threading.
run_uclient() {
    local label="$1"
    shift
    echo "Running $label"
    "$BINDIR/turnutils_uclient" "$@" -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 \
        | grep "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" > /dev/null
    if [ $? -eq 0 ]; then
        echo OK
    else
        echo FAIL
        exit 1
    fi
}

# Legacy single-threaded uclient (no -K, no --sender-threads).
run_uclient "turn client TCP"   -t
run_uclient "turn client TLS"   -t -S
run_uclient "turn client UDP"
run_uclient "turn client DTLS"  -S

# Same four protocols with both worker pools at minimum non-zero size so
# we exercise the threaded recv (#1911) and threaded send (#1913) paths.
# -m 1 keeps the workload small; the pools still spin up, register the
# session via pick_listener_base / pick_sender_id, and drive the
# per-thread timer + recv loop end-to-end.
run_uclient "turn client TCP (threaded)"  -t      --listener-threads 1 --sender-threads 1
run_uclient "turn client TLS (threaded)"  -t -S   --listener-threads 1 --sender-threads 1
run_uclient "turn client UDP (threaded)"          --listener-threads 1 --sender-threads 1
run_uclient "turn client DTLS (threaded)" -S      --listener-threads 1 --sender-threads 1

# Linux-only load-gen smoke. Confirms -Y packet mode emits the recv_pps
# metric introduced in #1913 alongside send_pps, and that both are
# non-zero (so we'd catch a regression where the listener pool stops
# accumulating into recv_count_snapshot). 4s of -m 4 traffic is enough
# to clear several progress prints without blowing CI runtime; --sender-
# threads 2 matches the auto rule for -m >= 4. -c suppresses EVEN-PORT
# requests so the test is compatible with --multiplex-peer (future).
if [ "$(uname -s)" = "Linux" ]; then
    echo "Running turn client UDP load-gen smoke (-Y packet, threaded)"
    LOADGEN_LOG="/tmp/run_tests_loadgen.$$.log"
    # timeout exits 124 when it has to send SIGTERM; that's success here
    # because we just want a fixed-duration run. Capture log for inspection.
    timeout -s INT 6s "$BINDIR/turnutils_uclient" \
        -Y packet -m 4 -l 100 -c -e 127.0.0.1 -g \
        --listener-threads 1 --sender-threads 2 \
        -u user -W secret 127.0.0.1 > "$LOADGEN_LOG" 2>&1
    # Accept exit 124 (timeout killed) or 130 (SIGINT clean exit) as success.
    rc=$?
    if [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 130 ]; then
        echo "FAIL: uclient exited with $rc"
        cat "$LOADGEN_LOG"
        exit 1
    fi
    if grep -qE "send_pps=[1-9][0-9]*\.[0-9]+, recv_pps=[1-9][0-9]*\.[0-9]+" "$LOADGEN_LOG"; then
        echo OK
    else
        echo "FAIL: no non-zero send_pps/recv_pps line in load-gen output"
        tail -20 "$LOADGEN_LOG"
        exit 1
    fi
fi

sleep 2
