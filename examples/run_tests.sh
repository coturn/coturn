#!/bin/bash

# Per-run log paths. $$ in the suffix keeps two concurrent script
# invocations (rare, but happens with manual debug) from clobbering
# each other's diagnostics. cleanup() removes them on exit.
TURNSERVER_LOG="/tmp/run_tests.$$.turnserver.log"
PEER_LOG="/tmp/run_tests.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests.$$.uclient.log"
LOADGEN_LOG="/tmp/run_tests.$$.loadgen.log"

cleanup() {
    kill "$turnserver_pid" "$peer_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$PEER_LOG" "$UCLIENT_LOG" "$LOADGEN_LOG"
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
$BINDIR/turnserver --use-auth-secret --sock-buf-size=1048576 --static-auth-secret=secret --realm=north.gov --allow-loopback-peers $TURNSERVER_EXTRA_ARGS --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid="$!"

echo 'Running peer client'
$BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > "$PEER_LOG" 2>&1 &
peer_pid="$!"

sleep 2

# Dump the bits a maintainer needs to see when a protocol test fails: the
# uclient progress lines (shows where send/recv counters stalled), any
# uclient errors, and a tail of the turnserver + peer logs. The macOS
# run currently fails every protocol at tot_recv_msgs=0 because Darwin's
# loopback path drops the relay->peer echo; printing the diagnostics
# makes that immediately obvious instead of forcing a re-run with manual
# instrumentation. Caller passes the label so the banner identifies
# which protocol's run produced the dump.
diagnose_failure() {
    local label="$1"
    echo "=== Diagnostics for failed test: $label ==="
    echo "--- uclient: tot_send/tot_recv progress (last 6 lines) ---"
    grep "start_mclient: tot_send_msgs" "$UCLIENT_LOG" 2>/dev/null | tail -6
    echo "--- uclient: errors / warnings ---"
    grep -iE "error|warning|fail|broken|drop" "$UCLIENT_LOG" 2>/dev/null | tail -10
    echo "--- turnserver log (last 20 lines) ---"
    tail -20 "$TURNSERVER_LOG" 2>/dev/null
    echo "--- peer log (last 10 lines) ---"
    tail -10 "$PEER_LOG" 2>/dev/null
    echo "==="
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "Note: these tests are known to fail on macOS — every protocol stalls"
        echo "at tot_recv_msgs=0. The relay->peer loopback echo path on Darwin"
        echo "drops returned packets even though signaling / channel-bind succeed."
        echo "CI runs on Linux where the round trip works. Pre-existing on master."
    fi
}

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
    "$BINDIR/turnutils_uclient" "$@" -e 127.0.0.1 -X -g -u user -W secret 127.0.0.1 > "$UCLIENT_LOG" 2>&1
    if grep -q "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" "$UCLIENT_LOG"; then
        echo OK
    else
        echo FAIL
        diagnose_failure "$label"
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
