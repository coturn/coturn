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

# Server-side fast paths that we ship as Linux-only: enable them in the
# default test run so every CI cycle exercises recvmmsg drain + sendmmsg
# batching + GSO send. --udp-gso is a no-op without --udp-sendmmsg
# (udp_sendmmsg_batch_begin early-returns when sendmmsg is off), so the
# three flags travel together. Stays off on non-Linux because the kernel
# APIs aren't available.
TURNSERVER_EXTRA_ARGS=""
if [ "$(uname -s)" = "Linux" ]; then
    TURNSERVER_EXTRA_ARGS="--udp-recvmmsg --udp-sendmmsg --udp-gso"
    echo "Using TURNSERVER_EXTRA_ARGS=\"$TURNSERVER_EXTRA_ARGS\""
fi

echo 'Running turnserver'
if [ $IS_DARWIN -eq 1 ]; then
    $BINDIR/turnserver --use-auth-secret --sock-buf-size=1048576 --static-auth-secret=secret --realm=north.gov --allow-loopback-peers --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > /dev/null &
else
    # --log-file=stdout forces turnserver's per-line log into our redirected
    # stdout so $TURNSERVER_LOG actually gets populated. Without it,
    # turnserver writes to its platform-default location (syslog or
    # /var/log/turn_*.log) and our redirect captures an empty file; that
    # breaks wait_for_turnserver, which polls the log for a known
    # late-startup line, and it leaves the FAIL-path diagnostics useless.
    $BINDIR/turnserver --use-auth-secret --sock-buf-size=1048576 --static-auth-secret=secret --realm=north.gov --allow-loopback-peers --log-file=stdout --simple-log $TURNSERVER_EXTRA_ARGS --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem > "$TURNSERVER_LOG" 2>&1 &
fi
turnserver_pid="$!"

echo 'Running peer client'
if [ $IS_DARWIN -eq 1 ]; then
    $BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &
else
    $BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > "$PEER_LOG" 2>&1 &
fi
peer_pid="$!"

# Wait for OUR turnserver instance to finish coming up before running any
# client tests. The previous static `sleep 2` was tight for an uninstrumented
# binary and broke under sanitizer builds (ASan/TSan): instrumented
# turnserver routinely takes 5-10s before it has bound 3478, so uclient
# raced in and hit "Connection refused".
#
# We can't just poll /dev/tcp/127.0.0.1/3478: when this script runs
# back-to-back with another that didn't fully clean up, the dying
# previous turnserver may still answer the connect long enough to give
# a false positive, and uclient ends up talking to a half-dead server.
# Instead, poll OUR log file (uniquely named via $$) for a known late
# startup line. That's by-construction immune to other instances. "Total
# auth threads:" is emitted after relay setup and socket-per-thread UDP
# listener setup, so it is a better client-start gate than "Total relay
# threads:".
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
    sleep 2
else
    wait_for_turnserver || exit 1
    # No-barrier builds can log readiness before all worker event loops have
    # had a scheduling turn. Keep the old startup cushion after the active
    # per-process readiness check.
    sleep 2
fi

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

if [ $IS_DARWIN -eq 1 ]; then
    sleep 2
    exit 0
fi

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
