#!/bin/bash

# 401 rate-limit feature test.
#
# Exercises the --401-ratelimit / --401-req-limit / --401-window flags
# end-to-end:
#
#   positive: with --401-req-limit=1, drive one bounded
#             turnutils_uclient session. The client retries the 401
#             challenge several times within the same session, easily
#             crossing the threshold of 1, so the server must emit
#             exactly one "401 rate-limit exceeded" log line (the log
#             is self-rate-limited to one message per (bucket, window)
#             on purpose).
#
#   negative: same harness but --401-req-limit=100000. Same client
#             traffic produces nowhere near 100000 401s, so the
#             "exceeded" log line must NOT appear.
#
# Split out of run_tests.sh so the rate-limit configuration is fully
# isolated from the protocol-test server fixture in that script — a
# regression in either suite must not be masked by the other's flags.

# Per-run log path; $$ keeps two concurrent invocations from clobbering
# each other.
RATELIMIT_LOG="/tmp/run_tests_ratelimit_401.$$.log"
turnserver_pid=""

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -f "$RATELIMIT_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

# macOS loopback drops UDP relay traffic intermittently and the
# turnutils_uclient retry pattern there is different enough that the
# log-line accounting becomes flaky. Linux CI is the canonical target
# for this feature — skip on Darwin rather than emit false failures.
if [ "$(uname -s)" = "Darwin" ]; then
    echo "Skipping 401 rate-limit test on macOS"
    exit 0
fi

# Block until turnserver has printed the line that follows relay-port
# init and per-thread UDP listener setup. Cheaper and more reliable
# than `sleep N`; mirrors the pattern in run_tests.sh.
wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$RATELIMIT_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            echo "--- turnserver log ---"
            cat "$RATELIMIT_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$RATELIMIT_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}

# Start a fresh turnserver with --401-ratelimit + caller-supplied
# threshold/window flags. The previous server (if any) is killed
# first; the log file is truncated so each case sees a clean slate.
run_ratelimit_server() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    : > "$RATELIMIT_LOG"
    "$BINDIR/turnserver" --use-auth-secret --static-auth-secret=secret --realm=north.gov \
        --allow-loopback-peers --no-cli --no-tls --no-dtls \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
        --listening-port=3479 \
        --log-file=stdout --simple-log \
        "$@" > "$RATELIMIT_LOG" 2>&1 &
    turnserver_pid="$!"
    wait_for_turnserver
}

# turnutils_uclient with bad credentials. `timeout` caps the run so a
# hung session can't stall CI; we don't care about its exit status —
# all the assertions are against the server log.
drive_bad_client() {
    timeout 15s "$BINDIR/turnutils_uclient" \
        -e 127.0.0.1 -X -g -u baduser -W wrongsecret -p 3479 127.0.0.1 \
        > /dev/null 2>&1 || true
    sleep 1
}

echo "Running 401 rate-limit (positive)"
run_ratelimit_server --401-ratelimit --401-req-limit=1 --401-window=60 || exit 1
drive_bad_client

if grep -q '401 rate-limit exceeded from' "$RATELIMIT_LOG"; then
    echo OK
else
    echo "FAIL: rate-limit log line not emitted under attack"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$RATELIMIT_LOG"
    exit 1
fi

echo "Running 401 rate-limit (negative: high threshold)"
run_ratelimit_server --401-ratelimit --401-req-limit=100000 --401-window=60 || exit 1
drive_bad_client

if grep -q '401 rate-limit exceeded from' "$RATELIMIT_LOG"; then
    echo "FAIL: rate-limit triggered below threshold (--401-req-limit=100000)"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$RATELIMIT_LOG"
    exit 1
else
    echo OK
fi
