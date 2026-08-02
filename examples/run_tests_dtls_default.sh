#!/bin/bash

# DTLS opt-in test.
#
# DTLS client listeners are not started unless --dtls is given, even when
# usable certificates are configured. This suite pins that default and the
# compatibility handling of the deprecated --no-dtls flag:
#
#   default:      no flag, certificates present -> no DTLS listener, a DTLS
#                 client cannot complete a session, and the log says how to
#                 turn it on.
#   --dtls:       DTLS listener up, DTLS client relays end to end.
#   --no-dtls:    still off, plus the deprecation warning.
#   --no-dtls=false: on (the old way of asking for DTLS keeps working), plus
#                 the deprecation warning pointing at --dtls.
#
# Ports are offset from the defaults so a concurrent run_tests.sh cannot be
# mistaken for this suite's server.

DTLS_LOG="/tmp/run_tests_dtls_default.$$.turnserver.log"
UCLIENT_LOG="/tmp/run_tests_dtls_default.$$.uclient.log"
PEER_LOG="/tmp/run_tests_dtls_default.$$.peer.log"
turnserver_pid=""
peer_pid=""

# turnutils_peer binds PEER_PORT and PEER_PORT+1 (the RTCP sibling), so leave a
# gap between the two.
SERVER_PORT=3489
PEER_PORT=3490

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    if [ -n "$peer_pid" ]; then
        kill "$peer_pid" 2>/dev/null
        wait "$peer_pid" 2>/dev/null
    fi
    rm -f "$DTLS_LOG" "$UCLIENT_LOG" "$PEER_LOG"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$DTLS_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            echo "--- turnserver log ---"
            cat "$DTLS_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$DTLS_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}

# Start a fresh turnserver with certificates configured plus whatever DTLS
# flag the case under test needs.
start_turnserver() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
        turnserver_pid=""
    fi
    : > "$DTLS_LOG"
    "$BINDIR/turnserver" --use-auth-secret --static-auth-secret=secret --realm=north.gov \
        --allow-loopback-peers --no-cli \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
        --listening-port="$SERVER_PORT" \
        --cert ../examples/ca/turn_server_cert.pem \
        --pkey ../examples/ca/turn_server_pkey.pem \
        --log-file=stdout \
        "$@" > "$DTLS_LOG" 2>&1 &
    turnserver_pid="$!"
    wait_for_turnserver
}

# Run a command under a deadline. The negative case below has no server to talk
# to, so the client would otherwise retry forever. coreutils `timeout` is not on
# a stock macOS runner, so do the watchdog in bash.
run_bounded() {
    local secs="$1"
    shift
    "$@" &
    local cmd_pid="$!"
    ( sleep "$secs"; kill -TERM "$cmd_pid" 2>/dev/null ) &
    local watchdog_pid="$!"
    wait "$cmd_pid" 2>/dev/null
    local rc=$?
    kill -TERM "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null
    return $rc
}

# A DTLS relay session (-S over UDP). Returns 0 only when the full 1000-byte
# round trip completed, which needs a DTLS listener on the other end.
#
# The deadline is an argument because the two directions need different ones: a
# successful session takes about 16s, so the "no listener" case has to wait
# meaningfully longer than that before concluding nothing happened, while the
# positive cases only need a ceiling high enough not to cut a slow runner off.
dtls_client_works() {
    local deadline="$1"
    run_bounded "$deadline" "$BINDIR/turnutils_uclient" -S \
        -e 127.0.0.1 -r "$PEER_PORT" -p "$SERVER_PORT" -X -g \
        -u user -W secret 127.0.0.1 > "$UCLIENT_LOG" 2>&1
    grep -q "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" "$UCLIENT_LOG"
}

fail() {
    echo "FAIL: $1"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$DTLS_LOG"
    echo "--- uclient log (last 20 lines) ---"
    tail -20 "$UCLIENT_LOG" 2>/dev/null || echo "(no uclient log)"
    exit 1
}

echo 'Running peer client'
"$BINDIR/turnutils_peer" -L 127.0.0.1 -p "$PEER_PORT" > "$PEER_LOG" 2>&1 &
peer_pid="$!"
sleep 1

echo "Running DTLS default (no flag)"
start_turnserver || exit 1
grep -q "DTLS cipher suite:" "$DTLS_LOG" && fail "DTLS context created without --dtls"
grep -q "DTLS listeners are not started" "$DTLS_LOG" || fail "missing the hint that --dtls turns DTLS on"
dtls_client_works 40 && fail "DTLS client completed a session with no --dtls"
echo OK

echo "Running DTLS enabled (--dtls)"
start_turnserver --dtls || exit 1
grep -q "DTLS cipher suite:" "$DTLS_LOG" || fail "no DTLS context with --dtls"
dtls_client_works 90 || fail "DTLS client could not relay with --dtls"
echo OK

echo "Running deprecated --no-dtls"
start_turnserver --no-dtls || exit 1
grep -q "no-dtls is deprecated" "$DTLS_LOG" || fail "--no-dtls did not warn"
grep -q "DTLS cipher suite:" "$DTLS_LOG" && fail "--no-dtls started DTLS"
echo OK

echo "Running deprecated --no-dtls=false"
start_turnserver --no-dtls=false || exit 1
grep -q "no-dtls=false is deprecated" "$DTLS_LOG" || fail "--no-dtls=false did not warn"
grep -q "DTLS cipher suite:" "$DTLS_LOG" || fail "--no-dtls=false did not start DTLS"
dtls_client_works 90 || fail "DTLS client could not relay with --no-dtls=false"
echo OK
