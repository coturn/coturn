#!/bin/bash

# OAuth (RFC 7635) MESSAGE-INTEGRITY key-length test.
#
# turnutils_uclient -J mints a token carrying a 20-byte mac_key for one of the
# test keys in turndb/testsqldbsetup.sql. RFC 7635 keys MESSAGE-INTEGRITY with
# the whole mac_key; --oauth-legacy-mac-key (server and client) keeps only its
# first 16 bytes. Matching modes must relay end to end, mismatched modes must
# fail authentication:
#
#   server default, client default  -> relays
#   server legacy,  client legacy   -> relays
#   server default, client legacy   -> rejected
#   server legacy,  client default  -> rejected
#
# Needs a turnserver built with SQLite and either the sqlite3 CLI or python3 to
# load the test keys; SKIPs otherwise. Ports are offset from the defaults so a
# concurrent run_tests.sh cannot be mistaken for this suite's server.

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/run_tests_oauth.XXXXXX")"
OAUTH_DB="$WORKDIR/turndb"
TURN_LOG="$WORKDIR/turnserver.log"
UCLIENT_LOG="$WORKDIR/uclient.log"
PEER_LOG="$WORKDIR/peer.log"
turnserver_pid=""
peer_pid=""

# turnutils_peer binds PEER_PORT and PEER_PORT+1 (the RTCP sibling).
SERVER_PORT=3491
PEER_PORT=3492

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    if [ -n "$peer_pid" ]; then
        kill "$peer_pid" 2>/dev/null
        wait "$peer_pid" 2>/dev/null
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

SCHEMA="../turndb/schema.sql"
KEYS="../turndb/testsqldbsetup.sql"

load_oauth_keys() {
    if command -v sqlite3 >/dev/null 2>&1; then
        { cat "$SCHEMA"; grep "oauth_key" "$KEYS"; } | sqlite3 "$OAUTH_DB"
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$OAUTH_DB" "$SCHEMA" "$KEYS" <<'EOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.executescript(open(sys.argv[2]).read())
db.executescript("".join(l for l in open(sys.argv[3]) if "oauth_key" in l))
db.commit()
EOF
    else
        return 1
    fi
}

if ! "$BINDIR/turnserver" -h 2>&1 | grep -q -- "--db"; then
    echo "SKIP: turnserver built without SQLite support"
    exit 0
fi
if ! load_oauth_keys; then
    echo "SKIP: neither sqlite3 nor python3 is available to load the OAuth test keys"
    exit 0
fi

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$TURN_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            echo "--- turnserver log ---"
            cat "$TURN_LOG" 2>/dev/null || echo "(log file missing)"
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$TURN_LOG" 2>/dev/null || echo "(log file missing)"
    return 1
}

start_turnserver() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
        turnserver_pid=""
    fi
    : > "$TURN_LOG"
    "$BINDIR/turnserver" --lt-cred-mech --oauth --db="$OAUTH_DB" --realm=north.gov \
        --allow-loopback-peers \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
        --listening-port="$SERVER_PORT" \
        --no-tls --no-cli \
        --log-file=stdout \
        "$@" > "$TURN_LOG" 2>&1 &
    turnserver_pid="$!"
    wait_for_turnserver
}

# Run a command under a deadline: a client whose integrity is rejected retries
# until it gives up. coreutils `timeout` is not on a stock macOS runner.
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

# Returns 0 only when an OAuth-authenticated UDP relay session completed its
# full round trip.
oauth_client_works() {
    run_bounded 30 "$BINDIR/turnutils_uclient" -J "$@" \
        -e 127.0.0.1 -r "$PEER_PORT" -p "$SERVER_PORT" -n 10 -m 1 -X -g \
        -u north 127.0.0.1 > "$UCLIENT_LOG" 2>&1
    grep -Eq "start_mclient: tot_send_bytes ~ ([1-9][0-9]*), tot_recv_bytes ~ \1$" "$UCLIENT_LOG"
}

fail() {
    echo "FAIL: $1"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$TURN_LOG"
    echo "--- uclient log (last 20 lines) ---"
    tail -20 "$UCLIENT_LOG" 2>/dev/null || echo "(no uclient log)"
    exit 1
}

echo 'Running peer client'
"$BINDIR/turnutils_peer" -L 127.0.0.1 -p "$PEER_PORT" > "$PEER_LOG" 2>&1 &
peer_pid="$!"
sleep 1

echo "Running OAuth with the whole mac_key (default)"
start_turnserver || exit 1
grep -q "oauth-legacy-mac-key" "$TURN_LOG" && fail "legacy mac_key warning logged without the flag"
oauth_client_works || fail "RFC 7635 client could not relay against the default server"
oauth_client_works --oauth-legacy-mac-key && fail "legacy client authenticated against the default server"
echo OK

echo "Running OAuth with --oauth-legacy-mac-key"
start_turnserver --oauth-legacy-mac-key || exit 1
grep -q "WARNING: --oauth-legacy-mac-key" "$TURN_LOG" || fail "no warning that the legacy mac_key mode is on"
oauth_client_works --oauth-legacy-mac-key || fail "legacy client could not relay against the legacy server"
oauth_client_works && fail "RFC 7635 client authenticated against the legacy server"
echo OK
