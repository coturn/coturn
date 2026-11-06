#!/bin/bash

# RFC 8489 password-algorithm suite (--password-algorithms).
#
# Starts the server with each algorithm list and drives turnutils_uclient with
# --password-alg negotiation, signing with MESSAGE-INTEGRITY-SHA256 (the client
# default) and with MESSAGE-INTEGRITY (--integrity-sha1); responses must carry
# MESSAGE-INTEGRITY-SHA256 either way. Also pins that a legacy MD5 client is refused by a
# sha256-only server, and that a 0x MD5-key user cannot use SHA-256.

TURNSERVER_LOG="/tmp/run_tests_password_algorithms.$$.turnserver.log"
PEER_LOG="/tmp/run_tests_password_algorithms.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests_password_algorithms.$$.uclient.log"
turnserver_pid=""
peer_pid=""

stop_server() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
        turnserver_pid=""
    fi
}

cleanup() {
    stop_server
    kill "$peer_pid" 2>/dev/null
    wait "$peer_pid" 2>/dev/null
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

$BINDIR/turnutils_peer -L 127.0.0.1 -L ::1 -L 0.0.0.0 > "$PEER_LOG" 2>&1 &
peer_pid="$!"

start_server() {
    local label="$1"
    shift
    stop_server
    echo "Running turnserver ($label)"
    $BINDIR/turnserver --relay-threads=1 --realm=north.gov --allow-loopback-peers --log-file=stdout "$@" > "$TURNSERVER_LOG" 2>&1 &
    turnserver_pid="$!"
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$TURNSERVER_LOG" 2>/dev/null; then
            sleep 1
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver exited before init completed"
            cat "$TURNSERVER_LOG"
            exit 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:'"
    tail -30 "$TURNSERVER_LOG"
    exit 1
}

diagnose_failure() {
    echo "=== Diagnostics for failed test: $1 ==="
    grep -iE "401|400|438|nonce|error|warning|fail|cannot|integrity" "$UCLIENT_LOG" 2>/dev/null | tail -10
    echo "--- turnserver log (last 30 lines) ---"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null
    echo "==="
}

# $1 label, $2 "ok" or "fail", then the uclient arguments (credentials included).
run_uclient() {
    local label="$1" expect="$2"
    shift 2
    echo "Running $label"
    timeout 60 "$BINDIR/turnutils_uclient" "$@" -e 127.0.0.1 -X -g 127.0.0.1 > "$UCLIENT_LOG" 2>&1
    if grep -q "start_mclient: tot_send_bytes ~ 1000, tot_recv_bytes ~ 1000" "$UCLIENT_LOG"; then
        got=ok
    else
        got=fail
    fi
    if [ "$got" = "$expect" ]; then
        echo OK
    else
        echo "FAIL: expected $expect, got $got"
        diagnose_failure "$label"
        exit 1
    fi
}

REST="-u user -W secret"
STATIC="-u alice -w wonderland"

# 1. SHA-256 only, REST API credentials (the server derives the password).
start_server "--password-algorithms=sha256, REST" --use-auth-secret --static-auth-secret=secret --password-algorithms=sha256
run_uclient "sha256 + MESSAGE-INTEGRITY UDP (--integrity-sha1)" ok $REST --password-alg=sha256 --integrity-sha1
run_uclient "sha256 + MESSAGE-INTEGRITY TCP (--integrity-sha1)" ok $REST --password-alg=sha256 --integrity-sha1 -t
run_uclient "sha256 + MESSAGE-INTEGRITY-SHA256 UDP" ok $REST --password-alg=sha256
run_uclient "sha256 + MESSAGE-INTEGRITY-SHA256 TCP" ok $REST --password-alg=sha256 -t
run_uclient "legacy MD5 client against sha256-only server" fail $REST
run_uclient "md5 client against sha256-only server" fail $REST --password-alg=md5

run_probe() {
    if command -v python3 >/dev/null 2>&1; then
        echo "Running listener challenge probe ($1)"
        if python3 scripts/password_algorithms_probe.py 127.0.0.1 3478 "$2"; then
            echo OK
        else
            echo "FAIL: listener challenge probe"
            diagnose_failure "probe"
            exit 1
        fi
    else
        echo "SKIP: python3 not available (listener challenge probe)"
    fi
}
run_probe sha256 00020000

echo "Running uclient --integrity-sha1 without --password-alg"
if $BINDIR/turnutils_uclient --integrity-sha1 -u user -W secret 127.0.0.1 > "$UCLIENT_LOG" 2>&1; then
    echo "FAIL: accepted"
    exit 1
fi
echo OK

if grep -qi "md5" "$TURNSERVER_LOG"; then
    echo "NOTE: server log mentions md5 (informational only)"
fi

# 2. SHA-256 preferred, MD5 still accepted; static users.
start_server "--password-algorithms=sha256,md5, static user" --lt-cred-mech --user=alice:wonderland --password-algorithms=sha256,md5
run_uclient "sha256,md5: sha256 UDP" ok $STATIC --password-alg=sha256
run_uclient "sha256,md5: sha256 + MESSAGE-INTEGRITY-SHA256 UDP" ok $STATIC --password-alg=sha256
run_uclient "sha256,md5: md5 + MESSAGE-INTEGRITY UDP (--integrity-sha1)" ok $STATIC --password-alg=md5 --integrity-sha1
run_uclient "sha256,md5: md5 TCP" ok $STATIC --password-alg=md5 -t
run_uclient "sha256,md5: legacy client" ok $STATIC
run_probe sha256,md5 0002000000010000
run_probe "implied MD5 with MI-SHA256" implied

# 2b. Without --password-algorithms nothing of RFC 8489 shows: no PASSWORD-ALGORITHMS, no cookie, 420 for 0x001C.
start_server "no --password-algorithms (legacy)" --lt-cred-mech --user=alice:wonderland
run_probe legacy legacy

# 3. md5 listed alone still turns RFC 8489 mode on.
start_server "--password-algorithms=md5" --lt-cred-mech --user=alice:wonderland --password-algorithms=md5
run_uclient "md5-only: md5 negotiated" ok $STATIC --password-alg=md5
run_uclient "md5-only: legacy client" ok $STATIC
run_uclient "md5-only: sha256 not offered" fail $STATIC --password-alg=sha256

# 4. A precomputed 0x MD5 key (MD5("bob:north.gov:builder")) cannot do SHA-256; a 64-digit key is a SHA-256 key.
BOB_MD5=$(printf 'bob:north.gov:builder' | openssl md5 -r | cut -d' ' -f1)
BOB_SHA256=$(printf 'bob:north.gov:builder' | openssl dgst -sha256 -r | cut -d' ' -f1)
start_server "static 0x keys, sha256,md5" --lt-cred-mech --user=bob:0x$BOB_MD5 --user=carol:0x$BOB_SHA256 --password-algorithms=sha256,md5
run_uclient "MD5-keyed user cannot use sha256" fail -u bob -w builder --password-alg=sha256
run_uclient "MD5-keyed user can use md5" ok -u bob -w builder --password-alg=md5
CAROL_SHA256=$(printf 'carol:north.gov:builder' | openssl dgst -sha256 -r | cut -d' ' -f1)
start_server "static 0x SHA-256 key, sha256,md5" --lt-cred-mech --user=carol:0x$CAROL_SHA256 --password-algorithms=sha256,md5
run_uclient "SHA-256-keyed user can use sha256" ok -u carol -w builder --password-alg=sha256
run_uclient "SHA-256-keyed user cannot use md5" fail -u carol -w builder --password-alg=md5
start_server "sha256 only, MD5-keyed user" --lt-cred-mech --user=bob:0x$BOB_MD5 --password-algorithms=sha256
if grep -q "no key for any configured password algorithm" "$TURNSERVER_LOG"; then
    echo "OK (startup warning for the unusable user)"
else
    echo "FAIL: no startup warning for a user without a usable key"
    diagnose_failure "0x md5 warning"
    exit 1
fi
run_uclient "MD5-keyed user refused by sha256-only server" fail -u bob -w builder --password-alg=sha256

# 6. turnadmin --password-algorithms=sha256 stores a 64-digit SHA-256 key; a sha256-only server
# authenticates that user from the database.
if "$BINDIR/turnserver" -h 2>&1 | grep -q -- "--db"; then
    DBDIR="$(mktemp -d "${TMPDIR:-/tmp}/run_tests_password_algorithms.XXXXXX")"
    trap 'rm -rf "$DBDIR"; cleanup' EXIT
    keyline=$($BINDIR/turnadmin -k -u dave -r north.gov -p builder --password-algorithms=sha256)
    if [ ${#keyline} -eq 66 ]; then
        echo "OK (turnadmin -k printed a 64-digit key)"
    else
        echo "FAIL: turnadmin --password-algorithms=sha256 -k printed '$keyline'"
        exit 1
    fi
    $BINDIR/turnadmin -a -b "$DBDIR/turndb" -u dave -r north.gov -p builder --password-algorithms=sha256 > /dev/null 2>&1
    start_server "sha256 only, user from turnadmin DB" --lt-cred-mech --db="$DBDIR/turndb" --password-algorithms=sha256
    run_uclient "turnadmin sha256 user can use sha256" ok -u dave -w builder --password-alg=sha256
    run_uclient "turnadmin sha256 user cannot use md5 (legacy client)" fail -u dave -w builder
    run_uclient "turnadmin sha256 user cannot use md5" fail -u dave -w builder --password-alg=md5
else
    echo "SKIP: turnserver built without SQLite support (turnadmin test)"
fi

if [ $IS_DARWIN -eq 1 ]; then
    exit 0
fi

# 5. Transports with a session per connection, and the threaded client.
start_server "--password-algorithms=sha256,md5, TLS/DTLS" --lt-cred-mech --user=alice:wonderland --password-algorithms=sha256,md5 --dtls --cert ../examples/ca/turn_server_cert.pem --pkey ../examples/ca/turn_server_pkey.pem
run_uclient "sha256 TLS" ok $STATIC --password-alg=sha256 -t -S
run_uclient "sha256 DTLS" ok $STATIC --password-alg=sha256 -S
run_uclient "sha256 UDP (threaded)" ok $STATIC --password-alg=sha256 --listener-threads 1 --sender-threads 1

sleep 1
