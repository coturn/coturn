#!/bin/bash

# Pins that the per-request and auth-failure log lines carry the client
# address ("client <ip>:<port>"), so tools like fail2ban can ban on them.

LOG="/tmp/run_tests_log_client_ip.$$.turnserver.log"
SERVER_PORT=3499
turnserver_pid=""

cleanup() {
    [ -n "$turnserver_pid" ] && kill "$turnserver_pid" 2>/dev/null && wait "$turnserver_pid" 2>/dev/null
    :
}
trap cleanup EXIT

BINDIR="../bin"
[ -f "$BINDIR/turnserver" ] || BINDIR="../build/bin"

"$BINDIR/turnserver" --use-auth-secret --static-auth-secret=secret --realm=north.gov \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --listening-port="$SERVER_PORT" \
    --no-tls -v --log-file=stdout > "$LOG" 2>&1 &
turnserver_pid="$!"
for _ in $(seq 1 40); do
    grep -q "Total auth threads:" "$LOG" && break
    sleep 0.5
done

# Unauthenticated request: the server answers 401.
"$BINDIR/turnutils_stunclient" -p "$SERVER_PORT" 127.0.0.1 > /dev/null 2>&1
# Wrong credentials: the server logs the auth failure.
"$BINDIR/turnutils_uclient" -p "$SERVER_PORT" -e 127.0.0.1 -u baduser -W wrongsecret -n 1 -m 1 127.0.0.1 > /dev/null 2>&1 &
uc="$!"
sleep 3
kill "$uc" 2>/dev/null
wait "$uc" 2>/dev/null

if grep -E "incoming packet .*client 127\.0\.0\.1:[0-9]+\)" "$LOG" > /dev/null; then
    echo OK
else
    echo "FAIL: no log line with the client address"
    tail -30 "$LOG"
    exit 1
fi
