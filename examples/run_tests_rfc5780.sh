#!/bin/bash

# System-level test for RFC 5780 (STUN NAT Behavior Discovery).
#
# RFC 5780 is a server-side feature gated behind --rfc5780 that requires the
# listener to be bound to *two* distinct IP addresses: the server advertises
# the second address (and the alternate port) in an OTHER-ADDRESS attribute,
# and honours CHANGE-REQUEST / RESPONSE-PORT so a client can probe the NAT's
# mapping and filtering behaviour. get_alt_addr() in netengine.c returns -1
# unless turn_params.listener.addrs_number >= 2, so a single-IP server never
# exercises the feature.
#
# turnutils_stunclient sets its rfc5780 flag as soon as it sees an
# OTHER-ADDRESS in the first binding response, then (with -f) sends the two
# follow-up CHANGE-REQUEST / RESPONSE-PORT probes. We assert that the client
# reports at least one "RFC 5780 response" and prints the advertised
# OTHER-ADDRESS, which end-to-end proves the server codec + handle_turn_binding
# path is still wired up.
#
# NOTE ON ADDRESSES: the two listener IPs must both be locally bindable. On
# Linux the whole 127.0.0.0/8 loopback block is bound, so 127.0.0.1 +
# 127.0.0.2 work out of the box. macOS only has 127.0.0.1 by default; this
# script adds a 127.0.0.2 loopback alias if it can do so non-interactively and
# otherwise SKIPs (exit 0) rather than failing.

if [ -d examples ]; then
    cd examples
fi

PRIMARY_IP=127.0.0.1
ALT_IP=127.0.0.2
STUN_PORT=3478

TURNSERVER_LOG="/tmp/run_tests_rfc5780.$$.turnserver.log"
STUNCLIENT_LOG="/tmp/run_tests_rfc5780.$$.stunclient.log"

turnserver_pid=""
added_alias=0

cleanup() {
    [ -n "$turnserver_pid" ] && kill "$turnserver_pid" 2>/dev/null
    [ -n "$turnserver_pid" ] && wait "$turnserver_pid" 2>/dev/null
    # Only tear down the loopback alias if this script created it.
    if [ "$added_alias" -eq 1 ]; then
        sudo -n ifconfig lo0 -alias "$ALT_IP" 2>/dev/null
    fi
    rm -f "$TURNSERVER_LOG" "$STUNCLIENT_LOG"
}
trap cleanup EXIT

# Detect cmake vs autotools build layout.
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

# Make sure the second loopback IP is bindable, setting up an alias on macOS
# if possible. If we can't get a usable second address, SKIP rather than FAIL:
# a machine without a spare loopback IP can't exercise this feature at all.
ensure_alt_ip() {
    if [ "$(uname -s)" = "Linux" ]; then
        return 0 # 127.0.0.2 is always bindable on Linux loopback.
    fi
    # macOS / BSD: reuse an existing alias if present.
    if ifconfig lo0 2>/dev/null | grep -q "$ALT_IP"; then
        return 0
    fi
    if sudo -n ifconfig lo0 alias "$ALT_IP" up 2>/dev/null; then
        added_alias=1
        return 0
    fi
    return 1
}

if ! ensure_alt_ip; then
    echo "SKIP: RFC 5780 test needs a second loopback IP ($ALT_IP) that could not"
    echo "SKIP: be configured (need e.g. 'sudo ifconfig lo0 alias $ALT_IP up'). Skipping."
    exit 0
fi

echo "Running turnserver with RFC 5780 enabled on $PRIMARY_IP + $ALT_IP"
$BINDIR/turnserver \
    --use-auth-secret --static-auth-secret=secret --realm=north.gov \
    --allow-loopback-peers --rfc5780 \
    --no-cli --no-tls --no-dtls \
    --listening-ip=$PRIMARY_IP --listening-ip=$ALT_IP \
    --min-port=49152 --max-port=49300 \
    --log-file=stdout --simple-log > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid="$!"

# Poll our uniquely-named log for a known late-startup line instead of racing
# on a fixed sleep (mirrors run_tests.sh).
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
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' within 20s"
    tail -30 "$TURNSERVER_LOG" 2>/dev/null
    return 1
}
wait_for_turnserver || exit 1
sleep 1

# Guard: the alt IP must actually be bound. If the second listener failed to
# bind (e.g. missing loopback alias), the server can't advertise OTHER-ADDRESS
# and the feature test would be meaningless — surface that as a FAIL.
if grep -qE "Cannot bind .*$ALT_IP" "$TURNSERVER_LOG"; then
    echo "FAIL: turnserver could not bind the second listener IP $ALT_IP"
    grep -iE "bind|$ALT_IP" "$TURNSERVER_LOG" | tail -10
    exit 1
fi

echo "Running turnutils_stunclient (-f forces the RFC 5780 probe sequence)"
"$BINDIR/turnutils_stunclient" -f -p "$STUN_PORT" "$PRIMARY_IP" > "$STUNCLIENT_LOG" 2>&1

# The client prints "RFC 5780 response N" for every binding response that
# carried an OTHER-ADDRESS, and "Other addr: <ip>:<port>" with the advertised
# alternate. Both must appear for the feature to be considered working.
if grep -q "RFC 5780 response" "$STUNCLIENT_LOG" && grep -q "Other addr:" "$STUNCLIENT_LOG"; then
    echo "OK: RFC 5780 NAT behavior discovery is supported"
    echo "--- stunclient RFC 5780 output ---"
    grep -E "RFC 5780 response|Response origin:|Other addr:" "$STUNCLIENT_LOG"
else
    echo "FAIL: turnutils_stunclient did not observe an RFC 5780 (OTHER-ADDRESS) response"
    echo "--- stunclient output ---"
    cat "$STUNCLIENT_LOG"
    echo "--- turnserver log (last 20 lines) ---"
    tail -20 "$TURNSERVER_LOG"
    exit 1
fi

exit 0
