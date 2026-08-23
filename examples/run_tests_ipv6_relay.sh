#!/bin/bash

# System-level test for IPv6 relayed transport addresses (issue #1322).
#
# RFC 8656 Section 7.2 gives the server two choices for an Allocate carrying
# REQUESTED-ADDRESS-FAMILY=IPv6: allocate an IPv6 relayed transport address, or
# fail with 440. Section 3 defines that address as an address on the server
# itself, so the XOR-RELAYED-ADDRESS of the success response has to name the
# relay socket peers will send to. Section 7.3 puts one duty on the client: it
# refuses only a family it cannot handle.
#
# Two configurations sit right on those boundaries, and both surface to the user
# as the same "relay addr cannot be received (2)" line from clnet_allocate():
#
#   --external-ip   An external IP is a single address of a single family, so it
#                   can only stand in for a relay of its own family. An IPv6
#                   allocation on a server with an IPv4 external-ip must still
#                   be advertised under its own IPv6 address.
#
#   -A keep         The keep policy hands an IPv6 client an IPv6 relay even
#                   though the client sent no REQUESTED-ADDRESS-FAMILY.
#                   turnutils_uclient handles both families, so it has to take
#                   that relay rather than insist on the family it never asked
#                   for.
#
# Ports are deliberately off the defaults the other run_tests scripts use, so a
# stray server from another run cannot answer for this one.

if [ -d examples ]; then
    cd examples
fi

TURN_IP=::1
TURN_PORT=3488
PEER_PORT=3486

TURNSERVER_LOG="/tmp/run_tests_ipv6_relay.$$.turnserver.log"
UCLIENT_LOG="/tmp/run_tests_ipv6_relay.$$.uclient.log"
PEER_LOG="/tmp/run_tests_ipv6_relay.$$.peer.log"

turnserver_pid=""
peer_pid=""

cleanup() {
    stop_turnserver
    [ -n "$peer_pid" ] && kill "$peer_pid" 2>/dev/null
    [ -n "$peer_pid" ] && wait "$peer_pid" 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$UCLIENT_LOG" "$PEER_LOG"
}
trap cleanup EXIT

# Detect cmake vs autotools build layout.
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

stop_turnserver() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
        turnserver_pid=""
    fi
}

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

start_turnserver() {
    stop_turnserver
    : > "$TURNSERVER_LOG"
    $BINDIR/turnserver \
        --use-auth-secret --static-auth-secret=secret --realm=north.gov \
        --allow-loopback-peers \
        --no-cli --no-tls \
        --listening-ip=127.0.0.1 --listening-ip=$TURN_IP --listening-port=$TURN_PORT \
        --relay-ip=127.0.0.1 --relay-ip=$TURN_IP \
        --min-port=49400 --max-port=49500 \
        --log-file=stdout "$@" > "$TURNSERVER_LOG" 2>&1 &
    turnserver_pid="$!"
    wait_for_turnserver || return 1
    sleep 1
    # Without a bound IPv6 relay there is nothing for these cases to assert on.
    if grep -qE "Cannot bind .*$TURN_IP" "$TURNSERVER_LOG"; then
        return 2
    fi
    return 0
}

diagnose_failure() {
    echo "--- uclient output (last 30 lines) ---"
    tail -30 "$UCLIENT_LOG"
    echo "--- turnserver log (last 20 lines) ---"
    tail -20 "$TURNSERVER_LOG"
}

# A completed relayed round trip is the same marker run_tests.sh asserts on: it
# only appears once traffic has gone out through the relay and come back, which
# an unusable relay address cannot fake. One session relays 1000 bytes each way
# (-m 1, 5 messages of 200 B); client-to-client runs two sessions, so 2000.
check_relay_traffic() {
    local label="$1"
    local bytes="$2"
    if ! grep -q "start_mclient: tot_send_bytes ~ $bytes, tot_recv_bytes ~ $bytes" "$UCLIENT_LOG"; then
        echo "FAIL: $label did not complete a relayed round trip"
        diagnose_failure
        exit 1
    fi
    if grep -q "relay addr cannot be received" "$UCLIENT_LOG"; then
        echo "FAIL: $label rejected the relayed transport address"
        diagnose_failure
        exit 1
    fi
}

echo "Running peer client on [$TURN_IP]:$PEER_PORT"
$BINDIR/turnutils_peer -L $TURN_IP -p $PEER_PORT > "$PEER_LOG" 2>&1 &
peer_pid="$!"
sleep 1
if ! kill -0 "$peer_pid" 2>/dev/null; then
    echo "SKIP: turnutils_peer could not listen on $TURN_IP; no usable IPv6 loopback."
    cat "$PEER_LOG" 2>/dev/null
    peer_pid=""
    exit 0
fi

########################################################################
echo "Running turnserver with an IPv4 external-ip and an IPv6 relay"
start_turnserver --external-ip=127.0.0.1
case "$?" in
    1) exit 1 ;;
    2) echo "SKIP: turnserver could not bind $TURN_IP; no usable IPv6 loopback."; exit 0 ;;
esac

echo "Running turn client IPv6 relay (-x) against an IPv4 external-ip"
"$BINDIR/turnutils_uclient" -v -x -g -e $TURN_IP -r $PEER_PORT -p $TURN_PORT \
    -u user -W secret $TURN_IP > "$UCLIENT_LOG" 2>&1

# The advertised address must be the IPv6 relay, not the IPv4 external-ip: an
# IPv4 XOR-RELAYED-ADDRESS here is exactly the family substitution being pinned.
if ! grep -q "IPv6. Received relay addr" "$UCLIENT_LOG"; then
    echo "FAIL: IPv6 allocation was not advertised under an IPv6 relayed address"
    diagnose_failure
    exit 1
fi
check_relay_traffic "IPv6 relay with an IPv4 external-ip" 1000
echo OK

########################################################################
echo "Running turnserver with allocation-default-address-family=keep"
start_turnserver -A keep
case "$?" in
    1) exit 1 ;;
    2) echo "SKIP: turnserver could not bind $TURN_IP; no usable IPv6 loopback."; exit 0 ;;
esac

# No -x: the client sends no REQUESTED-ADDRESS-FAMILY and the server's keep
# policy answers an IPv6 client with an IPv6 relay anyway.
echo "Running turn client c2c with no requested address family"
"$BINDIR/turnutils_uclient" -v -y -g -p $TURN_PORT \
    -u user -W secret $TURN_IP > "$UCLIENT_LOG" 2>&1

check_relay_traffic "unrequested IPv6 relay" 2000
echo OK

exit 0
