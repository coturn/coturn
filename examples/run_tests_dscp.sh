#!/bin/bash

# System-level test for DSCP/TOS preservation across the relay (issue #385).
#
# A TURN relay must not strip the IP DSCP/TOS marking off the packets it
# forwards: coturn reads the marking from each inbound datagram (IP_RECVTOS /
# IPV6_RECVTCLASS) and re-applies it on the outbound leg. This test proves both
# directions end to end by observing the marking on the wire.
#
# Topology (all on 127.0.0.1):
#   turnutils_uclient  --(tos 0x22)-->  turnserver  --(relay)-->  turnutils_peer
# turnutils_uclient marks its own client socket TOS 0x22 / TTL 47
# (startuclient.c). turnutils_peer echoes each datagram back with the same
# marking it arrived with (its default behavior), which lets us check the
# peer->client leg too.
#
# tcpdump reads the IP TOS byte off the loopback interface, so the four legs
# are:
#   1) client -> listener (:3478)   tos 0x22   (client's own marking)
#   2) relay  -> peer     (:3480)   tos 0x22   <- coturn reflects (forward)
#   3) peer   -> relay              tos 0x22   (peer -O reflects the mark back)
#   4) listener -> client (:3478 >) tos 0x22   <- coturn reflects (return)
# Legs 2 and 4 are the assertions.
#
# Reliable loopback TOS capture and IP_RECVTOS both need Linux; on any other
# platform, or without tcpdump / capture privileges, this SKIPs (exit 0)
# rather than failing.

if [ -d examples ]; then
    cd examples
fi

PRIMARY_IP=127.0.0.1
STUN_PORT=3478
PEER_PORT=3480
MIN_PORT=50000
MAX_PORT=50050
LOOPBACK_IF=lo
CLIENT_TOS="0x22" # value startuclient.c sets on the uclient socket

TURNSERVER_LOG="/tmp/run_tests_dscp.$$.turnserver.log"
PEER_LOG="/tmp/run_tests_dscp.$$.peer.log"
UCLIENT_LOG="/tmp/run_tests_dscp.$$.uclient.log"
TCPDUMP_LOG="/tmp/run_tests_dscp.$$.tcpdump.log"

turnserver_pid=""
peer_pid=""
tcpdump_pid=""

cleanup() {
    [ -n "$tcpdump_pid" ] && kill "$tcpdump_pid" 2>/dev/null
    [ -n "$turnserver_pid" ] && kill "$turnserver_pid" 2>/dev/null
    [ -n "$peer_pid" ] && kill "$peer_pid" 2>/dev/null
    wait 2>/dev/null
    rm -f "$TURNSERVER_LOG" "$PEER_LOG" "$UCLIENT_LOG" "$TCPDUMP_LOG"
}
trap cleanup EXIT

# Reliable loopback TOS capture (and IP_RECVTOS on the peer) is a Linux thing.
if [ "$(uname -s)" != "Linux" ]; then
    echo "SKIP: DSCP test needs Linux for loopback TOS capture and IP_RECVTOS. Skipping."
    exit 0
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "SKIP: tcpdump not found; cannot observe the on-the-wire DSCP marking. Skipping."
    exit 0
fi

# Detect cmake vs autotools build layout (mirrors run_tests_rfc5780.sh).
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

# Confirm we can actually capture on loopback (needs root / CAP_NET_RAW). A
# permission failure exits tcpdump immediately with an error on stderr; a
# working capture stays alive waiting for the -c packet, so liveness after a
# short sleep means we have the privilege.
tcpdump -i "$LOOPBACK_IF" -c 1 -w /dev/null 'ip' >/dev/null 2>"$TCPDUMP_LOG" &
probe_pid=$!
sleep 0.5
if kill -0 "$probe_pid" 2>/dev/null; then
    kill "$probe_pid" 2>/dev/null
    wait "$probe_pid" 2>/dev/null
elif grep -qiE "permission|not permitted|no such device|can't|couldn't" "$TCPDUMP_LOG"; then
    echo "SKIP: tcpdump cannot capture on $LOOPBACK_IF (needs root / CAP_NET_RAW). Skipping."
    exit 0
fi
rm -f "$TCPDUMP_LOG"

# --- start the echo peer (reflects DSCP/TOS by default) ---
echo "Running turnutils_peer (reflects DSCP/TOS) on $PRIMARY_IP:$PEER_PORT"
"$BINDIR/turnutils_peer" -L "$PRIMARY_IP" -p "$PEER_PORT" > "$PEER_LOG" 2>&1 &
peer_pid=$!
sleep 0.5
if ! kill -0 "$peer_pid" 2>/dev/null; then
    echo "FAIL: turnutils_peer did not start"
    cat "$PEER_LOG"
    exit 1
fi

# --- start turnserver: no-auth loopback relay, narrow relay-port range ---
echo "Running turnserver (no-auth) on $PRIMARY_IP:$STUN_PORT, relay ports $MIN_PORT-$MAX_PORT"
"$BINDIR/turnserver" \
    --listening-ip=$PRIMARY_IP --relay-ip=$PRIMARY_IP --allow-loopback-peers \
    --no-tls --no-dtls --no-auth --cli=false \
    --listening-port=$STUN_PORT --min-port=$MIN_PORT --max-port=$MAX_PORT \
    --log-file=stdout > "$TURNSERVER_LOG" 2>&1 &
turnserver_pid=$!

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

# --- capture on loopback, self-terminating (300 pkts or 20s) ---
timeout 25 tcpdump -i "$LOOPBACK_IF" -n -v -c 300 \
    "udp and (port $STUN_PORT or port $PEER_PORT or portrange $MIN_PORT-$MAX_PORT)" \
    > "$TCPDUMP_LOG" 2>/dev/null &
tcpdump_pid=$!
sleep 1

# --- drive traffic: uclient marks TOS 0x22 on its own socket ---
echo "Running turnutils_uclient (marks TOS $CLIENT_TOS) relaying to the peer"
timeout 20 "$BINDIR/turnutils_uclient" -n 25 -m 1 -l 100 -e "$PRIMARY_IP" -X -g -z 40 \
    "$PRIMARY_IP" > "$UCLIENT_LOG" 2>&1
uclient_rc=$?

sleep 2
kill "$tcpdump_pid" 2>/dev/null
wait "$tcpdump_pid" 2>/dev/null

if [ "$uclient_rc" -ne 0 ]; then
    echo "FAIL: turnutils_uclient exited $uclient_rc"
    tail -20 "$UCLIENT_LOG"
    exit 1
fi

# tcpdump prints a two-line record: "... IP (tos 0xNN,... )" then a
# "    src.port > dst.port: ..." line. Pair each address line with the tos on
# the preceding header line.
tos_to() { # $1 = grep pattern matching the address line's destination
    grep -B1 "$1" "$TCPDUMP_LOG" | grep -oE "tos 0x[0-9a-f]+" | sort | uniq -c
}
tos_from_listener() { # 3478 -> client, header tos on the preceding line
    grep -B1 "$PRIMARY_IP.$STUN_PORT > " "$TCPDUMP_LOG" | grep -oE "tos 0x[0-9a-f]+" | sort | uniq -c
}

echo
echo "--- observed TOS per leg ---"
echo "leg 2  relay  -> peer     (> .$PEER_PORT):"; tos_to "> $PRIMARY_IP.$PEER_PORT:"
echo "leg 4  listener-> client  (.$STUN_PORT >):"; tos_from_listener

relay_to_peer_has_mark=$(grep -B1 "> $PRIMARY_IP.$PEER_PORT:" "$TCPDUMP_LOG" | grep -c "tos $CLIENT_TOS")
listener_to_client_has_mark=$(grep -B1 "$PRIMARY_IP.$STUN_PORT > " "$TCPDUMP_LOG" | grep -c "tos $CLIENT_TOS")

echo
rc=0
if [ "$relay_to_peer_has_mark" -gt 0 ]; then
    echo "OK: forward leg preserved DSCP — relay->peer carried tos $CLIENT_TOS ($relay_to_peer_has_mark pkts)"
else
    echo "FAIL: forward leg lost DSCP — no tos $CLIENT_TOS on the relay->peer leg"
    rc=1
fi
if [ "$listener_to_client_has_mark" -gt 0 ]; then
    echo "OK: return leg preserved DSCP — listener->client carried tos $CLIENT_TOS ($listener_to_client_has_mark pkts)"
else
    echo "FAIL: return leg lost DSCP — no tos $CLIENT_TOS on the listener->client leg"
    rc=1
fi

if [ "$rc" -ne 0 ]; then
    echo "--- tcpdump (first 40 lines) ---"
    head -40 "$TCPDUMP_LOG"
fi
exit $rc
