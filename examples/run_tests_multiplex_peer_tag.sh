#!/bin/bash
#
# End-to-end test for multiplex-peer tagging (--multiplex-peer-tag on the
# turnserver, -M on turnutils_peer).
#
# Plain --multiplex-peer routes inbound packets by peer IP:port and therefore
# REJECTS a second session on the same relay thread that reuses the same peer
# IP:port (error 400, "Peer address already used ..."). With tagging, each
# session carries a per-session mux-id trailer and inbound packets are routed
# by that id, so many sessions can share one peer IP:port.
#
# The test pins the server to 2 relay threads (--cpus=2) and drives 4 concurrent
# sessions, ALL to one shared peer IP:port. By pigeonhole at least two sessions
# land on the same relay thread (same mp_table), so:
#
#   * tag OFF (plain --multiplex-peer): the server MUST reject the colliding
#     same-peer registration ("Peer address already used ...").
#   * tag ON  (--multiplex-peer-tag):   NO collision is rejected and every byte
#     sent to the shared peer is relayed back to the right session (send==recv).
#
# The contrast is the proof: the identical workload that the server rejects
# without tagging succeeds with it. multiplex-peer is Linux-only; elsewhere
# this test SKIPs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: multiplex-peer (and thus --multiplex-peer-tag) is Linux-only."
  exit 0
fi

BINDIR="../bin"
[ -f "$BINDIR/turnserver" ] || BINDIR="../build/bin"
if [ ! -x "$BINDIR/turnserver" ]; then
  echo "Cannot find turnserver in ../bin or ../build/bin"
  exit 1
fi

MULTIPLEX_PEER_PORT="${MULTIPLEX_PEER_PORT:-35100}"
# The peer MUST listen outside the multiplex-peer relay range
# [base .. base + 2*threads - 1] (35100-35103 for two threads) so the peer and
# the relay sockets do not fight over a port.
PEER_PORT="${PEER_PORT:-35090}"
RELAY_THREADS=2
SESSIONS=4
MSGS=100

REJECT_MSG="Peer address already used by another multiplex-peer allocation"

turnserver_pid=""
peer_pid=""
turnserver_log=""
peer_log=""

kill_quiet() {
  if [ -n "$1" ]; then
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
  fi
  return 0
}
cleanup() {
  kill_quiet "$peer_pid"; peer_pid=""
  kill_quiet "$turnserver_pid"; turnserver_pid=""
  [ -n "$turnserver_log" ] && rm -f "$turnserver_log"
  [ -n "$peer_log" ] && rm -f "$peer_log"
  return 0
}
trap cleanup EXIT

# run_phase <label> <tag|notag>; sets PHASE_SEND/PHASE_RECV/PHASE_REJECTED/
# PHASE_DISTINCT/PHASE_RC and PHASE_OUTPUT.
run_phase() {
  local label="$1" mode="$2"
  turnserver_log="$(mktemp "${TMPDIR:-/tmp}/turnserver-mpx-tag.XXXXXX.log")"
  peer_log="$(mktemp "${TMPDIR:-/tmp}/peer-mpx-tag.XXXXXX.log")"

  "$BINDIR/turnutils_peer" -M -p "$PEER_PORT" -L 127.0.0.1 -v > "$peer_log" 2>&1 &
  peer_pid="$!"
  sleep 1

  local extra=()
  [ "$mode" = "tag" ] && extra+=("--multiplex-peer-tag")

  "$BINDIR/turnserver" \
    --use-auth-secret --static-auth-secret=secret --realm=north.gov \
    --sock-buf-size=1048576 \
    --cpus="$RELAY_THREADS" \
    -L 127.0.0.1 -E 127.0.0.1 --allow-loopback-peers \
    --multiplex-peer --multiplex-peer-port="$MULTIPLEX_PEER_PORT" "${extra[@]}" \
    --udp-recvmmsg -v --simple-log --log-file "$turnserver_log" > /dev/null &
  turnserver_pid="$!"
  sleep 4

  PHASE_RC=0
  PHASE_OUTPUT=$("$BINDIR/turnutils_uclient" \
    -m "$SESSIONS" -n "$MSGS" -c --no-even-port -e 127.0.0.1 -r "$PEER_PORT" -X -g \
    -u user -W secret 127.0.0.1 2>&1) || PHASE_RC=$?
  sleep 1

  local line
  line=$(printf '%s\n' "$PHASE_OUTPUT" | grep -oE "tot_send_bytes ~ [0-9]+, tot_recv_bytes ~ [0-9]+" | tail -n1 || true)
  PHASE_SEND=$(printf '%s\n' "$line" | grep -oE "tot_send_bytes ~ [0-9]+" | grep -oE "[0-9]+$" || true)
  PHASE_RECV=$(printf '%s\n' "$line" | grep -oE "tot_recv_bytes ~ [0-9]+" | grep -oE "[0-9]+$" || true)
  PHASE_SEND="${PHASE_SEND:-0}"; PHASE_RECV="${PHASE_RECV:-0}"
  PHASE_REJECTED=$(grep -c "$REJECT_MSG" "$turnserver_log" 2>/dev/null || true)
  PHASE_REJECTED="${PHASE_REJECTED:-0}"
  PHASE_DISTINCT=$(grep -oE "distinct=[0-9]+" "$peer_log" | grep -oE "[0-9]+$" | sort -n | tail -n1 || true)
  PHASE_DISTINCT="${PHASE_DISTINCT:-0}"

  echo "[$label] send=$PHASE_SEND recv=$PHASE_RECV collisions_rejected=$PHASE_REJECTED (uclient rc=$PHASE_RC)"

  kill_quiet "$peer_pid"; peer_pid=""
  kill_quiet "$turnserver_pid"; turnserver_pid=""
}

fail=0

echo "Negative control: $SESSIONS sessions to one peer IP:port over $RELAY_THREADS threads, WITHOUT tagging"
run_phase "tag OFF" notag
if [ "$PHASE_REJECTED" -lt 1 ]; then
  echo "FAIL: without tagging, the colliding same-peer registration was NOT rejected"
  tail -n 20 "$turnserver_log" 2>/dev/null || true
  fail=1
fi
rm -f "$turnserver_log" "$peer_log"; turnserver_log=""; peer_log=""

echo "Positive: same $SESSIONS sessions to the SAME peer IP:port WITH --multiplex-peer-tag"
run_phase "tag ON" tag
if [ "$PHASE_SEND" -eq 0 ] || [ "$PHASE_SEND" != "$PHASE_RECV" ]; then
  echo "FAIL: with tagging, relay round-trip mismatch (send=$PHASE_SEND recv=$PHASE_RECV)"
  printf '%s\n' "$PHASE_OUTPUT" | tail -n 8
  fail=1
fi
if [ "$PHASE_REJECTED" -ne 0 ]; then
  echo "FAIL: with tagging, a same-peer allocation was still rejected ($PHASE_REJECTED times)"
  fail=1
fi
rm -f "$turnserver_log" "$peer_log"; turnserver_log=""; peer_log=""

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "OK: tagging let $SESSIONS sessions share one peer IP:port that plain --multiplex-peer rejects."
