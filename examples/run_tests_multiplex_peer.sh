#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

turnserver_pid=""
peer_pid=""
turnserver_log=""

cleanup() {
  if [ -n "$peer_pid" ]; then
    kill "$peer_pid" 2>/dev/null || true
    wait "$peer_pid" 2>/dev/null || true
  fi
  if [ -n "$turnserver_pid" ]; then
    kill "$turnserver_pid" 2>/dev/null || true
    wait "$turnserver_pid" 2>/dev/null || true
  fi
  if [ -n "$turnserver_log" ]; then
    rm -f "$turnserver_log"
  fi
}
trap cleanup EXIT

# Detect cmake build and adjust path.
BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
  BINDIR="../build/bin"
fi

if [ ! -x "$BINDIR/turnserver" ]; then
  echo "Cannot find turnserver in ../bin or ../build/bin"
  exit 1
fi

MULTIPLEX_PEER_PORT="${MULTIPLEX_PEER_PORT:-35000}"
TURNSERVER_EXTRA_ARGS=("--multiplex-peer" "--multiplex-peer-port=$MULTIPLEX_PEER_PORT")
if [ "$(uname -s)" = "Linux" ]; then
  TURNSERVER_EXTRA_ARGS+=("--udp-recvmmsg")
  echo 'Using TURNSERVER_EXTRA_ARGS="--udp-recvmmsg"'
fi

turnserver_log="$(mktemp "${TMPDIR:-/tmp}/turnserver-multiplex-peer.XXXXXX.log")"

print_turnserver_log_tail() {
  echo "Last turnserver log lines:"
  tail -n 40 "$turnserver_log" 2>/dev/null || true
}

run_client() {
  local name="$1"
  local peer_port="$2"
  local expected_bytes="$3"
  local output
  local rc=0
  local attempt
  local max_attempts=8
  shift 3

  echo "Running $name"
  "$BINDIR/turnutils_peer" -p "$peer_port" -L 127.0.0.1 -L ::1 -L 0.0.0.0 > /dev/null &
  peer_pid="$!"
  sleep 1

  for attempt in $(seq 1 "$max_attempts"); do
    rc=0
    output=$("$BINDIR/turnutils_uclient" "$@" 2>&1) || rc=$?
    if printf '%s\n' "$output" |
      grep -q "start_mclient: tot_send_bytes ~ $expected_bytes, tot_recv_bytes ~ $expected_bytes"; then
      kill "$peer_pid" 2>/dev/null || true
      wait "$peer_pid" 2>/dev/null || true
      peer_pid=""
      echo OK
      return 0
    fi

    if printf '%s\n' "$output" | grep -q "error 400" &&
      grep -q "EVEN-PORT is not supported with multiplex-peer" "$turnserver_log" &&
      [ "$attempt" -lt "$max_attempts" ]; then
      echo "Retrying $name after randomized EVEN-PORT request"
      continue
    fi

    break
  done

  kill "$peer_pid" 2>/dev/null || true
  wait "$peer_pid" 2>/dev/null || true
  peer_pid=""

  echo FAIL
  printf '%s\n' "$output"
  print_turnserver_log_tail
  if [ "$rc" -ne 0 ]; then
    return "$rc"
  fi
  return 1
}

echo "Running turnserver in multiplex-peer mode on base port $MULTIPLEX_PEER_PORT"
"$BINDIR/turnserver" \
  --use-auth-secret \
  --sock-buf-size=1048576 \
  --static-auth-secret=secret \
  --realm=north.gov \
  -L 127.0.0.1 \
  -E 127.0.0.1 \
  --allow-loopback-peers \
  "${TURNSERVER_EXTRA_ARGS[@]}" \
  -v \
  --cert ca/turn_server_cert.pem \
  --pkey ca/turn_server_pkey.pem \
  --simple-log \
  --log-file "$turnserver_log" \
  > /dev/null &
turnserver_pid="$!"

sleep 5

# Multiplex-peer is incompatible with EVEN-PORT, so these tests disable RTCP reservation with -c.
run_client "turn client UDP" 3480 500 -c -e 127.0.0.1 -r 3480 -X -g -u user -W secret 127.0.0.1
run_client "turn client TCP" 3482 500 -c -t -e 127.0.0.1 -r 3482 -X -g -u user -W secret 127.0.0.1
run_client "turn client TLS" 3484 500 -c -t -S -e 127.0.0.1 -r 3484 -X -g -u user -W secret 127.0.0.1
run_client "turn client DTLS" 3490 500 -c -S -e 127.0.0.1 -r 3490 -X -g -u user -W secret 127.0.0.1

sleep 2
