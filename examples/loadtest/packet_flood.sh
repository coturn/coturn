#!/bin/bash

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"

BINDIR="${REPO_ROOT}/build/bin"
if [ ! -x "${BINDIR}/turnserver" ]; then
  BINDIR="${REPO_ROOT}/bin"
fi

cleanup() {
  kill "${uclient_pid:-}" "${peer_pid:-}" "${turnserver_pid:-}" 2>/dev/null || true
  wait "${uclient_pid:-}" "${peer_pid:-}" "${turnserver_pid:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"${BINDIR}/turnserver" \
  --use-auth-secret \
  --static-auth-secret=secret \
  --realm=north.gov \
  --allow-loopback-peers \
  --listening-ip=127.0.0.1 \
  --relay-ip=127.0.0.1 \
  > /dev/null 2>&1 &
turnserver_pid=$!

"${BINDIR}/turnutils_peer" -L 127.0.0.1 -p 3480 > /dev/null 2>&1 &
peer_pid=$!

sleep 2

"${BINDIR}/turnutils_uclient" \
  -Y packet \
  -m 1 \
  -z 0 \
  -l 120 \
  -e 127.0.0.1 \
  -r 3480 \
  -X \
  -g \
  -u user \
  -W secret \
  "$@" \
  127.0.0.1 &
uclient_pid=$!

wait "${uclient_pid}"
