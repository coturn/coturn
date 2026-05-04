#!/bin/bash

set -eu

# Allocation flood does not start turnutils_peer.
# turnutils_uclient now generates a unique synthetic peer ip:port for
# each new allocation cycle, so only turnserver and uclient are needed.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"

BINDIR="${REPO_ROOT}/build/bin"
if [ ! -x "${BINDIR}/turnserver" ]; then
  BINDIR="${REPO_ROOT}/bin"
fi

cleanup() {
  kill "${uclient_pid:-}" "${turnserver_pid:-}" 2>/dev/null || true
  wait "${uclient_pid:-}" "${turnserver_pid:-}" 2>/dev/null || true
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

sleep 2

"${BINDIR}/turnutils_uclient" \
  -Y alloc \
  -m 50 \
  -L 127.0.0.1 \
  -u user \
  -W secret \
  "$@" \
  127.0.0.1 &
uclient_pid=$!

wait "${uclient_pid}"
