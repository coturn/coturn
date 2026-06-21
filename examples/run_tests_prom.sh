#!/bin/bash


# Detect cmake build and adjust path
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

# turnserver startup is near-instant on Linux but takes ~5s on macOS, where the
# thread-barrier rendezvous in netengine.c degrades to a fixed sleep(5) because
# libpthread lacks pthread_barrier_*. Rather than sleeping a fixed interval, the
# helpers below poll for readiness (the metrics endpoint, or the server log) up
# to this timeout.
POLL_TIMEOUT=30

TURNSERVER_LOG="$(mktemp "${TMPDIR:-/tmp}/run_tests_prom.XXXXXX")"
turnserver_pid=""

# Pin the TURN listeners to loopback and skip the TLS/DTLS listeners: this test
# only exercises the Prometheus exporter (served independently by libmicrohttpd),
# and leaving address auto-discovery on makes startup slow and flaky on hosts
# with tentative/temporary IPv6 addresses (the DTLS/UDP bind retries with
# sleep(1) until Duplicate Address Detection completes).
COMMON_ARGS="-L 127.0.0.1 -E 127.0.0.1 --no-tls --no-dtls --log-file=stdout --simple-log"

# stop_turnserver: stop the running turnserver and wait for it to exit so its
# listening ports are released before the next instance binds them. SIGKILL is
# used deliberately: graceful SIGTERM shutdown can take up to ~5s (the auth
# housekeeping thread sleeps in 5s cycles), and this test does not care about a
# clean drain.
function stop_turnserver() {
  if [ -n "$turnserver_pid" ]; then
    kill -KILL "$turnserver_pid" 2>/dev/null
    wait "$turnserver_pid" 2>/dev/null
    turnserver_pid=""
  fi
}

function cleanup() {
  stop_turnserver
  rm -f "$TURNSERVER_LOG"
}
trap cleanup EXIT

# start_turnserver <args...>: launch turnserver in the background with its output
# captured to TURNSERVER_LOG so the negative tests can poll for its decision.
function start_turnserver() {
  : > "$TURNSERVER_LOG"
  # shellcheck disable=SC2086
  "$BINDIR/turnserver" $COMMON_ARGS "$@" > "$TURNSERVER_LOG" 2>&1 &
  turnserver_pid="$!"
}

# wait_for_prom_decision: block until turnserver has logged that it settled its
# Prometheus startup decision (exporter started, or explicitly not started).
# Used by the no-response tests, which cannot poll the (absent) endpoint.
function wait_for_prom_decision() {
  local deadline=$((SECONDS + POLL_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -Eq "prometheus collector started successfully|prometheus collector disabled, not started|could not read certificate|without TLS support|no certificate/key is configured" "$TURNSERVER_LOG"; then
      return 0
    fi
    sleep 0.2
  done
  echo "FAIL (turnserver did not settle its prometheus decision within ${POLL_TIMEOUT}s)"
  cat "$TURNSERVER_LOG"
  exit 1
}

function assert_prom_no_response() {
  wget --quiet --output-document=/dev/null --tries=1 "$1"
  status="$?"
  if [ "$status" -eq 0 ]; then
    echo FAIL
    exit 1
  else
    echo OK
  fi
}

function assert_prom_response() {
  # Poll until the endpoint returns something that looks like the expected body,
  # or fail after POLL_TIMEOUT.
  local deadline=$((SECONDS + POLL_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if wget --quiet --output-document=- --tries=1 "$1" 2>/dev/null |
        grep -q 'TYPE\|HELP\|counter\|gauge'; then
      echo OK
      return 0
    fi
    sleep 0.2
  done
  echo FAIL
  cat "$TURNSERVER_LOG"
  exit 1
}

function assert_prom_response_tls() {
  # Same as assert_prom_response but over HTTPS with a self-signed cert, so
  # certificate verification is disabled. A plaintext HTTP request to the same
  # URL must NOT succeed (the endpoint is TLS-only).
  local deadline=$((SECONDS + POLL_TIMEOUT))
  local ok=0
  while [ "$SECONDS" -lt "$deadline" ]; do
    if wget --no-check-certificate --quiet --output-document=- --tries=1 "$1" 2>/dev/null |
        grep -q 'TYPE\|HELP\|counter\|gauge'; then
      ok=1
      break
    fi
    sleep 0.2
  done
  if [ "$ok" -ne 1 ]; then
    echo FAIL
    cat "$TURNSERVER_LOG"
    exit 1
  fi
  # The HTTPS endpoint must reject a plaintext HTTP request on the same port.
  http_url="${1/https:/http:}"
  wget --quiet --output-document=/dev/null --tries=1 "$http_url"
  if [ "$?" -eq 0 ]; then
    echo "FAIL (plaintext HTTP accepted on TLS endpoint)"
    exit 1
  fi
  echo OK
}

echo "Running without prometheus"
start_turnserver
wait_for_prom_decision
assert_prom_no_response "http://localhost:9641/metrics"
stop_turnserver

echo "Running turnserver with prometheus, using defaults"
start_turnserver --prometheus
assert_prom_response "http://localhost:9641/metrics"
stop_turnserver

echo "Running turnserver with prometheus, using custom address and port"
start_turnserver --prometheus --prometheus-address="127.0.0.1" --prometheus-port="8080"
assert_prom_response "http://127.0.0.1:8080/metrics"
stop_turnserver

echo "Running turnserver with prometheus, using custom path"
start_turnserver --prometheus --prometheus-path="/coturn/metrics"
assert_prom_response "http://localhost:9641/coturn/metrics"
stop_turnserver

# --prometheus-tls implies --prometheus, so the exporter is enabled without a
# separate --prometheus flag below.
echo "Running turnserver with prometheus over TLS, explicit --prometheus-cert/--prometheus-key"
start_turnserver --prometheus-tls \
  --prometheus-cert=etc/turn_server_cert.pem --prometheus-key=etc/turn_server_pkey.pem
assert_prom_response_tls "https://localhost:9641/metrics"
stop_turnserver

echo "Running turnserver with prometheus over TLS, cert/key inherited from server --cert/--pkey"
start_turnserver --prometheus-tls \
  --cert=etc/turn_server_cert.pem --pkey=etc/turn_server_pkey.pem
assert_prom_response_tls "https://localhost:9641/metrics"
stop_turnserver

echo "Running turnserver with prometheus TLS but an unreadable cert: endpoint must not start"
start_turnserver --prometheus-tls \
  --prometheus-cert=/nonexistent/cert.pem --prometheus-key=/nonexistent/key.pem
wait_for_prom_decision
assert_prom_no_response "https://localhost:9641/metrics"
stop_turnserver
