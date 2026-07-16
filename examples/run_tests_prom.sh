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

function assert_prom_metric_nonzero() {
  metric="$1"
  body="$2"
  if echo "$body" | grep -Eq "^${metric}(_total)? [1-9][0-9]*(\\.[0-9]+)?$"; then
    echo OK
  else
    echo "FAIL: metric ${metric} was not non-zero"
    exit 1
  fi
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

# COMMON_ARGS already supplies -L/-E 127.0.0.1 and --no-tls --no-dtls.
echo "Running turnserver with prometheus 401 mitigation counters"
start_turnserver --prometheus --prometheus-address="127.0.0.1" --prometheus-port="8081" \
  --use-auth-secret --static-auth-secret=secret --realm=north.gov \
  --allow-loopback-peers --no-cli --listening-port=3479 \
  --unauthorized-ratelimit --unauthorized-ratelimit-rps=1
assert_prom_response "http://127.0.0.1:8081/metrics"
# The two 401-mitigation metric families have deliberately different exposure
# timing, and a single bad-cred client run satisfies only one at a time:
#   * turn_unauthenticated_401_* are per-thread accumulators flushed into the
#     registry on the engine's 1 Hz timer, so they only appear ~1s AFTER traffic.
#   * turn_ratelimit_occupied_buckets is computed live at scrape time and decays
#     to 0 within RATELIMIT_WINDOW_SECS (1s) of the most recent 401.
# turnutils_uclient emits its whole 401 burst in well under a second and then
# idles, so right after a burst the gauge is live but the counters have not
# flushed, and a second later the counters appear but the gauge has decayed.
# Keep bad-cred traffic flowing continuously (a short-lived client restarted in a
# loop) so a rate-limit window stays open across at least one counter-flush tick,
# then poll until a single scrape shows both families non-zero.
flood_stop="$(mktemp "${TMPDIR:-/tmp}/run_tests_prom_flood.XXXXXX")"
(
  while [ -e "$flood_stop" ]; do
    timeout 1s "$BINDIR/turnutils_uclient" \
      -e 127.0.0.1 -X -g -u baduser -W wrongsecret -p 3479 127.0.0.1 \
      > /dev/null 2>&1
  done
) &
flood_pid="$!"
prom_metrics=""
deadline=$((SECONDS + POLL_TIMEOUT))
while [ "$SECONDS" -lt "$deadline" ]; do
  scrape="$(wget --quiet --output-document=- --tries=1 "http://127.0.0.1:8081/metrics" 2>/dev/null)"
  if echo "$scrape" | grep -Eq "^turn_ratelimit_occupied_buckets [1-9][0-9]*(\\.[0-9]+)?$" &&
     echo "$scrape" | grep -Eq "^turn_unauthenticated_401_requests(_total)? [1-9][0-9]*(\\.[0-9]+)?$"; then
    prom_metrics="$scrape"
    break
  fi
  sleep 0.2
done
rm -f "$flood_stop"
wait "$flood_pid" 2>/dev/null
assert_prom_metric_nonzero "turn_unauthenticated_401_requests" "$prom_metrics"
assert_prom_metric_nonzero "turn_unauthenticated_401_responses" "$prom_metrics"
assert_prom_metric_nonzero "turn_unauthenticated_401_dropped_responses" "$prom_metrics"
# The single bad-cred source occupies exactly one live bucket; capacity is the
# fixed table size. (Collisions stay 0 with one source, so are not asserted here.)
assert_prom_metric_nonzero "turn_ratelimit_occupied_buckets" "$prom_metrics"
assert_prom_metric_nonzero "turn_ratelimit_total_buckets" "$prom_metrics"
stop_turnserver
