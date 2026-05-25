#!/bin/bash


# Detect cmake build and adjust path
BINDIR="../bin"
if [ ! -f $BINDIR/turnserver ]; then
    BINDIR="../build/bin"
fi

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
  # Match something that looks like the expected body
  wget --quiet --output-document=- --tries=1 "$1" | grep 'TYPE\|HELP\|counter\|gauge' >/dev/null
  status="$?"
  if [ "$status" -eq 0 ]; then
    echo OK
  else
    echo FAIL
    exit "$status"
  fi
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
$BINDIR/turnserver  > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_no_response "http://localhost:9641/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus, using defaults"
$BINDIR/turnserver --prometheus > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response "http://localhost:9641/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus, using custom address"
$BINDIR/turnserver --prometheus --prometheus-address="127.0.0.1" > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response "http://127.0.0.1:9641/metrics"
kill "$turnserver_pid"
 
echo "Running turnserver with prometheus, using custom port"
$BINDIR/turnserver --prometheus --prometheus-port="8080" > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response "http://localhost:8080/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus, using custom address and port"
$BINDIR/turnserver --prometheus --prometheus-address="127.0.0.1" --prometheus-port="8080" > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response "http://127.0.0.1:8080/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus, using custom path"
$BINDIR/turnserver --prometheus --prometheus-path="/coturn/metrics" > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response "http://localhost:9641/coturn/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus 401 mitigation counters"
$BINDIR/turnserver --prometheus --prometheus-address="127.0.0.1" --prometheus-port="8081" \
  --use-auth-secret --static-auth-secret=secret --realm=north.gov \
  --allow-loopback-peers --no-cli --no-tls --no-dtls \
  --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --listening-port=3479 \
  --401-ratelimit --401-req-limit=1 --401-window=60 > /dev/null &
turnserver_pid="$!"
sleep 5
timeout 15s "$BINDIR/turnutils_uclient" \
  -e 127.0.0.1 -X -g -u baduser -W wrongsecret -p 3479 127.0.0.1 \
  > /dev/null 2>&1 || true
sleep 1
prom_metrics="$(wget --quiet --output-document=- --tries=1 "http://127.0.0.1:8081/metrics")"
assert_prom_metric_nonzero "turn_unauthenticated_401_requests" "$prom_metrics"
assert_prom_metric_nonzero "turn_unauthenticated_401_responses" "$prom_metrics"
assert_prom_metric_nonzero "turn_unauthenticated_401_dropped_responses" "$prom_metrics"
# The single bad-cred source occupies exactly one live bucket; capacity is the
# fixed table size. (Collisions stay 0 with one source, so are not asserted here.)
assert_prom_metric_nonzero "turn_ratelimit_occupied_buckets" "$prom_metrics"
assert_prom_metric_nonzero "turn_ratelimit_total_buckets" "$prom_metrics"
kill "$turnserver_pid"
