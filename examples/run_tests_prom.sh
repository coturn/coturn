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

function assert_prom_response_tls() {
  # Same as assert_prom_response but over HTTPS with a self-signed cert, so
  # certificate verification is disabled. A plaintext HTTP request to the same
  # URL must NOT succeed (the endpoint is TLS-only).
  wget --no-check-certificate --quiet --output-document=- --tries=1 "$1" |
    grep 'TYPE\|HELP\|counter\|gauge' >/dev/null
  status="$?"
  if [ "$status" -ne 0 ]; then
    echo FAIL
    exit "$status"
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

echo "Running turnserver with prometheus over TLS, explicit --prometheus-cert/--prometheus-key"
$BINDIR/turnserver --prometheus --prometheus-tls \
  --prometheus-cert=etc/turn_server_cert.pem --prometheus-key=etc/turn_server_pkey.pem > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response_tls "https://localhost:9641/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus over TLS, cert/key inherited from server --cert/--pkey"
$BINDIR/turnserver --prometheus --prometheus-tls \
  --cert=etc/turn_server_cert.pem --pkey=etc/turn_server_pkey.pem > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_response_tls "https://localhost:9641/metrics"
kill "$turnserver_pid"
sleep 5

echo "Running turnserver with prometheus TLS but an unreadable cert: endpoint must not start"
$BINDIR/turnserver --prometheus --prometheus-tls \
  --prometheus-cert=/nonexistent/cert.pem --prometheus-key=/nonexistent/key.pem > /dev/null &
turnserver_pid="$!"
sleep 5
assert_prom_no_response "https://localhost:9641/metrics"
kill "$turnserver_pid"
