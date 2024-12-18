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

echo "Running without prometheus"
$BINDIR/turnserver /dev/null &
turnserver_pid="$!"
sleep 2
assert_prom_no_response "http://localhost:9641/metrics"
kill "$turnserver_pid"

echo "Running turnserver with prometheus, using defaults"
$BINDIR/turnserver --prometheus > /dev/null &
turnserver_pid="$!"
sleep 2
assert_prom_response "http://localhost:9641/metrics"
kill "$turnserver_pid"

echo "Running turnserver with prometheus, using custom address"
$BINDIR/turnserver --prometheus --prometheus-address="127.0.0.1" > /dev/null &
turnserver_pid="$!"
sleep 2
assert_prom_response "http://127.0.0.1:9641/metrics"
kill "$turnserver_pid"
 
echo "Running turnserver with prometheus, using custom port"
$BINDIR/turnserver --prometheus --prometheus-port="8080" > /dev/null &
turnserver_pid="$!"
sleep 2
assert_prom_response "http://localhost:8080/metrics"
kill "$turnserver_pid"

echo "Running turnserver with prometheus, using custom address and port"
$BINDIR/turnserver --prometheus --prometheus-address="127.0.0.1" --prometheus-port="8080" > /dev/null &
turnserver_pid="$!"
sleep 2
assert_prom_response "http://127.0.0.1:8080/metrics"
kill "$turnserver_pid"

echo "Running turnserver with prometheus, using custom path"
$BINDIR/turnserver --prometheus --prometheus-path="/coturn/metrics" > /dev/null &
turnserver_pid="$!"
sleep 2
assert_prom_response "http://localhost:9641/coturn/metrics"
kill "$turnserver_pid"
