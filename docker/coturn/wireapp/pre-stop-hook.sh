#!/bin/bash

# FUTUREWORK: this will break with IPv6. this should be fixed so it works with
# IPv6.

set -uo pipefail

SLEEPTIME=60

host="$1"
port="$2"

url="http://$host:$port/metrics"

echo "Polling coturn status on $url"

while true; do
    allocs=$(curl -s "$url" | grep -E '^turn_active_allocations' | cut -d' ' -f2)
    if [ "$?" != 0 ]; then
        echo "Could not retrieve metrics from coturn!"
        exit 1
    fi

    if [ -z "$allocs" ]; then
        echo "No more active allocations, exiting"
        exit 0
    fi
    if [ "$allocs" = 0 ]; then
        echo "No more active allocations, exiting"
        exit 0
    fi

    echo "Active allocations remaining, sleeping for $SLEEPTIME seconds"
    sleep "$SLEEPTIME"
done
