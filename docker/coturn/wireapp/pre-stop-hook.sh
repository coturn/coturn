#!/bin/bash

# FUTUREWORK: this will break with IPv6. this should be fixed so it works with
# IPv6.

set -uo pipefail

SLEEPTIME=3

host="$1"
port="$2"

url="http://$host:$port/metrics"

coturn_exe=/usr/bin/turnserver
coturn_pid=$(pgrep -f "$coturn_exe" | head -n 1)

function log(){
    msg=$1
    # send log output of the preStop hook to stdout of
    # the main turnserver process, so they show up in the
    # normal logs of the pod.
    echo "PRESTOP: $msg" > "/proc/$coturn_pid/fd/1"
}

function getAllocations(){
    allocs=$(curl -s "$url" | grep -E '^turn_total_allocations' | cut -d' ' -f2)
    if [ -z "$allocs" ]; then
        # nobody used the coturn server yet, which means the metric is absent from the output, in which case default to 0.
        allocs=0
    fi
    # Note: there can be multiple allocation counts, e.g.
    # turn_total_allocations{type="UDP"} 0
    # turn_total_allocations{type="TCP"} 0
    # So we need to sum the counts before comparing with 0.
    sum=0
    for num in $allocs; do
        (( sum += num ))
    done
    log "Active remaining turn_allocations: $sum"
}

getAllocations

# Invoke drain mode (https://github.com/wireapp/coturn/pull/12)
pkill -f --signal SIGUSR1 "$coturn_exe"
log "Sent SIGUSR1 to $coturn_exe to start draining."

while pgrep -f "$coturn_exe" > /dev/null; do
    log "$coturn_exe is still running"
    getAllocations
    sleep $SLEEPTIME
done
