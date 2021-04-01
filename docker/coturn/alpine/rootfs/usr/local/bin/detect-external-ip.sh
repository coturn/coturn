#!/bin/sh

if [ -z "$REAL_EXTERNAL_IP" ]; then
  export REAL_EXTERNAL_IP="$(curl -4 https://icanhazip.com 2>/dev/null)"
fi

exec echo "$REAL_EXTERNAL_IP"
