#!/bin/bash

# If command starts with an option, prepend it with a `turnserver` binary.
if [ "${1:0:1}" == '-' ]; then
  set -- turnserver "$@"
fi

if [ -v DETECT_EXTERNAL_IP ]; then
  DETECT_EXTERNAL_IP=" --external-ip=$(eval "detect-external-ip")"
fi

if [ -v DETECT_EXTERNAL_IPV6 ]; then
  DETECT_EXTERNAL_IPV6=" --external-ip=$(eval "detect-external-ip --ipv6")"
fi

if [ -v DETECT_RELAY_IP ]; then
  DETECT_RELAY_IP=" --relay-ip=$(eval "detect-external-ip")"
fi

if [ -v DETECT_RELAY_IPV6 ]; then
  DETECT_RELAY_IPV6=" --relay-ip=$(eval "detect-external-ip --ipv6")"
fi

exec "$@ ${DETECT_EXTERNAL_IP} ${DETECT_EXTERNAL_IPV6} ${DETECT_RELAY_IP} ${DETECT_RELAY_IPV6}"
