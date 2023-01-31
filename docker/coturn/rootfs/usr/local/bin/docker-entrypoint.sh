#!/bin/bash

# If command starts with an option, prepend it with a `turnserver` binary.
if [ "${1:0:1}" == '-' ]; then
  set -- turnserver "$@"
fi

expanded=()
for i in "$@"; do
  expanded+=("$(eval "echo $i")")
done

exec "${expanded[@]}"
