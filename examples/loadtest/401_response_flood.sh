#!/bin/sh

# Build and run the Linux 401 Unauthorized response-path flood generator.
# The separate compile step keeps this benchmark independent of turnserver's
# installed targets while still making it easy to upload and run on a load host.

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT="${TMPDIR:-/tmp}/coturn_401_response_flood"

"${CC:-cc}" -O3 -pthread -Wall -Wextra -o "$OUT" "$SCRIPT_DIR/401_response_flood.c"
exec "$OUT" "$@"
