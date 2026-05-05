#!/usr/bin/env bash
# Configure and build coturn with the Fil-C toolchain. Called from
# docker-entrypoint.sh inside the container.

set -euo pipefail

src=/work/coturn
build="${src}/build"
log_dir="${LOG_DIR:-/out}"

cd "${src}"

echo "## cmake configure"
cmake -S . -B "${build}" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=ON \
  -DCMAKE_C_COMPILER=filcc \
  -DCMAKE_CXX_COMPILER=fil++ \
  2>&1 | tee "${log_dir}/configure.log"

echo
echo "## cmake build"
cmake --build "${build}" --parallel "$(nproc)" \
  2>&1 | tee "${log_dir}/build.log"

echo
echo "## built binaries"
ls -la "${build}/bin" 2>/dev/null || true

echo
echo "## sanity-check the relay binary"
file "${build}/bin/turnserver" 2>/dev/null || true
"${build}/bin/turnserver" -h 2>&1 | head -5 || true
