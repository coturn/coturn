#!/usr/bin/env bash
# Build coturn with the Fil-C compiler in Docker and run the test suite.
# All output is captured under filc/logs/<UTC-timestamp>/ on the host.
#
# Fil-C is Linux/x86_64 only; on Apple Silicon hosts the image runs under
# Docker Desktop's amd64 emulation (Rosetta or QEMU) and is therefore slow.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  filc/run-local.sh [args passed through to the in-container entrypoint]

Environment:
  COTURN_FILC_IMAGE   image tag to build/run (default: coturn-filc-local)
  FILC_VERSION        Fil-C release to bake into the image (default: 0.678)

Examples:
  filc/run-local.sh
  COTURN_FILC_IMAGE=coturn-filc-local:dev filc/run-local.sh
  FILC_VERSION=0.678 filc/run-local.sh
EOF
}

case "${1:-}" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_name="${COTURN_FILC_IMAGE:-coturn-filc-local}"
filc_version="${FILC_VERSION:-0.678}"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${repo_root}/filc/logs/${ts}"
mkdir -p "${log_dir}"

echo "Logs: ${log_dir}"
echo "Image: ${image_name}"
echo "Fil-C version: ${filc_version}"
echo

docker_run_flags=(--rm --platform linux/amd64)
if [ -t 0 ] && [ -t 1 ]; then
  docker_run_flags+=(-it)
fi

# Build the image. Use the host log dir so a failing build is still triagable.
set +e
docker build \
  --platform linux/amd64 \
  --build-arg "FILC_VERSION=${filc_version}" \
  -f "${repo_root}/filc/Dockerfile" \
  -t "${image_name}" \
  "${repo_root}/filc" 2>&1 | tee "${log_dir}/docker-build.log"
build_status=${PIPESTATUS[0]}
set -e

if [ "${build_status}" -ne 0 ]; then
  echo "docker build failed (exit ${build_status}). See ${log_dir}/docker-build.log" >&2
  exit "${build_status}"
fi

# Run the build + tests inside the container. The entrypoint writes per-phase
# logs to /out (mounted to ${log_dir}) and never aborts mid-run, so we get a
# full picture of every issue in a single pass.
set +e
docker run "${docker_run_flags[@]}" \
  -v "${repo_root}:/src:ro" \
  -v "${log_dir}:/out" \
  "${image_name}" \
  "$@"
run_status=$?
set -e

echo
echo "Logs: ${log_dir}"
if [ -f "${log_dir}/SUMMARY.txt" ]; then
  echo "----- SUMMARY.txt -----"
  cat "${log_dir}/SUMMARY.txt"
  echo "-----------------------"
fi
if [ -f "${log_dir}/ISSUES.txt" ] && [ -s "${log_dir}/ISSUES.txt" ]; then
  echo "ISSUES.txt is non-empty — see ${log_dir}/ISSUES.txt"
fi

exit "${run_status}"
