#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  fuzzing/run-local.sh [ASan|UBSan|MSan] [0|1] [libFuzzer args...]

Targets:
  0  FuzzStun
  1  FuzzStunClient

Examples:
  fuzzing/run-local.sh ASan 0 -runs=100000
  fuzzing/run-local.sh UBSan 1 -max_total_time=60
EOF
}

case "${1:-}" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_name="${COTURN_FUZZ_IMAGE:-coturn-fuzz-local}"

args=("$@")
if [ "${#args[@]}" -eq 0 ]; then
  args=(ASan 0)
fi

docker_run_flags=(--rm)
if [ -t 0 ] && [ -t 1 ]; then
  docker_run_flags+=(-it)
fi

docker build \
  -f "${repo_root}/fuzzing/Dockerfile" \
  -t "${image_name}" \
  "${repo_root}/fuzzing"

docker run "${docker_run_flags[@]}" \
  -v "${repo_root}:/src:ro" \
  "${image_name}" \
  "${args[@]}"
