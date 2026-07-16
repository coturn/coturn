#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  docker run ... coturn-fuzz-local [ASan|UBSan|MSan] [0|1] [libFuzzer args...]

Targets:
  0  FuzzStun
  1  FuzzStunClient

Examples:
  run-local.sh ASan 0 -runs=100000
  run-local.sh UBSan 1 -max_total_time=60
EOF
}

sanitizer="${1:-ASan}"
if [ "$#" -gt 0 ]; then
  shift
fi

target="${1:-0}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "${sanitizer}" in
  ASan|UBSan|MSan) ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "Unsupported sanitizer: ${sanitizer}" >&2
    usage >&2
    exit 2
    ;;
esac

case "${target}" in
  0|1) ;;
  *)
    echo "Unsupported fuzz target: ${target}" >&2
    usage >&2
    exit 2
    ;;
esac

readonly mounted_src=/src
readonly work_src=/work/coturn

mkdir -p "${work_src}"
tar \
  --exclude='.git' \
  --exclude='.DS_Store' \
  --exclude='build' \
  --exclude='build-*' \
  -C "${mounted_src}" \
  -cf - . | tar -C "${work_src}" -xf -

cd "${work_src}/fuzzing"
./build.sh "${sanitizer}"
cd "${work_src}"

readonly fuzz_build_dir=./fuzzing/build/fuzzing

case "${target}" in
  0)
    exec "${fuzz_build_dir}/FuzzStun" \
      "${fuzz_build_dir}/FuzzStun_Corpus/" \
      "${fuzz_build_dir}/FuzzStun_seed_corpus" \
      "-dict=${fuzz_build_dir}/stun.dict" \
      "$@"
    ;;
  1)
    exec "${fuzz_build_dir}/FuzzStunClient" \
      "${fuzz_build_dir}/FuzzStunClient_Corpus/" \
      "${fuzz_build_dir}/FuzzStunClient_seed_corpus" \
      "-dict=${fuzz_build_dir}/stun.dict" \
      "$@"
    ;;
esac
