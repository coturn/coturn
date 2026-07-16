#!/usr/bin/env bash
# In-container orchestrator. Runs each phase, captures stdout+stderr to its
# own log file under /out, records exit codes in /out/SUMMARY.txt, and never
# aborts on a single phase failure — so one run surfaces every issue.

# Deliberately not setting `set -e` at the top level: each phase manages its
# own failure handling so subsequent phases still run.
set -uo pipefail

readonly mounted_src=/src
readonly work_src=/work/coturn
readonly log_dir=/out

mkdir -p "${log_dir}"
: > "${log_dir}/all.log"
: > "${log_dir}/SUMMARY.txt"
printf '%-18s %-6s %-5s %s\n' phase status exit log >> "${log_dir}/SUMMARY.txt"

overall_status=0

ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

# run_phase <name> <log-file> <cmd...>
# Streams output to both the per-phase log and /out/all.log, with timestamps.
# Records the result in SUMMARY.txt. Updates overall_status on failure.
run_phase() {
  local name=$1
  local log_file=$2
  shift 2

  echo
  echo "===== [$(ts)] PHASE: ${name} ====="
  {
    echo "===== [$(ts)] PHASE: ${name} ====="
    echo "Command: $*"
  } | tee -a "${log_dir}/${log_file}" "${log_dir}/all.log" >/dev/null

  local start_epoch end_epoch dur status
  start_epoch=$(date -u +%s)

  set +e
  ( "$@" ) 2>&1 \
    | gawk '{ print strftime("[%Y-%m-%dT%H:%M:%SZ] ", systime(), 1) $0; fflush(); }' \
    | tee -a "${log_dir}/${log_file}" "${log_dir}/all.log"
  status=${PIPESTATUS[0]}
  set -e

  end_epoch=$(date -u +%s)
  dur=$((end_epoch - start_epoch))

  local label=PASS
  if [ "${status}" -ne 0 ]; then
    label=FAIL
    overall_status=1
  fi

  printf '%-18s %-6s %-5s %s\n' "${name}" "${label}" "${status}" "${log_file}" \
    >> "${log_dir}/SUMMARY.txt"
  echo "===== [$(ts)] PHASE ${name}: ${label} (exit=${status}, ${dur}s) ====="

  return 0
}

# ----- phase: env -------------------------------------------------------------
phase_env() {
  echo "## uname"
  uname -a
  echo
  echo "## /etc/os-release"
  cat /etc/os-release
  echo
  echo "## CPU model"
  grep -m1 'model name' /proc/cpuinfo || true
  echo
  echo "## Apt-installed build deps"
  dpkg -l | grep -E 'libssl|libevent|sqlite|cmake|pkg-config|^ii  curl' || true
  echo
  echo "## filcc --version"
  filcc --version || true
  echo
  echo "## /opt/fil contents"
  ls -la /opt/fil/bin 2>/dev/null | head -50 || true
  echo
  echo "## Fil-C-built libs available in /opt/fil"
  ls /opt/fil/lib*/libssl*    2>/dev/null || true
  ls /opt/fil/lib*/libcrypto* 2>/dev/null || true
  ls /opt/fil/lib*/libevent*  2>/dev/null || true
  ls /opt/fil/lib*/libsqlite* 2>/dev/null || true
  echo
  echo "## pkg-config sees"
  for pkg in openssl libevent sqlite3; do
    printf '%-12s ' "${pkg}"
    pkg-config --modversion "${pkg}" 2>&1 || echo "(missing)"
  done
  echo
  echo "## env"
  env | sort | grep -E '^(CC|CXX|PATH|CMAKE_|PKG_CONFIG|LD_)' || true
}

# ----- phase: source-copy -----------------------------------------------------
phase_source_copy() {
  rm -rf "${work_src}"
  mkdir -p "${work_src}"
  echo "Copying ${mounted_src} -> ${work_src} (excluding .git, build*, .DS_Store)"
  tar \
    --exclude='.git' \
    --exclude='.DS_Store' \
    --exclude='build' \
    --exclude='build-*' \
    --exclude='filc/logs' \
    -C "${mounted_src}" \
    -cf - . | tar -C "${work_src}" -xf -
  echo "Copy complete."
  du -sh "${work_src}"
  ls "${work_src}"
}

# ----- phase: build -----------------------------------------------------------
phase_build() {
  LOG_DIR="${log_dir}" coturn-filc-build
}

# ----- phase: unit-tests ------------------------------------------------------
phase_unit_tests() {
  ctest \
    --test-dir "${work_src}/build" \
    --output-on-failure \
    --output-junit "${log_dir}/unit-tests.junit.xml"
}

# ----- phase: system-tests-cli ------------------------------------------------
phase_system_cli() {
  cd "${work_src}/examples"
  # Bump the post-launch sleep from 2s to 6s. Under linux/amd64 emulation on
  # Apple Silicon, the Fil-C-built turnserver is not yet accepting TCP at 2s,
  # so the very first sub-test races and prints FAIL. Matches run_tests_conf.sh.
  sed -i 's/^sleep 2$/sleep 6/' run_tests.sh
  ./run_tests.sh
}

# ----- phase: system-tests-conf -----------------------------------------------
phase_system_conf() {
  cd "${work_src}/examples"
  ./run_tests_conf.sh
}

# Run every phase, but skip later ones if a prerequisite already failed.
run_phase env         env.log              phase_env
run_phase source-copy source-copy.log     phase_source_copy

if grep -E '^source-copy +PASS' "${log_dir}/SUMMARY.txt" >/dev/null; then
  run_phase build build.log phase_build
fi

if grep -E '^build +PASS' "${log_dir}/SUMMARY.txt" >/dev/null; then
  run_phase unit-tests   unit-tests.log   phase_unit_tests
  run_phase system-cli   run_tests.log    phase_system_cli
  run_phase system-conf  run_tests_conf.log phase_system_conf
else
  echo "Build failed; skipping test phases."
  for skipped in unit-tests system-cli system-conf; do
    printf '%-18s %-6s %-5s %s\n' "${skipped}" SKIP -- skipped \
      >> "${log_dir}/SUMMARY.txt"
  done
fi

# examples/run_tests.sh prints "FAIL" on failed test cases but exits 0.
# Catch that explicitly.
for phase_log in run_tests.log run_tests_conf.log; do
  if [ -f "${log_dir}/${phase_log}" ] && \
     grep -Eq '(^|\] )FAIL$' "${log_dir}/${phase_log}"; then
    echo "Detected FAIL marker in ${phase_log}; downgrading phase status."
    case "${phase_log}" in
      run_tests.log)      target=system-cli ;;
      run_tests_conf.log) target=system-conf ;;
    esac
    # Mark failure and update overall status.
    awk -v t="${target}" '
      $1==t { printf "%-18s %-6s %-5s %s\n", $1, "FAIL", "1", $4; next }
      { print }
    ' "${log_dir}/SUMMARY.txt" > "${log_dir}/SUMMARY.txt.new"
    mv "${log_dir}/SUMMARY.txt.new" "${log_dir}/SUMMARY.txt"
    overall_status=1
  fi
done

# ----- issues extraction ------------------------------------------------------
{
  echo "# Issues extracted from /out/*.log"
  echo "# Generated: $(ts)"
  echo
  for f in "${log_dir}"/*.log; do
    [ -f "${f}" ] || continue
    base=$(basename "${f}")
    [ "${base}" = "all.log" ] && continue
    matches=$(grep -nE \
      'error:|undefined reference|warning:|FAIL$|SEGV|Segmentation fault|panic|Filc panic|filc panic|AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|assertion|Assertion .* failed|cannot find' \
      "${f}" || true)
    if [ -n "${matches}" ]; then
      echo "## ${base}"
      echo "${matches}"
      echo
    fi
  done
} > "${log_dir}/ISSUES.txt"

echo
echo "===== [$(ts)] FINAL SUMMARY ====="
cat "${log_dir}/SUMMARY.txt"
echo "===== overall exit: ${overall_status} ====="

exit "${overall_status}"
