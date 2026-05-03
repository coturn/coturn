# AGENT.md — Coturn

Coturn is a TURN/STUN server written in C11, implementing RFC 5766, RFC 5389, and related NAT traversal protocols. It supports multiple database backends (SQLite, PostgreSQL, MySQL, Redis, MongoDB), multiple auth mechanisms, and a fuzzing harness for OSS-Fuzz.

## Build

```bash
# Standard build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)

# Fuzzer build (requires clang or AppleClang)
CC=clang CXX=clang++ cmake -S . -B build -DFUZZER=ON
cmake --build build -j$(nproc)
```

Key CMake options:
- `-DFUZZER=ON` — build OSS-Fuzz targets (requires Clang or AppleClang)
- `-DCMAKE_BUILD_TYPE=Debug|Release`
- `-DWITH_MYSQL=ON/OFF`, `-DWITH_PGSQL=ON/OFF`, `-DWITH_MONGO=ON/OFF`, `-DWITH_REDIS=ON/OFF`

## Required validation

Every code change must be validated before it is considered complete. Run the
unit tests, the local/system tests, and the fuzzing smoke tests. When working
from macOS, also validate the Linux build and Docker image tests inside Docker
containers.

```bash
# Local build + unit tests
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --parallel $(nproc)
ctest --test-dir build --output-on-failure

# Local/system tests
cd examples
./run_tests.sh
./run_tests_conf.sh
./run_tests_prom.sh   # only when Prometheus support is built
cd ..

# Fuzzing smoke tests (increase runs/time for fuzzing-related changes)
fuzzing/run-local.sh ASan 0 -runs=1
fuzzing/run-local.sh ASan 1 -runs=1
```

Treat any `FAIL` line from the example scripts as a test failure even if the
script exits with status 0.

On macOS, run the Linux validation in Docker as well. The fuzzing smoke tests
build the reusable `coturn-fuzz-local` image; then run a clean Linux build and
system-test pass against a copied checkout so no root-owned build artifacts are
left in the working tree:

```bash
docker run --rm \
  -v "$PWD:/src:ro" \
  --entrypoint bash \
  coturn-fuzz-local \
  -lc 'apt-get update && apt-get install -y --no-install-recommends git && \
       cp -a /src /tmp/coturn && \
       cd /tmp/coturn && \
       cmake -S . -B build-linux -DBUILD_TESTING=ON && \
       cmake --build build-linux --parallel $(nproc) && \
       ctest --test-dir build-linux --output-on-failure && \
       rm -rf build && ln -s build-linux build && \
       cd examples && ./run_tests.sh && ./run_tests_conf.sh'
```

Also validate the packaged Docker image:

```bash
cd docker/coturn
make docker.image dockerfile=debian tag=codex-local platform=linux/arm64
make test.docker tag=codex-local platform=linux/arm64/v8
cd ../..
```

Use `platform=linux/amd64` on x86_64 hosts. On Apple Silicon, build with
`platform=linux/arm64` and run the Bats image tests with
`platform=linux/arm64/v8`, which is the spelling expected by
`docker/coturn/tests/main.bats`.

## Code style

All C source — including `src/`, `fuzzing/`, and `tests/` — must be formatted
with `clang-format-15` using the project's [.clang-format](.clang-format).
The CI job [.github/workflows/clang.yml](.github/workflows/clang.yml) runs
`make lint` and **fails the build on any formatting drift**, so any commit
containing C/H files must be formatted before it is created.

```bash
# Format the entire repo (uses the Makefile target — equivalent to
# `find . -iname "*.c" -o -iname "*.h" | xargs clang-format -i`):
make format

# Verify formatting matches CI (zero output = clean):
make lint
```

**Mandatory pre-commit step for any session that edits C/H files:**

```bash
find . -iname "*.c" -o -iname "*.h" | xargs clang-format -i
```

Run this before `git commit` whenever the staged diff touches `*.c` or `*.h`,
even when only one file was edited. The `find` form above does not require
`./configure` to have been run, so it works in worktrees and fresh clones.

Key style rules (LLVM-based):
- Indent: 2 spaces, no tabs
- Column limit: 120
- Pointer alignment: right (`int *p`)
- Brace style: attach (K&R)
- Zero-initialize stack buffers at declaration: `uint8_t buf[N] = {0}` or `SomeStruct s = {0}`

## Tests

```bash
# Protocol conformance (RFC 5769 test vectors)
cd examples && ./scripts/rfc5769.sh

# Basic TURN relay test (run server first, then client)
cd examples && ./scripts/basic/relay.sh
cd examples && ./scripts/basic/udp_c2c_client.sh

# Full test suite
cd examples && ./run_tests.sh
```

## Load Test on DigitalOcean

Use two same-region CPU-optimized droplets for repeatable load tests. The last
known setup used Ubuntu 24.04 `c-4` droplets in `nyc1`:

- turnserver droplet private IP: `10.116.0.2`
- loadgen droplet private IP: `10.116.0.3`
- build: current branch archived with `git archive`
- important baseline: turnserver was **not** run with `--udp-recvmmsg`

Never paste DigitalOcean tokens into logs or files. Use a local environment
variable such as `DIGITALOCEAN_TOKEN`, and revoke temporary tokens after the
run.

Local source package and upload:

```bash
git archive --format=tar HEAD -o /tmp/coturn.tar

scp /tmp/coturn.tar root@TURN_PUBLIC_IP:/root/coturn.tar
scp /tmp/coturn.tar root@LOADGEN_PUBLIC_IP:/root/coturn.tar
```

Install dependencies and build on both droplets:

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential cmake pkg-config libssl-dev libevent-dev \
  libsqlite3-dev libhiredis-dev git iproute2 sysstat

rm -rf /root/coturn
mkdir /root/coturn
tar -xf /root/coturn.tar -C /root/coturn
cmake -S /root/coturn -B /root/coturn/build -DCMAKE_BUILD_TYPE=Release
cmake --build /root/coturn/build --target turnserver turnutils_uclient turnutils_peer -j$(nproc)
```

Start `turnserver` on the server droplet. This is the baseline command used for
the final run; add `--udp-recvmmsg` only when intentionally comparing that mode:

```bash
pkill -x turnserver || true
sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728 \
  net.core.netdev_max_backlog=250000 || true
ulimit -n 1048576

nohup /root/coturn/build/bin/turnserver \
  --use-auth-secret \
  --static-auth-secret=secret \
  --realm=north.gov \
  --allow-loopback-peers \
  --listening-ip=10.116.0.2 \
  --relay-ip=10.116.0.2 \
  --min-port=49152 \
  --max-port=65535 \
  --no-cli \
  --no-tls \
  --no-dtls \
  --log-file=stdout \
  --simple-log \
  > /root/turnserver.log 2>&1 &
echo $! > /root/turnserver.pid
```

Start the UDP peer on the loadgen droplet:

```bash
pkill -x turnutils_peer || true
sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728 \
  net.core.netdev_max_backlog=250000 || true
ulimit -n 1048576

nohup /root/coturn/build/bin/turnutils_peer -L 10.116.0.3 -p 3480 \
  > /root/peer.log 2>&1 &
echo $! > /root/peer.pid
```

Optional server-side monitor, run on the turnserver droplet before each test:

```bash
cat > /root/start_monitor.sh <<'EOF'
#!/bin/bash
label=$1
pid=$(cat /root/turnserver.pid)
rm -f /root/${label}_*.txt
nohup bash -c "pidstat -h -u -r -p $pid 1 14 > /root/${label}_pidstat.txt & \
  mpstat 1 14 > /root/${label}_mpstat.txt & \
  sar -n DEV 1 14 > /root/${label}_sar.txt & wait" \
  > /root/${label}_monitor.out 2>&1 &
echo $! > /root/${label}_monitor.pid
EOF
chmod +x /root/start_monitor.sh
```

Connectivity smoke from loadgen:

```bash
/root/coturn/build/bin/turnutils_uclient \
  -Y packet -m 1 -n 1000 -l 120 \
  -e 10.116.0.3 -r 3480 -X -g \
  -u user -W secret \
  10.116.0.2
```

Packet relay sweep from loadgen:

```bash
for m in 1 2 4 8 16 32; do
  log=/root/packet_m${m}.log
  timeout -s INT 12s /root/coturn/build/bin/turnutils_uclient \
    -Y packet -m "$m" -l 120 \
    -e 10.116.0.3 -r 3480 -X -g \
    -u user -W secret \
    10.116.0.2 > "$log" 2>&1 || true
  tail -20 "$log"
done
```

Monitored packet run:

```bash
# on turnserver
/root/start_monitor.sh packet_m1_mon

# on loadgen
timeout -s INT 12s /root/coturn/build/bin/turnutils_uclient \
  -Y packet -m 1 -l 120 \
  -e 10.116.0.3 -r 3480 -X -g \
  -u user -W secret \
  10.116.0.2 > /root/packet_m1_mon.log 2>&1 || true
```

Packet-only CPU profile, useful when checking the relay bottleneck. Build with
`-DCMAKE_BUILD_TYPE=RelWithDebInfo` if you want readable user-space symbols.
Run once without `--udp-recvmmsg`, then restart `turnserver` with
`--udp-recvmmsg` and rerun the same commands with the `recvmmsg` label:

```bash
# on turnserver
sysctl -w kernel.perf_event_paranoid=-1 kernel.kptr_restrict=0 || true
pid=$(cat /root/turnserver.pid)
label=no_recvmmsg

(pidstat -h -u -r -p "$pid" 1 14 > /root/${label}_pidstat.txt & \
  mpstat 1 14 > /root/${label}_mpstat.txt & \
  sar -n DEV 1 14 > /root/${label}_sar.txt & wait) \
  > /root/${label}_monitor.out 2>&1 &

perf record -F 99 -g -p "$pid" -o /root/${label}.perf.data -- sleep 14
perf report --stdio -i /root/${label}.perf.data --no-children \
  --sort comm,dso,symbol > /root/${label}_perf.report
perf report --stdio -i /root/${label}.perf.data --children \
  --sort symbol,dso > /root/${label}_perf.children

# on loadgen, started about one second after perf starts
timeout -s INT 12s /root/coturn/build/bin/turnutils_uclient \
  -Y packet -m 1 -l 120 \
  -e 10.116.0.3 -r 3480 -X -g \
  -u user -W secret \
  10.116.0.2 > /root/${label}_packet_m1.log 2>&1 || true
```

Invalid-packet flood:

```bash
# on turnserver
/root/start_monitor.sh invalid_m1_mon

# on loadgen
timeout -s INT 12s /root/coturn/build/bin/turnutils_uclient \
  -Y invalid -m 1 -l 16 \
  10.116.0.2 > /root/invalid_m1_mon.log 2>&1 || true
```

Restart `turnserver` after invalid-packet tests before allocation tests. The
last run saw rapid RSS growth during invalid flood, so avoid chaining tests on
the same server process.

Allocation flood:

```bash
# on turnserver
/root/start_monitor.sh alloc_10000_mon

# on loadgen
/root/coturn/build/bin/turnutils_uclient \
  -Y alloc -m 50 -n 200 \
  -L 10.116.0.3 \
  -u user -W secret \
  10.116.0.2 > /root/alloc_10000.log 2>&1
```

Useful summaries:

```bash
grep -h 'send_pps=' /root/packet_m*.log /root/*_mon.log | tail -50
grep -h 'total_allocations=' /root/alloc_*.log | tail -20
ps -o pid,rss,vsz,pcpu,pmem,comm -p $(cat /root/turnserver.pid)
tail -20 /root/*_pidstat.txt
tail -20 /root/*_sar.txt
```

### Unit tests (Unity, opt-in via `BUILD_TESTING=ON`)

Unity is fetched on demand via CMake `FetchContent`; nothing is vendored.
Tests live under [tests/](tests/) and link against the existing
`turnclient` static library.

```bash
# CMake direct
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j --target check     # builds tests, runs ctest
cmake --build build -j --target test_ioaddr  # build a single binary
ctest --test-dir build --output-on-failure   # run already-built tests

# Legacy Makefile bridge (after ./configure; requires cmake on PATH)
make unit-tests   # bootstraps build/unit-tests/, builds + runs Unity tests
```

Adding a new test: drop `tests/test_<name>.c` and append
`coturn_add_test(test_<name>)` in [tests/CMakeLists.txt](tests/CMakeLists.txt).
The `check` target picks it up automatically.

See [docs/Testing.md](docs/Testing.md) for database setup and extended test scenarios.

## Source layout

```
src/
  client/          # TURN client library (C)
  client++/        # TURN client library (C++)
  server/          # Core TURN/STUN server logic
  apps/
    relay/         # turnserver main process, listeners, netengine
    uclient/       # CLI test client
include/turn/      # Public headers
fuzzing/           # OSS-Fuzz targets and seed corpora
examples/          # Test scripts and sample configs
turndb/            # Database schema and setup scripts
docs/              # Protocol notes and configuration docs
```

## Common patterns

- **Port types**: use `uint16_t` for port fields and parameters (not `int`); port 0 means OS-assigned ephemeral
- **Buffer initialization**: zero-initialize stack buffers at declaration (`= {0}`), not just before first use
- **HMAC output buffers**: declare as `uint8_t buf[MAXSHASIZE] = {0}` — the buffer is written into the message before HMAC runs, so uninitialized bytes would be briefly present in the packet
- **Uninitialized structs**: use `= {0}` for stack-allocated address structs (e.g., `ioa_addr`)
- **Counter overflow in `turn_ports.c`**: `_turnports` uses `uint32_t low/high` counters; comparisons must be overflow-safe (use subtraction, not `>=`)
- **Port bounds checks**: use `<= USHRT_MAX` (not `< USHRT_MAX`) when validating that an `int` holds a valid port — port 65535 is valid
- **Error handling**: check return values of all OpenSSL/libevent calls; use `ERR_clear_error()` before HMAC operations
- **Logging**: use `TURN_LOG_FUNC` macros, not `fprintf`/`perror`
