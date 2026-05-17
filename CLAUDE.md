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
./run_tests.sh                  # default protocols, both legacy and
                                # threaded uclient (--listener-threads /
                                # --sender-threads). On Linux it also
                                # enables --udp-recvmmsg on the server
                                # and runs a -Y packet load-gen smoke
                                # that checks non-zero send_pps +
                                # recv_pps. GSO/multiplex live in
                                # run_tests_multiplex_peer.sh.
./run_tests_conf.sh             # same protocols, conf-file driven;
                                # mirrors run_tests.sh via config keys.
./run_tests_multiplex_peer.sh   # exercises --multiplex-peer with shared
                                # per-thread relay sockets (UDP/TCP/TLS/
                                # DTLS) on the small port range opened by
                                # --multiplex-peer-port. Auto-enables
                                # --udp-recvmmsg on Linux.
./run_tests_prom.sh             # only when Prometheus support is built
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
       cd examples && ./run_tests.sh && ./run_tests_conf.sh && \
       ./run_tests_multiplex_peer.sh'
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

### Topology — 3 same-region droplets

Run uclient, turnserver, and peer on **separate** droplets so the loadgen
and reflector never compete with the server under test. Last known setup
was three Ubuntu 24.04 `c-4` (4 vCPU / 8 GB) droplets in `nyc1`, all in
the `default-nyc1` VPC (`10.116.0.0/24`):

| Role | Droplet | Private IP |
|---|---|---|
| turnserver | `coturn-server-perf` (id `570437076`) | `10.116.0.2` |
| uclient (loadgen) | `coturn-loadgen-perf` (id `570437077`) | `10.116.0.3` |
| peer (reflector) | `coturn-peer-perf` (id `571385939`) | `10.116.0.4` |

The 2-droplet shape (peer co-located on the loadgen) is fine for smoke
runs but burns ~20 % of loadgen CPU on the peer reflector and skews
`send_pps` comparisons across configs.

Never paste DigitalOcean tokens into logs or files. Use a local
environment variable such as `DIGITALOCEAN_TOKEN`.

### Flag inventory (relay-side)

- `--udp-recvmmsg` — Linux `recvmmsg()` batched receive on UDP listener
  and plain connected relay UDP sockets. DTLS session sockets still go
  through the OpenSSL read path.
- `--udp-gso` — Linux UDP-GSO (`UDP_SEGMENT` cmsg) when a sendmmsg
  batch shares destination and segment size. **Requires
  `--multiplex-peer`** — that mode is what enables the sendmmsg
  batching GSO piggybacks on; passing `--udp-gso` alone is a silent
  no-op.
- `--multiplex-peer` — replace the per-allocation relay-port bind with
  a per-thread shared IPv4+IPv6 relay socket pair. Implies sendmmsg
  batching on Linux and default-enables `--udp-recvmmsg` (override
  with an explicit `--udp-recvmmsg=0`). Port layout: thread `i` binds
  `--multiplex-peer-port + 2*i` (IPv4) and `+1` (IPv6); a 4-thread
  server with default base 3480 uses 3480–3487. See
  [docs/multiplex-peer.md](docs/multiplex-peer.md) for the design.
- `--udp-recvmmsg-log` — emit `udp-recvmmsg stats` every 10 s; useful
  to confirm per-thread batch occupancy.

### Flag inventory (uclient)

- `-Y packet|invalid|alloc` — load-generator mode.
- `-c` — no rtcp; in `clnet_allocate` the EVEN-PORT slot is then chosen
  randomly between 0 and -1 ([startuclient.c:440](src/apps/uclient/startuclient.c:440)).
- `--no-even-port` — force `ep = -1` unconditionally. **Required** for
  alloc-flood runs against `--multiplex-peer`, which strictly rejects
  EVEN-PORT with error 400 ([ns_ioalib_engine_impl.c:1585](src/apps/relay/ns_ioalib_engine_impl.c:1585)).
- `-K N` / `--listener-threads N`, `--sender-threads N` — loadgen-side
  receive/send pools. Auto: 0 for `-m < 4`, bumped to 1 listener / 2
  sender for `-m >= 4`. Max 4 each. Use `--sender-threads 4` to push
  the loadgen harder when you're trying to saturate the server.

### Source upload + build

```bash
# locally
git archive --format=tar HEAD -o /tmp/coturn.tar
for ip in TURN_PUBLIC_IP UCLIENT_PUBLIC_IP PEER_PUBLIC_IP; do
  scp /tmp/coturn.tar root@$ip:/root/coturn.tar &
done; wait

# on each droplet (apt step needed once per droplet; peer needs at least
# turnutils_peer; uclient needs turnutils_uclient; server needs turnserver)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential cmake pkg-config \
  libssl-dev libevent-dev libsqlite3-dev libhiredis-dev git iproute2 sysstat

rm -rf /root/coturn && mkdir /root/coturn
tar -xf /root/coturn.tar -C /root/coturn
cmake -S /root/coturn -B /root/coturn/build -DCMAKE_BUILD_TYPE=Release
cmake --build /root/coturn/build \
  --target turnserver turnutils_uclient turnutils_peer -j$(nproc)
```

### Sysctl + ulimit on every droplet

```bash
sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728 \
  net.core.netdev_max_backlog=250000
ulimit -n 1048576
```

### Peer fleet (peer droplet, 10.116.0.4)

Bring up 8 `turnutils_peer` processes on ports 3480..3487 so the
loadgen can target multiple distinct peer ports. The Linux peer
transparently batches inbound datagrams via `recvmmsg()` and echoes
with GSO-segmented `sendmsg()` when the batch shares source IP and
segment size (see [src/apps/peer/udpserver.c](src/apps/peer/udpserver.c)),
so 8 processes on a 4-vCPU peer droplet stay well below saturation:

```bash
pkill -x turnutils_peer 2>/dev/null || true
for p in 3480 3481 3482 3483 3484 3485 3486 3487; do
  nohup /root/coturn/build/bin/turnutils_peer -L 10.116.0.4 -p $p \
    > /root/peer_${p}.log 2>&1 &
done
ss -ulnp | grep -E ':(348[0-7])\b' | wc -l  # expect >= 8
```

### turnserver (server droplet, 10.116.0.2)

Baseline (no fast paths). Add flags from the table above to compare:

```bash
pkill -x turnserver 2>/dev/null || true
mkdir -p /root/runs
LABEL=baseline   # or recvmmsg / mpx_peer / mpx_gso
EXTRA=""         # "--udp-recvmmsg" |
                 # "--multiplex-peer --multiplex-peer-port=3480" |
                 # "--multiplex-peer --multiplex-peer-port=3480 --udp-gso"

nohup /root/coturn/build/bin/turnserver \
  --use-auth-secret --static-auth-secret=secret --realm=north.gov \
  --allow-loopback-peers \
  --listening-ip=10.116.0.2 --relay-ip=10.116.0.2 \
  --min-port=49152 --max-port=65535 \
  --no-cli --no-tls --no-dtls \
  --log-file=stdout --simple-log \
  $EXTRA \
  > /root/runs/${LABEL}.turnserver.log 2>&1 &
echo $! > /root/runs/${LABEL}.pid

# Wait for readiness before driving load.
until grep -q "Total auth threads:" /root/runs/${LABEL}.turnserver.log; do
  sleep 0.5
done
```

### Packet-flood matrix workload (uclient droplet, 10.116.0.3)

8 parallel uclient processes, each `-m 1` against a distinct peer port
(3480..3487). The 1-session-per-(thread, peer-port) shape is what keeps
`--multiplex-peer`'s per-thread `mp_table` collision-free regardless of
which relay thread the server's round-robin assigns each session to.

```bash
mkdir -p /root/runs
LABEL=baseline
PIDS=()
for pp in 3480 3481 3482 3483 3484 3485 3486 3487; do
  LOG=/root/runs/${LABEL}.par_p${pp}.log
  (timeout -s INT 45s /root/coturn/build/bin/turnutils_uclient \
     -Y packet -m 1 -n 50000000 -l 120 -c --no-even-port \
     --listener-threads 1 --sender-threads 4 \
     -e 10.116.0.4 -r "$pp" -X -g \
     -u user -W secret \
     10.116.0.2 > "$LOG" 2>&1) &
  PIDS+=("$!")
done
for p in "${PIDS[@]}"; do wait "$p"; done
```

`turnutils_uclient` logs `send_pps=… , recv_pps=… , total_sent=… ,
total_recv=…` periodically ([uclient.c:945](src/apps/uclient/uclient.c:945)).
Always take the **median of in-flight progress lines** (drop the first
2-3 warm-up samples and any trailing zero-pps lines), then **sum across
the 8 streams**. Two derived values that matter:

- `recv_pps` = end-to-end relayed throughput. The canonical comparison
  metric across configs.
- `send_pps − recv_pps` = packets dropped somewhere on the round trip.
  At parity throughput this should match across configs.

### 3-host CPU instrumentation

Run `mpstat` on all three droplets (host-wide CPU breakdown) and
`pidstat` on the server droplet (turnserver process slice), pinned to
the duration of the loadgen run:

```bash
DUR=45

# on turnserver
nohup mpstat 1 $DUR > /root/runs/${LABEL}.server_mpstat.txt 2>&1 & disown
nohup pidstat -h -u -r -p $(cat /root/runs/${LABEL}.pid) 1 $DUR \
  > /root/runs/${LABEL}.server_pidstat.txt 2>&1 & disown

# on uclient
nohup mpstat 1 $DUR > /root/runs/${LABEL}.uclient_mpstat.txt 2>&1 & disown

# on peer
nohup mpstat 1 $DUR > /root/runs/${LABEL}.peer_mpstat.txt 2>&1 & disown
```

Parse the `Average:` line — note field offsets differ from the
per-sample lines because there's no time column:

```bash
awk '$1=="Average:" && $2=="all" {
  printf "user=%5.1f sys=%5.1f softirq=%5.1f idle=%5.1f\n", $3, $5, $8, $NF
}' /root/runs/${LABEL}.server_mpstat.txt

# turnserver process CPU only:
tail -1 /root/runs/${LABEL}.server_pidstat.txt | awk '{
  print "usr="$4" sys="$5" CPU="$8"%"
}'
```

### Reading the matrix (what "good" looks like)

A last clean run (2026-05-16, 3-droplet, 8 streams × 45 s, `c-4`):

| Config | recv pps (8-stream sum) | `turnserver` CPU | server host idle | server host softirq |
|---|---:|---:|---:|---:|
| baseline | 91 k | 367 % | 24 % | 14.1 % |
| `--udp-recvmmsg` | 99 k | 229 % (−38 %) | 48 % | 2.6 % |
| `--multiplex-peer` | 97 k | 293 % (−20 %) | 42 % | 13.3 % |
| `--multiplex-peer --udp-gso` | 96 k | **134 % (−63 %)** | **65 %** | **0.8 %** |

The recv-pps ceiling (~95-100 k) is the loadgen-side cap on a `c-4`
uclient — `%sys + %softirq` on the uclient host runs at ~70 % per core
across all configs, indicating the kernel network stack is saturated.
The win shows up as server-side CPU savings, **not** as more relayed
pps. To push the server toward saturation, resize the uclient to `c-8`
(or larger) first.

### Bottleneck identification

For any run, look at the three `mpstat Average:` lines:

| Host idle % | Reading |
|---|---|
| < 20 % on uclient | uclient is the cap; you're measuring loadgen, not server. Bump uclient size or thread pools. |
| < 20 % on peer | peer reflector saturated; add more peer processes or move peer to a bigger droplet. |
| > 50 % on server | server has headroom; you can push it harder if uclient/peer allow. |
| < 10 % on server | server is the bottleneck — this is what you want when measuring server-side perf changes. |

### Allocation throughput

```bash
# on uclient — alloc-flood; --no-even-port keeps multiplex-peer from
# rejecting every other request with 400.
timeout -s INT 60s /root/coturn/build/bin/turnutils_uclient \
  -Y alloc -m 200 -n 1000 -c --no-even-port \
  -L 10.116.0.3 \
  -u user -W secret \
  10.116.0.2 > /root/runs/${LABEL}.alloc.log 2>&1

# rate:
grep -oE "total_allocations=[0-9]+" /root/runs/${LABEL}.alloc.log \
  | awk -F= '{print $2}' | sort -n | tail -1
```

Sessions are torn down between iterations, so this measures alloc/s
**throughput**, not concurrent-session cap. Baseline and
`--multiplex-peer` deliver roughly the same rate (~700 alloc/s on
`c-4`); allocation is control-plane and isn't where the fast paths
help. The cap-removal property of `--multiplex-peer` is structural (2
ports per relay thread, total) — cite [docs/multiplex-peer.md](docs/multiplex-peer.md)
rather than trying to demo it via a load test.

### Invalid-packet flood

```bash
# on uclient
timeout -s INT 12s /root/coturn/build/bin/turnutils_uclient \
  -Y invalid -m 1 -l 16 \
  10.116.0.2 > /root/runs/invalid_m1.log 2>&1 || true
```

`-Y invalid` bypasses the TURN allocate handshake and sprays malformed
datagrams at the listener; useful for the parse/reject hot path. The
uclient pacer drops its interval to 100 µs and lifts the per-burst send
cap to 4096 in flood modes ([uclient.c:899](src/apps/uclient/uclient.c:899)),
so even `-m 1` produces real load. **Restart turnserver after an invalid
flood** before any allocation test — past runs saw rapid RSS growth.

### CPU profile (perf, server droplet)

Build with `-DCMAKE_BUILD_TYPE=RelWithDebInfo` for readable symbols.
Capture once per config you're comparing (`fastpath_off`, `fastpath_on`,
optionally one-flag-at-a-time):

```bash
sysctl -w kernel.perf_event_paranoid=-1 kernel.kptr_restrict=0
pid=$(cat /root/runs/${LABEL}.pid)
perf record -F 99 -g -p "$pid" -o /root/runs/${LABEL}.perf.data -- sleep 30
perf report --stdio -i /root/runs/${LABEL}.perf.data --no-children \
  --sort comm,dso,symbol > /root/runs/${LABEL}_perf.report
```

### Useful summaries

```bash
# per-stream median send/recv pps across all 8 streams of a run:
for f in /root/runs/${LABEL}.par_p*.log; do
  grep "send_pps=" "$f" | awk -F'[=, ]' '
    {for (i=1;i<=NF;i++) {if ($i=="send_pps") s=$(i+1)+0;
                          if ($i=="recv_pps") r=$(i+1)+0}
     print s" "r}' | sort -n | awk -v f="$f" '
    {a[NR]=$0} END {print f": median="a[int(NR/2)]}'
done

# turnserver process RSS over time:
ps -o pid,rss,vsz,pcpu,pmem,comm -p $(cat /root/runs/${LABEL}.pid)

# server NIC counters (drops show up as nonzero rx_dropped on eth1):
ssh root@TURN_PUBLIC_IP 'cat /proc/net/dev | column -t | head -5'
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
