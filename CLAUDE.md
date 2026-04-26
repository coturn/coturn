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

All C source must be formatted with `clang-format` using the project's [.clang-format](.clang-format):

```bash
find src -name '*.c' -o -name '*.h' | xargs clang-format -i
```

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
