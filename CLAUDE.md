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
- `= {0}` zero-initialization for stack buffers before use

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

- **Port types**: use `uint16_t` for port fields (not `int`)
- **Buffer initialization**: always zero-initialize stack buffers before passing to functions (`= {0}` or `memset`)
- **HMAC output buffers**: declare as `uint8_t buf[MAXSHASIZE] = {0}` before passing to integrity functions
- **Uninitialized structs**: use `= {0}` for stack-allocated address structs (e.g., `ioa_addr`)
- **Error handling**: check return values of all OpenSSL/libevent calls; use `ERR_clear_error()` before HMAC operations
- **Logging**: use `TURN_LOG_FUNC` macros, not `fprintf`/`perror`
