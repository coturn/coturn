# Prometheus setup

coturn exposes a Prometheus metrics endpoint (default `:9641/metrics`) when
started with `--prometheus`.

## Vendored Prometheus client

coturn ships a minimal, self-contained Prometheus client under
[`src/prometheus`](../src/prometheus) and builds it straight from those
sources.

The vendored client implements the slice of the API coturn uses —
counters, gauges, a single default registry, and the text-exposition
serializer. Histograms, summaries, custom registries and a bundled HTTP
handler are out of scope; coturn serves the endpoint with its own
libmicrohttpd handler in
[`src/apps/relay/prom_server.c`](../src/apps/relay/prom_server.c).

The exporter's only external dependency is **libmicrohttpd**.

## Install libmicrohttpd

### Ubuntu / Debian

```
sudo apt install libmicrohttpd-dev
```

### macOS (Homebrew)

```
brew install libmicrohttpd
```

### From source

[libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/) — download from
https://git.gnunet.org/libmicrohttpd.git

```
git clone https://git.gnunet.org/libmicrohttpd.git
cd libmicrohttpd
./autogen.sh
./configure --prefix=`pwd`/install --disable-doc --disable-examples \
    --disable-tools
make install
```

## Build

The exporter is built whenever libmicrohttpd is found, and skipped otherwise;
there is no separate opt-in flag. The runtime `--prometheus` flag controls
whether it is started. To point CMake at a non-standard libmicrohttpd install
prefix, set `MicroHTTPD_ROOT`:

```
cmake -S . -B build -DMicroHTTPD_ROOT=/path/to/libmicrohttpd/install
cmake --build build
```
