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

The exporter is always compiled in; libmicrohttpd is a required build
dependency (provided by vcpkg on Windows). The runtime `--prometheus` flag
controls whether it is started. To point CMake at a non-standard libmicrohttpd
install prefix, set `MicroHTTPD_ROOT`:

```
cmake -S . -B build -DMicroHTTPD_ROOT=/path/to/libmicrohttpd/install
cmake --build build
```

The exporter is always compiled in (libmicrohttpd is a required build
dependency); the runtime `--prometheus` flag controls whether it is started.

## HTTPS (optional)

By default the metrics endpoint is served over plain HTTP. To serve it over
HTTPS instead, pass `--prometheus-tls` (requires libmicrohttpd built with TLS
support). `--prometheus-tls` implies `--prometheus`, so it enables the exporter
on its own — there is no need to pass both. The certificate and key default to
the server's own `--cert` / `--pkey`; override them with `--prometheus-cert` /
`--prometheus-key`:

```
# Reuse the server's TLS material:
turnserver --prometheus-tls --cert server.pem --pkey server.key

# Or use a dedicated certificate for the metrics endpoint:
turnserver --prometheus-tls \
    --prometheus-cert metrics.pem --prometheus-key metrics.key
```

Then scrape with `https://<host>:9641/metrics`. If `--prometheus-tls` is set
but no certificate/key can be loaded, the exporter logs an error and does not
start.

## UDP 401 mitigation metrics

When the optional UDP 401 response rate limit is enabled, use:

```
unauthorized-ratelimit
unauthorized-ratelimit-rps=10
prometheus
```

The rate limit is disabled by default. It applies only to UDP `401 Unauthorized`
responses, which can otherwise be used in spoofed-source reflection attacks.

When Prometheus is enabled, the exporter provides the following counters for
this path whether or not mitigation is enabled. The dropped response counter
increments only when `unauthorized-ratelimit` suppresses responses.

| Metric | Type | Meaning |
|---|---|---|
| `turn_unauthenticated_401_requests` | counter | UDP requests requiring a `401 Unauthorized` response. |
| `turn_unauthenticated_401_responses` | counter | UDP `401 Unauthorized` responses emitted. |
| `turn_unauthenticated_401_dropped_responses` | counter | UDP `401` responses suppressed by the rate limit. |

The rate-limit hash table is also instrumented. These values are computed
lazily when Prometheus scrapes `/metrics`, so they add no cost to the hot path:

| Metric | Type | Meaning |
|---|---|---|
| `turn_ratelimit_hash_collisions` | counter | Requests whose source hashed to a bucket already owned by a different live address (distinct sources sharing a budget — the mitigation's false-positive surface). |
| `turn_ratelimit_occupied_buckets` | gauge | Buckets currently holding a live (non-expired) window. |
| `turn_ratelimit_total_buckets` | gauge | Table capacity in buckets. |

`turn_ratelimit_occupied_buckets / turn_ratelimit_total_buckets` is the table
load factor; a sustained high ratio or a climbing `turn_ratelimit_hash_collisions`
rate means distinct attackers are colliding into shared buckets. See
[docs/401-ratelimit.md](401-ratelimit.md) for the full design.
