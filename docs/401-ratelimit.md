# 401 Unauthorized rate-limiting

This document describes the per-source rate-limit on `401 Unauthorized`
responses. It covers what the feature defends
against, how it is implemented, how to operate it, expected performance, and
its known weaknesses.

## Why

TURN/STUN long-term authentication is a challenge/response flow: the first
request from a client arrives without valid credentials, and the server
answers with `401 Unauthorized` carrying a `REALM` and a `NONCE`. This is
normal — the legitimate client then retries with credentials derived from the
nonce.

The problem is on UDP. UDP source addresses are trivially spoofable, and a
`401` response is larger than the request that triggers it (it carries
`REALM`, `NONCE`, `SOFTWARE`, and message-integrity material). An attacker can
therefore:

- **Reflect**: send authentication requests with the *victim's* IP forged as
  the source, so the server bounces `401` responses at the victim, and
- **Amplify**: each small spoofed request produces a larger `401`, multiplying
  the attacker's outbound bandwidth at the victim.

The server is an unwitting reflector/amplifier. The mitigation is to cap how
many `401` responses the server will emit toward any single source address per
unit time. Past the cap, the server simply stays silent — it does not send the
`401`, denying the attacker both the reflection and the amplification.

The feature is **off by default** and opt-in, because suppressing `401`
responses changes a protocol-visible behavior and only matters for operators
exposed to UDP reflection abuse.

## What it does

When enabled, for every request that *would* produce a `401`:

1. Only `UDP` client sockets are considered. TCP/TLS can't be spoofed for
   reflection (the handshake forces a real return path), so they are never
   rate-limited.
2. The source IP (port stripped) is looked up in a fixed bucket table and its
   counter for the current window is incremented.
3. If the count is within the limit, the `401` is sent as normal.
4. If the count is over the limit, `no_response` is set: the `401` is silently
   suppressed for the rest of the window.
5. The first suppression in each window emits exactly one log line; further
   drops in the same window are silent (no log-write amplification).

Counting is **consume-on-401**: only requests that actually result in a `401`
spend a token. Successful or otherwise-errored requests don't touch the table.

## How it works

### Components

| File | Role |
|---|---|
| [src/ns_turn_atomic.h](../src/ns_turn_atomic.h) | Portable 32-bit atomics (load/store/fetch_add/CAS) over C11 `<stdatomic.h>` and, on MSVC, the `Interlocked*` intrinsics. |
| [src/server/ns_turn_ratelimit.h](../src/server/ns_turn_ratelimit.h) / [.c](../src/server/ns_turn_ratelimit.c) | The lock-free rate-limit table and its two entry points. |
| [src/server/ns_turn_server.c](../src/server/ns_turn_server.c) | The consume call site inside `handle_turn_command`. |
| [src/apps/relay/mainrelay.c](../src/apps/relay/mainrelay.c) | CLI flags, defaults, and one-time `ratelimit_init()`. |
| [src/apps/relay/prom_server.c](../src/apps/relay/prom_server.c) | Prometheus counters for UDP `401` decisions. |
| [examples/run_tests_ratelimit_401.sh](../examples/run_tests_ratelimit_401.sh) | End-to-end positive/negative system test. |

### The table

```c
#define RATELIMIT_BUCKETS 4096u    // power of two
typedef struct {
  turn_atomic_u32 tag;             // hash of source IP (port stripped); 0 = empty
  turn_atomic_u32 window_start;    // turn_time() when the current window opened
  turn_atomic_u32 count;           // requests counted in this window
  turn_atomic_u32 logged;          // 1 once a drop has been logged this window
  turn_atomic_u32 collision_logged;// 1 once a collision has been logged this window
} ratelimit_bucket;
static ratelimit_bucket ratelimit_table[RATELIMIT_BUCKETS];
```

A single statically-allocated, zero-initialized table of 4096 buckets, 20
bytes each (~80 KiB resident). No `malloc`/`free` on the hot path, no growth,
no eviction list.

It is a **direct-mapped** structure: `bucket = hash(addr) & (RATELIMIT_BUCKETS-1)`.
There is exactly one active budget per bucket. An address that collides with
an unexpired bucket shares that existing budget; it cannot replace the bucket
owner and get a fresh response allowance.

- IPv4 keys are hashed with a splitmix-style 32-bit finalizer over
  `sin_addr.s_addr`.
- IPv6 keys are hashed with FNV-1a over the 16 address bytes.
- The hash is forced non-zero so `0` can mean "empty bucket".
- The **port is deliberately excluded** from the key, so an attacker cannot
  evade the limit by rotating the source port.

### The consume algorithm ([ns_turn_ratelimit.c](../src/server/ns_turn_ratelimit.c))

`ratelimit_consume_address(addr, max, window, &first_drop, &first_collision)`
returns `true` when the current request is *over* the limit (caller should
suppress):

1. Hash the address, index the bucket, read `now = (uint32_t)turn_time()`.
2. Read the bucket's `tag` and `window_start`.
3. **Reset path** — if the bucket is empty or the window has expired
   (`now - window_start >= window`): atomically store a fresh `window_start`,
   clear the log latches, set `count = 1`, and finally store the new `tag`.
   Returns `false` (this request is the first in a fresh window).
4. **Collision path** — if an unexpired bucket has another tag, retain the
   bucket owner and count the new request against the same budget. The first
   such event sets `first_collision` for one bounded diagnostic log line.
5. **Count path** — `fetch_add(count, 1)` returns the pre-increment
   value `prev`. If `prev < max`, allow (`false`). Otherwise this is the
   `(max+1)`-th request: it's over the limit, return `true`.
6. **First-drop logging** — on an over-limit request, `CAS(logged, 0 -> 1)`.
   The single winner of that CAS gets `*first_drop = true`; everyone else in
   the window is silent.

### Lock-free design and its tradeoffs

There is no mutex. All bucket fields are sequentially-consistent atomics, and
the design accepts small, bounded races by construction rather than locking
them out:

- Two threads resetting the same bucket concurrently: the second store wins;
  both observe `count == 1` by the time the `tag` store lands. Worst case the
  effective count is off by a request or two at a window boundary.
- The window-expiry check and the increment are not one transaction, so a
  request landing exactly at the boundary may be counted in the old or the new
  window. Bounded and harmless for a rate-limit.

This is acceptable because the goal is *coarse abuse mitigation*, not exact
accounting. Most importantly, active collisions share a budget instead of
granting additional reflected responses.

### Why a dedicated atomics header

The earlier shim typed the on/off flag as `bool` instead of `bool *` in
`init_turn_server()`, which truncated the parameter pointer and left the
feature effectively always-on. The fix makes all three tunables pointers into
`turn_params` (so every relay thread sees live CLI values without per-thread
copies) and centralizes the atomic primitives in
[src/ns_turn_atomic.h](../src/ns_turn_atomic.h). That header gates on
`_MSC_VER` (not the project `WINDOWS` macro) because only MSVC lacks usable C11
atomics — MinGW is a GCC toolchain and takes the `<stdatomic.h>` path. The
`Interlocked*` intrinsics and the non-explicit C11 atomics are both
sequentially consistent, so callers never reason about per-platform ordering.

## Configuration

| Flag | Default | Meaning |
|---|---|---|
| `--401-ratelimit` | off | Enable per-source 401 rate-limiting on UDP. |
| `--401-req-limit=<count>` | `1000` | Max 401 responses per source IP per window. |
| `--401-window=<seconds>` | `120` | Window length in seconds. |

Non-positive values for the threshold or window are rejected with a warning and
fall back to the default. The defaults (1000 per 120 s) are well above any
legitimate client's challenge/retry rate, so normal traffic is never affected.

Example:

```bash
turnserver --use-auth-secret --static-auth-secret=secret --realm=north.gov \
  --401-ratelimit --401-req-limit=1000 --401-window=120
```

When the limit is first crossed for a source in a window the server logs:

```
401 rate-limit exceeded from <ip>, suppressing responses for this window
```

If a different address first collides with an active bucket in a window, the
server also logs one diagnostic line for that bucket and window:

```
401 rate-limit bucket collision from <ip>, sharing active bucket budget for this window
```

When Prometheus is enabled, these metrics describe the UDP `401` reflection
surface:

| Metric | Type | Meaning |
|---|---|---|
| `turn_unauthenticated_401_requests` | counter | Requests that required a UDP `401` response. |
| `turn_unauthenticated_401_responses` | counter | UDP `401` responses emitted. |
| `turn_unauthenticated_401_dropped_responses` | counter | UDP `401` responses suppressed by this mitigation. |

A second group describes the health of the bucket table itself:

| Metric | Type | Meaning |
|---|---|---|
| `turn_ratelimit_hash_collisions` | counter | Total requests whose source hashed to a bucket already owned by a different live address. A rising rate means distinct sources are sharing budgets — the false-positive surface for the mitigation. |
| `turn_ratelimit_occupied_buckets` | gauge | Buckets currently holding a live (non-expired) window. |
| `turn_ratelimit_total_buckets` | gauge | Table capacity in buckets (the compile-time constant). |

`turn_ratelimit_occupied_buckets / turn_ratelimit_total_buckets` is the table
utilization; as it approaches 1, the birthday-paradox collision probability
climbs, so a sustained high ratio (or a climbing `turn_ratelimit_hash_collisions`
rate) is the signal to enlarge `RATELIMIT_BUCKETS`. These two are refreshed
lazily when Prometheus scrapes `/metrics`: the collision counter is a single
atomic incremented only on the collision branch, and occupancy is a one-pass
scan of the table performed at scrape time, so neither adds cost to the request
path.

## Performance

The feature is built to be effectively free on the data path:

- **Per-request cost**: one hash (a few multiplies/xors over 4 or 16 bytes),
  one array index, and a handful of atomic operations on a single bucket. No
  allocation, no syscall, no lock, no list traversal — O(1) with a tiny
  constant. It only runs on requests that already reached the `401` branch, so
  it adds nothing to authenticated relay traffic (the throughput the load tests
  in [CLAUDE.md](../CLAUDE.md) measure).
- **Memory**: a single static `ratelimit_table` of `4096 * 20 B ≈ 80 KiB` (five
  32-bit atomic fields per bucket), fixed for the life of the process and
  shared across all relay threads.
- **Cache/contention**: one bucket is one cache line's worth of atomics.
  Distinct attacker addresses hit distinct buckets, so there is no central
  contention point; a single hot source serializes only on its own bucket.
- **Log amplification**: drop and collision diagnostics each have a
  once-per-(bucket, window) CAS latch.

No microbenchmark numbers are committed for this path; the cost is dominated by
the existing `401` message construction it guards, not by the table operation.
The DigitalOcean load-test harness in [CLAUDE.md](../CLAUDE.md) measures relay
throughput, which this feature does not touch.

## Weaknesses and limitations

- **UDP only by design.** TCP/TLS/DTLS `401`s are never rate-limited. That is
  correct for the reflection threat (those transports can't be spoofed), but it
  means this is not a general brute-force-auth throttle.
- **Hash collisions share a bucket.** Two unrelated addresses mapping to the
  same of 4096 buckets consume one shared budget while its window is live. This
  prevents a collision from increasing reflected output, but a flood can cause
  incidental suppression of a colliding legitimate source's `401`s.
- **Fixed table size.** 4096 buckets is a compile-time constant
  (`RATELIMIT_BUCKETS`); there is no runtime sizing. A very large, highly-distributed
  spoof set will cycle buckets faster, but the table never grows.
- **Per-process, in-memory, non-persistent.** State is per `turnserver`
  process and resets on restart. There is no coordination across a cluster of
  servers behind a load balancer; each instance rate-limits independently.
- **Coarse accounting.** The lock-free design tolerates off-by-a-few counts at
  window boundaries and under concurrent resets. It is an abuse limiter, not an
  exact quota.
- **Granularity is whole-IP.** Because the port is stripped, all clients behind
  a single NAT/CGNAT public IP share one bucket. With many legitimate clients
  behind one address plus a tuned-down `--401-req-limit`, legitimate
  challenges could be suppressed. Keep the threshold comfortably above
  aggregate legitimate challenge rates for shared egress IPs.
- **Time source resolution.** Windows and timestamps use `turn_time()` at
  1-second granularity stored in 32 bits; fine for windows measured in seconds,
  not suitable for sub-second limiting.

## Testing

[examples/run_tests_ratelimit_401.sh](../examples/run_tests_ratelimit_401.sh)
runs two end-to-end cases against a real `turnserver` with bad credentials:

- **Positive** (`--401-req-limit=1`): a single `turnutils_uclient` session
  retries the `401` challenge enough times to cross the threshold, so exactly
  one `401 rate-limit exceeded` line must appear.
- **Negative** (`--401-req-limit=100000`): the same traffic stays far below the
  threshold, so the line must *not* appear.

It is split out of `run_tests.sh` so the rate-limit server fixture can't mask
or be masked by the protocol suite's flags. It is **skipped on macOS** (loopback
UDP relay is intermittently lossy there, making the log-line accounting flaky);
Linux CI is the canonical target.

[tests/test_ratelimit.c](../tests/test_ratelimit.c) finds a colliding source
address and verifies that a live collision remains suppressed and emits its
collision signal only once. [examples/run_tests_prom.sh](../examples/run_tests_prom.sh)
drives a low-limit unauthorized flow and verifies all three Prometheus counters
are non-zero in Linux CI.
