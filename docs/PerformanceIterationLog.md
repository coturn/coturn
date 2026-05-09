# Performance iteration log

Running notes for the multi-iteration performance work on the UDP relay
data path. Pick this up to continue without re-deriving everything.

The harness, baseline command, and droplet topology are documented in
[CLAUDE.md](../CLAUDE.md) under "Load Test on DigitalOcean" — this file
captures the *deltas*: what was measured, what landed, what didn't, and
where the next round should go.

## Cumulative result

Five commits on `claude/beautiful-black-c3b741` between `727ec2ab`
("loadgen") and `321a2d18`:

| # | Commit | Optimization |
|---|---|---|
| 1 | `ce7e7e53` | Hoist `turn_server_get_engine()` out of per-packet hot path |
| 2 | `8e28491a` | `ioa_socket_check_bandwidth` early fast-exit; drop dead `if (!(s->done \|\| s->fd==-1))` in `send_data_from_ioa_socket_nbh` |
| 3 | `344360f6` | Cache `get_relay_socket_ss()` and `ioa_network_buffer_get_size()` in `write_to_peerchannel`, `handle_turn_send`, `read_client_connection` |
| 4 | `a6f6767f` | Inline `get_ioa_addr_len()` via `ns_turn_ioaddr.h` |
| 5 | `321a2d18` | Inline `addr_cpy()` via `ns_turn_ioaddr.h` |

Current `relay-recvmmsg` follow-up:

| # | Commit | Optimization |
|---|---|---|
| 6 | `54c589d0` / `4b1a8d71` | Initial Linux `recvmmsg` batching for UDP listener and connected relay sockets |
| 7 | `8d9a7292` | Share the existing `--udp-recvmmsg` flag across listener and relay UDP paths; remove separate relay flag; use the shared ancillary-data parser in `dtls_listener` |
| 8 | `d48686b7` | Reduce relay per-socket `recvmmsg` state from 16 x 64 KiB cmsg buffers to TTL/TOS-sized buffers, avoid an extra would-block fallback `recvmsg`, and clean up all preallocated buffers after partial batches |
| 9 | `ad81705e` | Add per-engine `recvmmsg` occupancy counters and 10 s log summaries (`calls`, `packets`, `avg_batch`, `wouldblock`, `unavailable`, `no_buffer`, batch-size histogram) |
| 10 | `388b15d4` | Move connected relay UDP `recvmmsg` scratch from per-socket state to per-engine/per-thread state |
| 11 | `4c4fd67e` | Make the occupancy summaries opt-in behind `--udp-recvmmsg-log`, so `--udp-recvmmsg` can ship without periodic stats logs |

Validation after #7-#11:

- Local `cmake -S . -B build -DBUILD_TESTING=ON` passed.
- Local `cmake --build build --parallel 8` passed.
- Local `ctest --test-dir build --output-on-failure` passed 3/3.
- Local `build/bin/turnserver --udp-recvmmsg --udp-recvmmsg-log --version`
  parsed both flags and printed `4.11.0`.
- Linux Docker `turnserver` build passed after #7, after #8, and after #10.

Shipping cleanup learning: keep the occupancy counters in place because they
are low overhead and useful for DigitalOcean diagnostics, but keep the periodic
summaries off by default. Use `--udp-recvmmsg-log` only during measured runs
where the log stream is part of the observation.

DigitalOcean check on 2026-05-09:

- Reused the existing `c-4` droplets in `nyc1`: turnserver public
  `157.230.3.102`, private `10.116.0.2`; loadgen public `167.99.153.216`,
  private `10.116.0.3`. Droplets were left running between steps.
- Built fresh current artifacts from `d48686b7` on both droplets under
  `/root/coturn_recvmmsg_current`.
- Same-binary `--udp-recvmmsg` off/on, `-Y packet -m 1 -l 120`, 5 alternating
  30 s rounds each:
  - off mean 154,527, median 154,596, stdev 3,467
  - on mean 149,994, median 153,011, stdev 7,174
  - on was -2.9 % by mean and -1.0 % by median
- Same-binary `--udp-recvmmsg` off/on, `-Y packet -m 100 -l 120`, 5 alternating
  rounds each. The client completed before the 30 s timeout and landed in two
  send-volume buckets, so treat this as a coarse many-connection signal:
  - off mean 59,432, median 65,071, stdev 7,952
  - on mean 59,640, median 65,421, stdev 7,963
  - on was +0.3 % by mean and +0.5 % by median
- Follow-up `m=100 -n 1000` run, 3 alternating rounds each, derived receive
  count from `tot_recv_bytes / 120` because this log format omits
  `tot_recv_msgs`:
  - off mean 8,540, median 8,990, stdev 1,004
  - on mean 8,857, median 8,749, stdev 759
  - on was +3.7 % by mean and -2.7 % by median

Learning: the corrected relay `recvmmsg` implementation is now buildable and
much safer for many connections, but these droplet runs still do not show a
clear throughput win. Keep `--udp-recvmmsg` opt-in for now. The next useful
step is to instrument actual batch occupancy on connected relay sockets; if
most readiness events return one datagram, `recvmmsg` will mostly add setup
work without reducing syscalls.

DigitalOcean occupancy check on 2026-05-09:

- Built fresh current artifacts from `388b15d4` on both droplets under
  `/root/coturn_recvmmsg_current`.
- Same-binary `--udp-recvmmsg` off/on, `-Y packet -m 1 -l 120`, 3 alternating
  30 s rounds each:
  - off mean 153,133, median 153,608, stdev 4,383
  - on mean 148,452, median 149,711, stdev 10,833
  - on was -3.1 % by mean and -2.5 % by median
- `m=1` occupancy from the on runs: 1,129,427 `recvmmsg` calls returned
  17,660,300 packets, average batch 15.64. Histogram buckets:
  `hist_1=1,353`, `hist_2=1,496`, `hist_3_4=3,707`,
  `hist_5_8=14,817`, `hist_9_16=1,108,057`; 98.1 % of calls were in the
  `9..16` bucket.
- Same-binary `--udp-recvmmsg` off/on, `-Y packet -m 100 -l 120`, 3 alternating
  runs each:
  - off mean 55,443, median 50,679, stdev 8,369
  - on mean 60,596, median 65,404, stdev 8,383
  - on was +9.3 % by mean and +29.1 % by median, but the client again landed
    in two send-volume buckets, so treat the throughput delta as noisy.
- `m=100` occupancy from the on runs across all relay threads: 1,426,401
  `recvmmsg` calls returned 16,188,946 packets, average batch 11.35.
  Histogram buckets: `hist_1=83,057`, `hist_2=79,781`,
  `hist_3_4=130,066`, `hist_5_8=188,259`, `hist_9_16=945,238`; 66.3 %
  of calls were in the `9..16` bucket.

Learning: receive-side occupancy is high. The earlier hypothesis that
`recvmmsg` was mostly returning one packet is wrong for this harness. The
remaining bottleneck is after receive: per-packet callbacks, TURN processing,
and especially one `sendto` per relayed packet. The per-thread scratch change
is still worth keeping for memory/cache behavior with thousands of sockets,
but the next performance lever should be send-side batching or a design that
passes batches deeper instead of immediately decomposing them back into
single-packet callbacks.

Alternating A/B run on the same droplet pair, m=1 packet flood, 30 s
per run, with a 4 s warm-up between binary swaps:

- Baseline (clean `master` binary): mean 146,984 round-trips / 30 s
- Cumulative (all 5 iters): mean 155,468 round-trips / 30 s
- **+5.8 % throughput**

Per-iteration deltas were within run-to-run noise (~5–10 % variance).
The cumulative effect is what's visible.

## Test setup that was used

Two `c-4` Ubuntu 24.04 droplets in `nyc1`, same VPC `default-nyc1`.
Current active pair:

- `coturn-turnserver` — public `157.230.3.102`, private `10.116.0.2`
- `coturn-loadgen`    — public `167.99.153.216`, private `10.116.0.3`

Older pair used for the iter 5 cumulative run:

- `coturn-turnserver` — public `68.183.121.197`, private `10.116.0.2`
- `coturn-loadgen`    — public `68.183.132.220`, private `10.116.0.3`

Created via the DigitalOcean v2 API (`doctl` is *not* installed; use
`curl` + `$DIGITALOCEAN_TOKEN` from the user's `~/.zshrc`). SSH via
`~/.ssh/id_rsa` (matches DO ssh key id `23704483`, fingerprint
`37:3a:9b:e3:1e:1a:9b:42:a0:6f:58:f5:5a:3a:6a:2c`).

State on the turnserver droplet (kept across iterations):

- `/root/coturn_clean.tar` — `git archive HEAD` of master at start of run.
  Re-extract this before applying any new patch.
- `/root/coturn_baseline/build/bin/turnserver` — clean baseline binary,
  used as the "B" in every A/B round. **Don't overwrite.**
- `/root/coturn/build/bin/turnserver` — current iteration binary.
- `/root/start_turnserver.sh`, `/root/baseline_run.sh` — helper scripts.

State on the loadgen droplet:

- `/root/coturn/build/bin/turnutils_uclient`, `turnutils_peer`.
- `turnutils_peer` runs as a daemon on `10.116.0.3:3480`
  (`pid` in `/root/peer.pid`).

A small env file was written to `/tmp/coturn_perf_env.sh` on the local
machine with the IPs / droplet IDs — recreate it from the current
state of the DO account if it gets lost.

The standard packet-flood command (matches CLAUDE.md baseline, runs without
`--udp-recvmmsg`; add `--udp-recvmmsg` to `turnserver`, not the client, for the
batched listener/relay receive path):

```bash
timeout -s INT 30s /root/coturn/build/bin/turnutils_uclient \
  -Y packet -m 1 -l 120 \
  -e 10.116.0.3 -r 3480 -X -g \
  -u user -W secret \
  10.116.0.2
```

Metric: the `tot_recv_msgs` field on the last `start_mclient:` log
line. (This is round-trips through the relay over the test window;
`send_pps` is loadgen-side only and can hit 262 K even when the relay
is dropping most of them, so it's not a useful proxy for relay
throughput.)

## Hot-path map at the end of iter 5

`perf record -F 99 -g` on the turnserver during a 12 s `-Y packet -m 1`
run, sorted by user-space self-time:

```
0.80 % send_data_from_ioa_socket_nbh
0.76 % socket_input_worker
0.69 % read_client_connection.isra.0
0.60 % turn_report_session_usage
0.53 % peer_input_handler
0.51 % udp_server_input_handler
0.35 % udp_recvfrom               # was 0.76 % at iter 1
0.34 % lm_map_get
0.27 % stun_is_channel_message_str
0.27 % get_relay_socket
0.26 % ioa_socket_check_bandwidth # was 0.33 % at iter 1
0.26 % udp_send                   # was 0.60 % at iter 1
0.18 % ioa_network_buffer_get_size
```

Total user-space coturn cycles: ~5–7 % of the relay thread.
The relay thread sits at ~100 % CPU pinned to one core; the 4 relay
threads aren't parallelised by the m=1 single-flow test (one 5-tuple
hashes to one SO_REUSEPORT worker).

Kernel side (children-aggregated) is the real cost:

```
36 % udp_sendmsg (sendto path)
14 % udp_recvmsg
17 % ip_finish_output / ip_output / __dev_queue_xmit
~23 % syscall enter / exit machinery (sysret, SYSRETQ, SYSCALL_64*)
```

That ~23 % syscall overhead is the next big lever. Halving it
(via batching) is worth ~10 % wall-clock CPU.

## What didn't work

### Default `--udp-recvmmsg=true` on Linux (tried in iter 1, kept opt-in)

The flag now covers both the unconnected listener socket in
[dtls_listener.c](../src/apps/relay/dtls_listener.c) and connected plain-UDP
relay sockets in
[ns_ioalib_engine_impl.c](../src/apps/relay/ns_ioalib_engine_impl.c). DTLS
session sockets remain on the SSL read path and are not batched by the relay
socket helper.

Throughput parity or slight negative results were confirmed across multiple
A/B rounds on `m=1` and `m=100`; keep this opt-in until batch occupancy
instrumentation proves that real deployments commonly receive multiple queued
datagrams per connected socket readiness event.

### Caching `get_relay_socket_ss` (iter 3) — no measurable wall-clock win

The function is `static inline` already and the underlying
`get_relay_socket()` is a four-line accessor. Caching the result
*does* save a cross-TU function call per packet (the compiler can't
prove `get_relay_socket` pure across the
`set_df_on_ioa_socket` / `ioa_network_buffer_*` calls in between),
which the perf profile picked up as a small redistribution, but
throughput stayed in the noise band. Kept anyway: the cleanup is
defensible and matches the iter 4/5 inlining direction.

## Methodology lessons

- **Always alternate A/B per round** rather than running 5×B then 5×I.
  The droplet pair has noticeable environmental drift over a few
  minutes (other tenants on the hypervisor, NIC ring backpressure,
  whatever); sequential blocks bias whichever binary ran on the worse
  half of the run.
- **Discard the first run after a turnserver restart.** The loadgen's
  first run after a server restart is consistently 30–80 % slower
  than steady-state — looks like channel/permission state in the
  client side warming up, not the server. A 4 s "throwaway" run
  before the measured 30 s run is enough.
- **Run-to-run variance is ~5–10 %** even with alternation. Plan on
  6–8 rounds (≈ 8 minutes wall-clock) before claiming a sub-10 % win.
  A single 3-round A/B will lie to you.
- **Use the `tot_recv_msgs` field, not `send_pps`**. Loadgen send rate
  saturates at ~262 K pps regardless of relay capacity — it's
  whatever the loadgen kernel will accept into its UDP send buffer.
  The receive count is what made it round-trip through the relay.
- **The relay is kernel-bound.** User-space coturn is ~5 % of cycles.
  Halving it gives at most ~2.5 % wall-clock — usually undetectable
  per-iteration, only visible cumulatively. Don't expect a 10 % jump
  from a CSE.
- **Single-flow tests pin one core.** With `SO_REUSEPORT` the kernel
  hashes 5-tuples to worker sockets; one client → one tuple → one
  worker thread. The other 3 cores sit idle. To exercise all 4 relay
  threads you'd need m≥4 *with distinct source ports* — ours don't
  spread cleanly because the loadgen reuses ports.
- **Don't re-extract `/root/coturn` between iterations** if you want
  to keep `git apply`-style patches working. The droplet copy is *not*
  a git checkout (it's the `git archive` tar). Use `patch -p1`. Each
  iteration uploaded a *cumulative* diff (current branch vs `master`)
  and re-extracted from `/root/coturn_clean.tar` first to get a clean
  apply.

## Optimization backlog (bigger fish for next session)

Ordered by expected impact for the m=1 packet-flood metric:

1. **Batch the send side (`sendmmsg`) or pass receive batches deeper.** The
   occupancy counters show receive batching is already working: `m=1` averaged
   15.6 packets per call and `m=100` averaged 11.4. The code immediately
   invokes the existing per-packet callback for each received datagram, and
   each forwarded packet still pays a separate send syscall. The next
   measurable lever is to queue per-thread outbound datagrams during a receive
   batch and flush them with `sendmmsg`, or introduce a batch-aware callback
   path for the hot UDP relay case.

2. **Keep `recvmmsg` occupancy counters available while developing send
   batching.** They are cheap enough for targeted performance builds and make
   it obvious whether a benchmark is exercising one relay thread or all relay
   threads. Consider hiding periodic logs behind a verbose/debug option before
   shipping broadly.

3. **GSO (`UDP_SEGMENT`)** on the send path. Linux can take one
   "large" datagram and segment it in the kernel for back-to-back
   packets to the same destination. Our channel-data flood IS
   same-destination. Setting `UDP_SEGMENT` and submitting a single
   `sendmsg` of N×packet_size cuts skb-alloc / `__dev_queue_xmit`
   work substantially. Needs careful handling for short tails and
   non-uniform sizes; complementary to (2).

4. **Inline more cross-TU per-packet accessors.** Pattern from iter
   4/5 still applies: `addr_eq` (called per channel-data packet for
   permission lookup), `ioa_network_buffer_get_size`,
   `get_ioa_socket_type` / `_app_type`. Each is small enough; the
   only reason to be cautious is they're declared in `ns_turn_ioalib.h`
   which is part of the public-ish server library API — moving the
   body inline doesn't break ABI but does require a recompile of all
   consumers. Likely <1 % each but cheap to do.

5. **Re-evaluate `--udp-recvmmsg` default after instrumentation.** The current
   measurements do not justify default-on. Revisit only if production-like
   traces show frequent batch sizes above one and no latency/memory downside.

## Things investigated and ruled out (don't redo)

- `set_socket_ttl` / `set_socket_tos` already short-circuit on
  no-change via `s->current_ttl != ttl` / `s->current_tos != tos`.
  In a steady-state flood the per-packet call returns immediately
  without `setsockopt`. Already optimized.
- `set_df_on_ioa_socket` similarly guarded
  ([ns_ioalib_engine_impl.c:242](../src/apps/relay/ns_ioalib_engine_impl.c#L242)).
- `turn_report_session_usage` slow path runs once per 4096 packets
  (see iter 1 commit); the per-call overhead is now ~3 reads + 1
  bitmask test + 1 conditional return.
- `MSG_CONFIRM` in `sendto` would skip ARP refresh, but
  `neigh_resolve_output` + `neigh_hh_output` show ~17 % combined in
  perf only because we're sending *that many* packets — per-packet
  it's the normal cached neighbor path, not a refresh.
- Increasing `MAX_TRIES` from 16 to 64 in `socket_input_worker`
  doesn't change syscall count; it only delays returning to libevent.
  Useless without (1) above.

## How to resume

1. Verify the droplets are still up (the IPs above). If they were
   destroyed, re-create with `c-4` / `nyc1` / `default-nyc1` VPC and
   the `pavel` SSH key (id 23704483).
2. Re-upload `/tmp/coturn_clean.tar` from `git archive master` and
   rebuild `/root/coturn_baseline/build/bin/turnserver` if the
   baseline binary is gone. The A/B harness depends on having both
   binaries side-by-side on the turnserver droplet.
3. Run a 6-round alternating A/B as a sanity check that the current
   tip-of-branch still beats `master` by ~5 %. If it doesn't, the
   environment drifted and the baseline needs re-anchoring.
4. Pick the next item from the backlog. Item (1) — `recvmmsg` into
   `socket_input_worker` — is where the next material gain lives.
