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

Alternating A/B run on the same droplet pair, m=1 packet flood, 30 s
per run, with a 4 s warm-up between binary swaps:

- Baseline (clean `master` binary): mean 146,984 round-trips / 30 s
- Cumulative (all 5 iters): mean 155,468 round-trips / 30 s
- **+5.8 % throughput**

Per-iteration deltas were within run-to-run noise (~5–10 % variance).
The cumulative effect is what's visible.

## Test setup that was used

Two `c-4` Ubuntu 24.04 droplets in `nyc1`, same VPC `default-nyc1`:

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

The standard packet-flood command (matches CLAUDE.md baseline, runs
*without* `--udp-recvmmsg`):

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

### Default `--udp-recvmmsg=true` on Linux (tried in iter 1, reverted)

The flag exists and is wired to `receive_udp_batch_recvmmsg` in
[dtls_listener.c](../src/apps/relay/dtls_listener.c), but **only on
the listener socket** — the unconnected `udp_listen_s` that handles
the *first* packet from a new client. Once `dtls_listener` calls
`create_new_connected_udp_socket` (line ~583), subsequent
client→relay traffic on that 5-tuple goes through a per-session
*connected* UDP socket whose libevent callback is
`socket_input_handler` → `socket_input_worker` →
`udp_recvfrom` (single `recvmsg`). Same on the peer→relay direction.

In a steady-state packet flood with one client, almost zero packets
hit the listener path, so flipping the default does nothing for this
test. It would help a many-client / many-allocate workload, but
that's not what the m=1 harness measures.

Throughput parity confirmed across multiple A/B rounds; reverted to
keep the baseline mental model in CLAUDE.md intact.

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

1. **Extend `recvmmsg` into `socket_input_worker`** for plain UDP
   non-DTLS sockets. The existing `try_again` loop in
   [ns_ioalib_engine_impl.c:2683](../src/apps/relay/ns_ioalib_engine_impl.c#L2683)
   already drains up to `MAX_TRIES = 16` packets per epoll wakeup via
   16 single `recvmsg` calls. Replacing the inner read with a
   `recvmmsg` of up to 16 messages saves ~15 syscalls per drain
   iteration. At ~14 % `udp_recvmsg` kernel + ~6 % syscall machinery
   on the recv side, plausible 8–12 % throughput. Risk: the function
   is heavily branched (TCP / TLS / DTLS / UDP all share the body)
   and state can change mid-loop (`s->tobeclosed` etc.); the cleanest
   shape is a separate UDP-only helper called from
   `socket_input_handler` *before* falling through to the existing
   `socket_input_worker`, gated on `s->ssl == NULL && s->bev == NULL
   && !s->parent_s`. **This is the highest-value remaining item.**

2. **`sendmmsg` batched send.** Each successful packet fires one
   `sendto`. After (1) lands, when the receive loop hands a batch of
   N packets to the dispatch layer in one go, the corresponding sends
   could be coalesced into one `sendmmsg`. Requires a lightweight
   per-thread send queue and a flush at the end of each event-loop
   tick. Bigger refactor; expect another ~10 % if (1) lands.

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

5. **Re-evaluate `--udp-recvmmsg` default after (1) lands.** Once
   per-session sockets also batch, the listener path is no longer a
   special case and turning it on by default becomes a free win for
   multi-tenant servers without hurting m=1.

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
