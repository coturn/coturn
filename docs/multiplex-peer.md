# coturn Multiplex-Peer Mode — Design & Implementation Guide

## Problem Statement

Standard coturn allocates **one dedicated UDP socket (= one OS port) per TURN
session**.  The relay port range is bounded (default 49152–65535, ≈16 000
ports), so a single server is hard-capped at ≈16 000 simultaneous relay
sessions even when CPU, RAM, and bandwidth are plentiful.

---

## How coturn Normally Allocates Ports

```
handle_turn_allocate_request()          [ns_turn_server.c]
  └─ create_relay_connection()
       └─ create_relay_ioa_sockets()    [ns_ioalib_engine_impl.c]
            ├─ turnipports_allocate()   — pick a free port from the pool
            ├─ create_unbound_relay_ioa_socket()   — socket(2)
            ├─ bind_ioa_socket()        — bind(2) to relay-IP:chosen-port
            └─ (optionally) a second socket on port+1 for legacy RTCP
```

Every session holds one (or two) bound sockets.  The OS demultiplexes
inbound datagrams by destination port → one file descriptor per session.

```
available_ports  ≈ max-port − min-port + 1   (≈ 16 383 by default)
```

Once exhausted the server rejects new Allocates with `508 Insufficient
Capacity`.

---

## Design: Per-Thread Peer-Side Multiplexing

### Core idea

Replace the per-session `bind()` with **one persistent socket pair per relay
thread** (one IPv4 socket, one IPv6 socket).  Sessions are demultiplexed by
the **peer's source IP:port** rather than by the relay destination port.

### Why per-thread (not a single global socket)?

| Concern | Global socket | Per-thread socket |
|---------|---------------|-------------------|
| Mutex on hash table | Required — multiple threads write concurrently | **Not needed** — each thread owns its table |
| Cache thrashing | High — false sharing on the hash head pointer | None |
| libevent integration | Awkward — socket registered in one event_base, but written from others | Natural — socket lives in the thread's own event_base |
| Failure isolation | One bad socket affects all sessions | Failure of one thread's socket is contained |
| Port count consumed | 1 IPv4 + 1 IPv6 = 2 ports total | 2 × N ports (N = relay threads) |

With the default of 4 relay threads you consume 8 ports instead of 16 000.
With 64 threads you consume 128 ports — still orders of magnitude fewer.

### Port assignment formula

```
IPv4 port = base_port + thread_id × 2
IPv6 port = base_port + thread_id × 2 + 1
```

Example with `--multiplex-peer-port=3480` and 4 relay threads:

| Thread | IPv4 port | IPv6 port |
|--------|-----------|-----------|
| 0 | 3480 | 3481 |
| 1 | 3482 | 3483 |
| 2 | 3484 | 3485 |
| 3 | 3486 | 3487 |

No two threads ever share a port.  No `SO_REUSEPORT` trickery required
(though we set it anyway for future-proofing).

### Thread pinning

coturn's listener assigns each incoming client to a relay thread
round-robin at connection time and then pins that client there for the
session lifetime.  This means a client always reaches the **same thread**
— and thus the same relay port — for every packet.  The port returned
in `XOR-RELAYED-ADDRESS` is therefore stable and correct.

### Demultiplexing diagram

```
Normal mode:
  Client A ──► relay-ip:55000 (fd A, thread 0) ──► peer A
  Client B ──► relay-ip:55002 (fd B, thread 0) ──► peer B
  ... (one fd + one port consumed per session)

Multiplex-peer mode (4 threads):
  Client A (→ thread 0) ──► relay-ip:3480 (shared fd, thread 0) ──► peer A
  Client B (→ thread 0) ──► relay-ip:3480 (shared fd, thread 0) ──► peer B
  Client C (→ thread 1) ──► relay-ip:3482 (shared fd, thread 1) ──► peer C
  ...
  (2 × N fds total; demux by exact peer IP:port within each thread)
```

---

## Architecture: Where State Lives

All multiplex-peer state is embedded directly in `ioa_engine_t`.
There are **no globals** and **no mutexes**.

```c
/* New fields added to ioa_engine_t in ns_ioalib_engine_impl.c */
int               mp_enabled;       // 1 when multiplex-peer is active
int               relay_thread_id;  // zero-based thread index
ioa_socket_handle mp_sock_v4;       // thread-local IPv4 relay socket
ioa_socket_handle mp_sock_v6;       // thread-local IPv6 relay socket
uint16_t          mp_port_v4;       // port mp_sock_v4 is bound to
uint16_t          mp_port_v6;       // port mp_sock_v6 is bound to
ur_addr_map       mp_table;         // exact peer IP:port -> turn session
```

The `mp_table` address map:

```c
peer_addr:port -> ts_ur_super_session*
```

---

## Data Flow

### Allocate request

```
create_relay_connection()
  └─ create_relay_ioa_sockets(..., multiplex_peer_mode=1)
       └─ create_relay_socket_multiplex_peer()
            ├─ shared = mp_get_socket(e, AF_INET)   // engine's own socket
            └─ *rtp_s = shared                       // no bind(), no port consumed
```

### Client → peer (send indication / channel data)

The client sends to port 3478 (the TURN listener socket). The server reads
the allocation, looks up the permission, registers the exact peer IP:port
to the session, and sends to the peer from the shared relay socket.

### Peer → client (inbound relay data)

```
libevent fires mp_relay_input_handler(s=shared_sock, data->remote_addr=peer)
  └─ mp_table exact lookup: peer IP:port -> turn_session
       └─ verify the allocation still has permission for peer IP
       └─ forward to client socket
```

This mode assumes each peer IP:port belongs to exactly one client
allocation on the relay worker. If two clients use the same peer IP:port,
the second registration is rejected instead of routing ambiguously.

### Session teardown

```
shutdown_client_connection()
  ├─ mp_deregister_session_peers(e, ss, 0)   // remove exact-peer entries
  ├─ relay_endpoint_session->s = NULL        // prevent shared socket close
  └─ clear_allocation() / IOA_CLOSE_SOCKET() // now a safe no-op for relay sock
```

Nulling the relay socket pointer before `clear_allocation()` is the key
safety measure.  It ensures the engine-owned shared socket fd is never
closed by session teardown code.

---

## Egress Batching (sendmmsg / UDP-GSO) and Observability

Multiplex-peer mode does more than save ports — it is also what makes
**cross-session egress batching** possible on Linux.

### Why both directions batch under multiplex-peer

`recvmmsg` on a UDP socket drains many datagrams in one syscall, and the
drain loop (`socket_udp_read_batch_recvmmsg`) wraps its per-datagram dispatch
in `udp_sendmmsg_batch_begin()` / `udp_sendmmsg_batch_end()`. Any sends issued
while processing that drain are collected into a thread-local batch keyed by
the **send fd** and flushed once (via `sendmmsg`, or a single UDP-GSO `sendmsg`
when destination and segment size match) at `batch_end`.

- **Uplink (client → relay → peer).** The client listener's `recvmmsg` drain
  pulls many clients' datagrams; each is forwarded to its peer on the shared
  relay socket → one `sendmmsg` on the relay fd.
- **Downlink (peer → relay → client).** With multiplex-peer the **shared**
  relay socket's `recvmmsg` drain pulls datagrams for *many sessions* at once;
  each is forwarded to its client. Per-session UDP client sockets are children
  of the listener socket (`parent_s`), and `udp_send_fd()` returns the
  **listener fd** for all of them — so downlink sends to *different clients*
  coalesce into one `sendmmsg` on the shared listener fd, each `mmsghdr`
  carrying its own client destination.

This is why downlink-to-client is **not** an unbatched per-packet `sendto`
path under multiplex-peer: the listener fd is effectively a shared
client-facing send socket, and `sendmmsg` amortizes the syscall across
clients. (In non-multiplex mode each allocation has its own relay socket, so a
relay `recvmmsg` drain only ever spans one session and the downlink batch is a
singleton — cross-client batching genuinely requires multiplex-peer.)

`udp_sendmmsg` is enabled automatically whenever `--multiplex-peer` is set;
`--udp-gso` additionally turns on UDP-GSO segmentation for batches that share
destination and size.

### Measuring it: `--udp-sendmmsg-log`

GSO only engages when every datagram in a batch shares the same destination
and size, so at low per-flow packet rates (e.g. VoIP, a few dozen pps per
flow) it rarely fires and batches tend toward singletons. To see what is
actually happening, enable per-thread egress stats every 10 s:

```bash
turnserver --multiplex-peer --udp-gso --udp-sendmmsg-log ...
```

```
udp-sendmmsg stats: flushes=21 datagrams=27 avg_batch=1.29 \
  gso_flushes=0 gso_datagrams=0 gso_frac=0.000 \
  hist_1=17 hist_2=2 hist_3_4=2 hist_5_8=0 hist_9_16=0 hist_17_32=0
```

- `avg_batch` — mean datagrams coalesced per flush (1.0 = no coalescing).
- `gso_frac` — fraction of datagrams sent via UDP-GSO (≈0 means GSO is not
  earning its keep at this workload).
- `hist_*` — per-flush occupancy histogram.

Batch occupancy scales with how many datagrams arrive per `recvmmsg` drain,
which grows with aggregate pps — so these numbers rise under higher load and
stay near 1.0 on lightly loaded servers. Pair with `--udp-recvmmsg-log` to see
the ingress side.

---

## Files Changed

| File | What changes |
|------|-------------|
| `src/apps/relay/ns_ioalib_impl.h` | Multiplex-peer fields; declarations for `init_multiplex_peer`, exact-peer registration cleanup helpers, `mp_get_socket`, and `mp_get_port` |
| `src/apps/relay/ns_ioalib_engine_impl.c` | Shared socket setup, exact-peer routing table, registration cleanup helpers, and the multiplex-peer branch in `create_relay_ioa_sockets` |
| `src/server/ns_turn_ioalib.h` | Add `multiplex_peer_mode` parameter to `create_relay_ioa_sockets` declaration |
| `src/server/ns_turn_server.h` | Add `multiplex_peer_mode` field to `turn_turnserver` |
| `src/server/ns_turn_server.c` | Pass flag; register exact peers from CREATE_PERMISSION/SEND/CHANNEL_BIND; clean mappings on timeout/teardown; keep shared sockets open |
| `src/apps/relay/mainrelay.h` | Add `multiplex_peer` and `multiplex_peer_base_port` to `turn_params_t` |
| `src/apps/relay/mainrelay.c` | CLI options; startup validation; call `init_multiplex_peer` from `setup_relay_server` |

---

## CLI Usage

```bash
# Enable with default base port 3480 and default relay threads (4)
# Opens ports 3480-3487 (4 threads × 2 address families)
turnserver --multiplex-peer

# Custom base port
turnserver --multiplex-peer --multiplex-peer-port=4000

# Full example
turnserver \
  --listening-port=3478 \
  --relay-ip=203.0.113.1 \
  --relay-threads=4 \
  --multiplex-peer \
  --multiplex-peer-port=3480 \
  --lt-cred-mech \
  --realm=example.com
```

Startup log:
```
multiplex-peer: 4 thread(s), port range 3480-3487 (IPv4+IPv6 per thread)
multiplex-peer: thread 0 IPv4 socket bound to 203.0.113.1:3480
multiplex-peer: thread 0 IPv6 socket bound to ::1:3481
multiplex-peer: thread 1 IPv4 socket bound to 203.0.113.1:3482
...
```

---

## Firewall Rules

Standard mode requires opening 49152–65535 (16 383 ports).
Multiplex-peer mode requires only:

| Port(s) | Protocol | Purpose |
|---------|----------|---------|
| 3478 | UDP + TCP | TURN signalling (unchanged) |
| 5349 | UDP + TCP | TURN/TLS (unchanged, optional) |
| **3480 – 3480 + threads×2 − 1** | **UDP** | **Relay media (multiplex-peer)** |

With 4 threads: open 3480–3487.  With 8 threads: open 3480–3495.

---

## Limitations & Trade-offs

| Limitation | Detail |
|------------|--------|
| EVEN-PORT silently ignored | Modern WebRTC uses `rtcp-mux` — EVEN-PORT is not needed |
| Clients on different threads see different relay ports | Correct and expected; the thread assignment is stable per connection |
| Source-IP must be preserved | If a load balancer SNATs clients, the src-IP uniqueness guarantee breaks — use DSR or PROXY protocol |
| Ports exposed = 2 × relay_threads | Still tiny compared to the default range; adjust `--relay-threads` if needed |
| TCP relay unaffected | RFC 6062 TCP relay allocates one TCP socket per peer — not subject to the same port pressure |

---

## Testing

```bash
# Start server (no auth for easy testing)
turnserver \
  --no-auth \
  --listening-ip=127.0.0.1 \
  --relay-ip=127.0.0.1 \
  --relay-threads=2 \
  --multiplex-peer \
  --multiplex-peer-port=3480

# Confirm ports 3480-3483 are open and listening
ss -ulnp | grep -E '348[0-3]'

# Create 20 000 simultaneous allocations (far above the normal 16k limit)
turnutils_uclient -n 20000 -u test -w test 127.0.0.1

# Observe relay ports in XOR-RELAYED-ADDRESS – should only be 3480 or 3482
# (depending on which thread each client lands on)

# Packet-level verification
tcpdump -i lo udp portrange 3480-3483 -n
```
