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
