# coturn Multiplex-Peer Tagging — Design & Implementation Guide

> Companion to [multiplex-peer.md](multiplex-peer.md). Read that first: tagging
> is an opt-in extension of multiplex-peer mode and reuses its per-thread shared
> relay sockets, port layout, and session→thread pinning.

## Problem Statement

Plain `--multiplex-peer` replaces the per-session relay socket with one shared
socket pair per relay thread and demultiplexes inbound peer datagrams by the
**peer's source IP:port** (`mp_table`: `peer_addr:port → session`). That key is
only unique if every peer endpoint belongs to exactly one session on the thread.

When several logical peers sit **behind one shared IP:port** (a peer that
multiplexes many endpoints on a single UDP port), they collapse to a single
address tuple. The relay can no longer tell which session an inbound datagram
belongs to, and — symmetrically — the peer can't tell which logical endpoint an
outbound datagram is for. Plain multiplex-peer handles this by *rejecting* the
collision: the second session that registers an already-used peer IP:port gets
error `400` ("Peer address already used by another multiplex-peer allocation",
[ns_turn_server.c register_multiplex_peer](../src/server/ns_turn_server.c)).

**Multiplex-peer tagging** removes that restriction. It is a **private,
non-RFC** extension that must be enabled on **both** ends (turnserver and peer);
the relay↔peer wire protocol is extended with a small discriminator so multiple
sessions can share one peer IP:port unambiguously, in both directions.

---

## Design

### Core idea

Carry a **per-session mux-id** on every relay↔peer UDP datagram. The relay
assigns each session a unique 32-bit id, appends it on egress to the peer, and
on ingress reads it back to route the datagram to the right session — **by id,
not by peer IP:port**. The peer echoes the whole datagram, so the id round-trips
for free; with a real (non-echo) peer the id is the routing key for its own
logical endpoints.

Because routing is by id, the peer-IP:port uniqueness requirement disappears:
N sessions may share one peer IP:port, each distinguished by its mux-id.

### Where the discriminator lives: a trailer, not a prefix

The id is appended as a **4-byte trailer** (`[ payload ][ mux-id(4) ]`), not a
prefix. The peer's source 5-tuple is fixed, so the only place to put a
discriminator is inside the UDP payload — and the tail is the right end:

- **Strip on ingress** is a length decrement (`size -= 4`). It never touches the
  reserved **front** headroom that coturn's own framing relies on — the
  ChannelData header is prepended there via offset arithmetic
  (`ioa_network_buffer_add_offset_size`, [ns_turn_server.c peer_input_handler](../src/server/ns_turn_server.c)),
  and the Data-indication / STUN / FINGERPRINT path builds from the front too.
- **Append on egress** is a tail write (`size += 4`) into the buffer's tailroom,
  which is always present (UDP buffer capacity ≥ payload).

A prefix would *also* be zero-copy in coturn (its buffers reserve front
headroom and shuffle via offsets, not `memmove`), but it would compete with the
same 4-byte slot the ChannelData header reclaims — correct only by the
coincidence that both are 4 bytes, and fragile on the non-channel path. The
trailer sits at the opposite end from all of coturn's header machinery, so it
never interacts with it. See the codec in
[src/apps/relay/multiplex_peer_tag.h](../src/apps/relay/multiplex_peer_tag.h).

### Wire format

```
relay ──► peer       [ application payload ][ mux-id : 4 bytes, big-endian ]
peer  ──► relay      [ application payload ][ mux-id : 4 bytes, big-endian ]   (echoed unchanged)
```

- `mux-id` is a 32-bit big-endian integer. `0` is reserved for "unassigned" and
  is never put on the wire (`MULTIPLEX_PEER_TAG_NONE`).
- The client never sees the trailer: the relay appends it after the client's
  payload on the way out and strips it before relaying the echo back in. No TURN
  **client** change is required.
- This is **UDP-only**. A trailer is self-delimiting only because each datagram
  has an explicit length; a TCP/TLS relay leg has no message boundary. (A prefix
  wouldn't be self-delimiting there either — multiplexing is UDP-only
  regardless, which matches multiplex-peer.)

### Trust note

Logical peers sharing one IP:port are an inherently cooperating group; a
misbehaving member can spoof another's mux-id. The mux-id is a **routing** tag,
not an **authentication** token. The per-IP permission check is still enforced
on ingress, so an unpermitted peer IP is still dropped.

---

## Architecture: Where State Lives

All tagging state lives in `ioa_engine_t`, per relay thread, with **no globals
and no mutexes** — same model as multiplex-peer
([ns_ioalib_impl.h](../src/apps/relay/ns_ioalib_impl.h)):

```c
int       mp_tag_enabled;   // 1 when --multiplex-peer-tag is active
uint32_t  mp_next_mux_id;   // monotonic per-engine id allocator (starts at 1)
ur_map   *mp_mux_table;     // mux_id -> ts_ur_super_session*; O(1) get/put/del
```

Each session stores its own id ([ns_turn_session.h](../src/server/ns_turn_session.h)):

```c
uint32_t  mux_id;           // 0 = unassigned
```

Because a session is pinned to one relay thread for its lifetime, ids are
allocated from that thread's engine counter and are unique within the only
shared socket that ever carries the session's traffic. Single-threaded per
engine ⇒ no locking.

---

## Data Flow

### Allocation / first registration (id assignment)

When a session first registers a peer on the shared relay socket
(`register_multiplex_peer`, [ns_turn_server.c:408](../src/server/ns_turn_server.c)):

```
register_multiplex_peer(server, ss, peer_addr)
  └─ tagging on?
       ├─ yes → assign ss->mux_id = mp_assign_mux_id(e, ss)   // mux_id -> ss in mp_mux_table
       │        (no peer-addr registration, no collision check — that's the point)
       └─ no  → mp_register_peer(e, peer_addr, ss)            // legacy peer-addr keyed mp_table
```

`mp_assign_mux_id` ([ns_ioalib_engine_impl.c:1494](../src/apps/relay/ns_ioalib_engine_impl.c))
hands out the next free id, skipping the reserved `0` on wraparound.

### Client → peer (egress, append trailer)

Both peer-bound send paths append the trailer just before handing the buffer to
the relay socket, via `mp_tag_append_egress`
([ns_turn_server.c:447](../src/server/ns_turn_server.c)):

```
handle_turn_send()       (Send indication)  → mp_tag_append_egress(...)  [ns_turn_server.c:3186]
write_to_peerchannel()   (ChannelData)      → mp_tag_append_egress(...)  [ns_turn_server.c:4270]
       └─ no-op unless tagging is on, the relay socket IS the shared mp socket,
          and ss->mux_id != 0
       └─ multiplex_peer_tag_append(buf, &len, cap, ss->mux_id); set_size(len)
```

### Peer → client (ingress, strip trailer + route by id)

```
mp_relay_input_handler(shared_sock, data)   [ns_ioalib_engine_impl.c:1301]
  └─ tagging on?
       ├─ yes → multiplex_peer_tag_strip(buf, &sz, &mux_id); set_size(sz)
       │        ss = mp_lookup_mux_id(e, mux_id)        // route by id, not addr
       │        drop if no session maps to the id
       └─ no  → ur_addr_map_get(mp_table, src_addr)     // legacy peer-addr lookup
  └─ verify allocation still has permission for the peer IP
  └─ turn_peer_input_handler(...)   // normal relay-to-client path; client sees no trailer
```

### Session teardown

Alongside the existing multiplex-peer cleanup, the session's id is removed from
the engine map ([ns_turn_server.c:4370](../src/server/ns_turn_server.c)):

```
shutdown_client_connection()
  ├─ mp_deregister_session_peers(e, ss, 0)           // legacy mp_table entries
  ├─ mp_deregister_mux_id(e, ss->mux_id); ss->mux_id = 0   // tagging
  └─ null relay-socket pointers so the shared fd is not closed
```

---

## The Peer Side (`turnutils_peer -M`)

A multiplexing peer binds **one** UDP socket and represents many logical
endpoints on it. `turnutils_peer` is an echo server, so for tagging it:

- parses the trailing 4 bytes of each datagram as the mux-id
  (`peer_mux_account`, [udpserver.c:58](../src/apps/peer/udpserver.c)),
- accounts the distinct ids it has seen and logs each new one
  ("multiplex: new logical peer mux-id=… (distinct=…) on shared port"),
- echoes the **whole** datagram unchanged, so the trailer round-trips back to
  the relay.

The accounting runs in both the Linux `recvmmsg`/GSO batch path
([udpserver.c:207](../src/apps/peer/udpserver.c)) and the portable
`recvfrom`/`sendto` path ([udpserver.c:264](../src/apps/peer/udpserver.c)); it
reads the trailer without mutating the buffer, so echo behaviour is identical to
non-multiplex mode. A real multiplexing peer would instead strip the trailer,
route the payload to logical endpoint `mux-id`, and re-attach the id on the
response.

> GSO note: a per-datagram trailer does not break the peer's GSO echo
> homogeneity predicate (equal source and segment size), same as a prefix would
> not. It does cost 4 bytes of effective payload MTU, like any framing.

---

## Files Changed

| File | What changes |
|------|-------------|
| `src/apps/relay/multiplex_peer_tag.h` | **New.** Dependency-free trailer codec (`multiplex_peer_tag_append` / `_strip`), `MULTIPLEX_PEER_TAG_SIZE`, `MULTIPLEX_PEER_TAG_NONE`. Header-only so it is unit-testable in isolation. |
| `src/apps/relay/ns_ioalib_impl.h` | `mp_tag_enabled`, `mp_next_mux_id`, `mp_mux_table` on `ioa_engine_t`; new `tag_enabled` param on `init_multiplex_peer`; declarations for `mp_assign_mux_id` / `mp_lookup_mux_id` / `mp_deregister_mux_id`. |
| `src/apps/relay/ns_ioalib_engine_impl.c` | mux-id table init; the three id helpers; the tag branch in `mp_relay_input_handler` (strip + route by id). |
| `src/server/ns_turn_session.h` | `uint32_t mux_id` on the session. |
| `src/server/ns_turn_server.h` | `bool multiplex_peer_tag` on `turn_turnserver`. |
| `src/server/ns_turn_server.c` | Assign id in `register_multiplex_peer`; `mp_tag_append_egress` and its two call sites; deregister id on teardown. |
| `src/apps/relay/mainrelay.h` / `mainrelay.c` | `--multiplex-peer-tag` CLI flag, help text, and startup validation (requires `--multiplex-peer`). |
| `src/apps/relay/netengine.c` | Propagate the flag into the engine and `turn_turnserver`. |
| `src/apps/peer/udpserver.{h,c}` / `mainudpserver.c` | `turnutils_peer -M` flag and trailer accounting. |
| `tests/test_multiplex_tag.c` + `tests/CMakeLists.txt` | Unity unit test for the codec. |
| `examples/run_tests_multiplex_peer_tag.sh` | End-to-end positive/negative system test. |

---

## CLI Usage

```bash
# turnserver: tagging requires multiplex-peer
turnserver \
  --listening-ip=203.0.113.1 --relay-ip=203.0.113.1 \
  --multiplex-peer --multiplex-peer-port=3480 \
  --multiplex-peer-tag \
  --lt-cred-mech --realm=example.com

# peer: single-port multiplex mode (listen OUTSIDE the relay port range)
turnutils_peer -M -p 4000 -L 203.0.113.9 -v
```

Startup validation rejects `--multiplex-peer-tag` without `--multiplex-peer`:

```
CONFIG ERROR: --multiplex-peer-tag requires --multiplex-peer.
```

> The peer's listen port must NOT fall inside the multiplex-peer relay range
> `[base .. base + 2*threads - 1]`, or the peer and a relay socket will fight
> over the same port.

---

## Testing

### Unit (codec) — portable

[tests/test_multiplex_tag.c](../tests/test_multiplex_tag.c) pins the trailer
encode/decode: round trip, big-endian byte order, refusal on unassigned id and
on missing tailroom, rejection of short datagrams, zero-payload and max-id
cases, and NULL-arg safety.

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target test_multiplex_tag
ctest --test-dir build -R test_multiplex_tag --output-on-failure
```

### End-to-end (positive + negative control) — Linux only

[examples/run_tests_multiplex_peer_tag.sh](../examples/run_tests_multiplex_peer_tag.sh)
pins the server to 2 relay threads (`--cpus=2`) and drives 4 concurrent sessions
to **one** shared peer IP:port. By pigeonhole at least two sessions land on the
same relay thread / `mp_table`, so the contrast is deterministic:

| Phase | Expectation |
|-------|-------------|
| tag **OFF** (plain `--multiplex-peer`) | server rejects the colliding same-peer registration (≥1 `400`); the workload fails. |
| tag **ON** (`--multiplex-peer-tag`) | zero rejections; `tot_send_bytes == tot_recv_bytes` (every byte relayed back to the right session). |

The identical workload that the server rejects without tagging succeeds with it.
On non-Linux platforms the script SKIPs (multiplex-peer is Linux-only).

```bash
cd examples && ./run_tests_multiplex_peer_tag.sh
```

Observed (3-thread-pin run): `tag OFF → collisions_rejected=2, send=0 recv=0`;
`tag ON → collisions_rejected=0, send=40000 recv=40000`.

---

## Limitations & Trade-offs

| Limitation | Detail |
|------------|--------|
| Both ends must opt in | The trailer is a private protocol; an untagged peer would feed garbage trailers to the relay, and an untagged relay would not strip the peer's. Enable `--multiplex-peer-tag` and `turnutils_peer -M` together. |
| UDP-only | The trailer is located via the datagram length; TCP/TLS relay legs have no message boundary. |
| Routing tag ≠ auth | A cooperating peer group can spoof each other's mux-id; the per-IP permission check still applies. |
| −4 bytes MTU | Each datagram carries a 4-byte trailer, like any added framing. |
| Requires `--multiplex-peer` | Tagging has no meaning without the shared relay socket; enforced at startup. |
| 2³² ids per relay thread | Far beyond any real concurrent-session count; the allocator skips the reserved `0` on wraparound. |
```
