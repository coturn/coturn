# RFC 8016 Mobility Conformance

This document describes coturn's implementation of TURN mobility
([RFC 8016](https://datatracker.ietf.org/doc/html/rfc8016), "Mobility with
Traversal Using Relays around NAT (TURN)"), the gaps between the historical
coturn behavior and the RFC, and the changes made to close them.

Mobility is enabled with `--mobility` (config `mobility`) and is off by
default.

## Background

RFC 8016 lets a TURN client keep an allocation alive when its client-side
transport address (IP and/or port — the "5-tuple") changes, e.g. when a
mobile device roams between networks. Without mobility the client would have
to re-`ALLOCATE` and re-install every permission and channel. With mobility
the server issues an opaque `MOBILITY-TICKET`; after a network change the
client presents the ticket in a `REFRESH` from its new address and the server
moves the existing allocation to the new client path.

## Protocol summary (RFC 8016)

| Phase | Behavior |
|---|---|
| Allocate | Client sends a **zero-length** `MOBILITY-TICKET` to request mobility. Server marks the allocation mobile and returns a ticket in the success response. |
| Refresh (no move) | Client MUST NOT include `MOBILITY-TICKET`. |
| Refresh (after move) | Client sends the ticket from its new 5-tuple. Server looks the allocation up **by ticket**, not by packet 5-tuple. |
| Authorization | Server MUST run MESSAGE-INTEGRITY to confirm the resume comes from **the same user that created the allocation**; otherwise reject with **441**. |
| Handoff | Server updates state with the new address but **does not discard the old 5-tuple**. It **MUST keep receiving on** and **transmitting to** the old 5-tuple until it sees a `Send`/`ChannelData` from the client on the **new** 5-tuple (or a close), then discards the old 5-tuple/ticket and moves relay egress to the new path. |
| Ticket rotation | The ticket returned in the Refresh success response MUST differ from the old one. |

## Gap analysis (pre-change coturn)

| RFC item | Historical coturn | Status |
|---|---|---|
| Zero-length ticket requests mobility; non-zero → 400 | Implemented | ✅ |
| 405 when mobility disabled | Implemented | ✅ |
| Look up allocation by ticket | `get_session_from_mobile_map()` | ✅ |
| Resume authorized as the **original owner** (441 on mismatch) | Adopted original creds only when the resuming session was unauthenticated; an already-authenticated session was validated against its own identity | ❌ fixed separately (owner-binding fix) |
| Ticket differs on rotation | id is zeroed then regenerated on resume | ✅ |
| **Graceful dual-5-tuple handoff** | **Immediate hard switch at Refresh time; old socket closed at once** | ❌ **this change** |
| Unknown ticket → **437** | Returned **404** | ❌ **this change** |
| Ticket "strong entropy / authenticated + encrypted" | 56-bit random handle (8-bit server-id prefix), cleartext on non-TLS | ⚠️ see "Ticket hardening" |

## Change 1 — Graceful dual-5-tuple handoff

### Design

coturn's session model gives each `ts_ur_super_session` a single
`client_socket`. Rather than merge the resuming socket into the original
allocation immediately (the old behavior), the resume now enters a bounded
**transition** in which both client paths exist:

- The **original** session (`orig_ss`) keeps its allocation and its old
  `client_socket`. Peer→client relayed traffic keeps flowing to the **old**
  5-tuple, satisfying "MUST continue transmitting on the old 5-tuple."
- The **resuming** session (`ss`, on the new 5-tuple) is kept alive and
  linked to `orig_ss` as a *pending mobile resume* instead of being torn
  down. The old path keeps being received and processed on `orig_ss` (which
  still owns the allocation), satisfying "MUST continue receiving on the old
  5-tuple"; the new path's first packet is what promotes the allocation onto
  it (see below).
- The Refresh success response (carrying the **new**, rotated ticket) is sent
  on the new socket.

The transition ends in one of two ways:

1. **Promote (the client shows up on the new path).** The client's **first
   packet** on the new 5-tuple completes the handoff: the new socket is moved
   onto the allocation session (`attach_socket_to_session`), which closes the
   old client socket and thereby discards the old 5-tuple; the packet is then
   processed against the allocation. Peer→client egress reverts to the new
   socket from this point.

   RFC 8016 names the trigger as the client's first `Send`/`ChannelData` on the
   new path. coturn promotes on the first packet of **any** type, because
   control requests a roaming client issues from the new address
   (`CreatePermission`, `ChannelBind`, a subsequent `Refresh`) must be served by
   the allocation, not by the allocation-less pending session. The
   make-before-break guarantee that matters — that relayed peer→client data
   keeps flowing to the old path across the handoff gap — is preserved: egress
   stays on the old socket for the whole interval between the Refresh response
   and that first new-path packet.

2. **Abort (the client never shows up).** If the transition stays open past a
   bounded deadline (`MOBILITY_TRANSITION_TIMEOUT`, 30 s) with no packet on the
   new path, the per-session sweep abandons it: the allocation stays on the
   original/old path and the pending session is reaped. This is the
   conservative choice (keep the last known-good path); a client that really
   moved will have sent on the new path — and thus promoted — long before the
   deadline, and can always re-`Refresh` to reopen a transition.

Promotion reuses the original socket-transfer logic, factored into
`mobile_complete_transition()`.

### State (added to `ts_ur_super_session`)

- `mobile_resume_target` — on the pending session: id of the allocation session,
- `mobile_pending_resume` — on the allocation session: id of the pending session,
- `mobile_transition_deadline` — on the allocation session: abort-by time.

Session **ids** (not pointers) are stored so a session freed mid-transition
never leaves a dangling reference; `shutdown_client_connection()` also unlinks a
transition partner when either side is torn down.

### Helpers (`ns_turn_server.c`, near `handle_turn_refresh`)

- `mobile_begin_transition()` — links the two sessions, sets the deadline,
  removes the pending session's stray mobile-map entry, and disarms its
  un-allocated watchdog so it is not reaped while it legitimately holds no
  allocation.
- `mobile_complete_transition()` — promotes (moves the socket, closes the old
  one, tears down the pending session) and returns the allocation session.
- `mobile_abort_transition()` — clears the link and reaps the pending session,
  keeping the allocation on the old path.

### Interception points

- `read_client_connection()` — before normal processing, if the receiving
  session is a pending resume, promote and continue as the allocation session.
- `sweep_session_cb()` (the 1 s per-session tick) — abort transitions past the
  deadline. It only sets `to_be_closed` / clears links, so it is safe during map
  iteration.

### Note on quota

During the (sub-second in practice, ≤30 s worst case) transition both sessions
hold one quota unit for the same user; the pending session's unit is released
when it is torn down at promotion/abort. This transient over-count is bounded by
the deadline and is not persistent.

## Change 2 — Error-code conformance

- Unknown/stale ticket on resume now returns **437 (Allocation Mismatch)**, as
  required by RFC 8016, instead of the previous non-standard 404.
- Wrong-user resume returns **441 (Wrong Credentials)** — this follows from the
  owner-binding fix: the resuming request's `USERNAME` is compared against the
  adopted original owner and mismatches yield 441.

## Ticket hardening (design note)

The RFC requires the ticket to have "strong entropy" and to be "authenticated
and encrypted." coturn's ticket is an **opaque, stateless-to-the-client random
handle** into a server-side map — it carries no server state, so "modification"
is a non-issue (a tampered value simply misses the map) and the residual risk
is eavesdropping, which is addressed by (a) running mobility over `turns:` and
(b) the owner-binding credential re-check. The remaining letter-of-the-RFC gap
is entropy: the id is 64 bits with an 8-bit server-routing prefix, i.e. 56
random bits.

Raising this to a 128-bit ticket is specified but **not** bundled here because
the mobile id is also passed **between coturn processes** as a 64-bit value on
the cross-server resume path (`send_socket_to_relay` / `RMT_MOBILE_SOCKET`);
widening it changes that inter-process wire format and, for true "encryption,"
would require a cluster-shared key that coturn does not currently manage. It is
tracked as a separate hardening item to avoid coupling a wire-format/key-mgmt
change to the protocol-behavior work here.

## Testing

`examples/run_tests_mobile.sh` starts the server with `--mobility` and drives
`turnutils_uclient -M` (UDP/TCP, legacy and threaded worker pools). The `-M`
flow allocates, obtains a ticket, reopens on a fresh 5-tuple, and resumes with a
`REFRESH` — so every run exercises the new path end-to-end: `handle_turn_refresh`
opens a transition (`mobile_begin_transition`) and the client's next packet on
the new socket drives `mobile_complete_transition`.

The script then asserts, from the server log, that the handoff actually
executed — it greps for the `mobility handoff completed` marker emitted by
`mobile_complete_transition()`. This distinguishes "the transition machinery
ran and promoted the allocation" from merely "a resume response was returned,"
so a regression that skipped or broke the handoff fails the test rather than
silently falling back.

The transition helpers are tightly coupled to the live IO engine, sockets, and
session maps, so they are validated at this integration level rather than as
isolated unit tests. The suite is wired into the Linux CI workflows alongside
the other `run_tests_*` scripts.

An end-to-end assertion of the *make-before-break* property specifically (that
peer→client data keeps arriving on the old 5-tuple during the transition window)
would require a custom client that holds both 5-tuples open simultaneously;
`turnutils_uclient` closes/reopens instead, so that aspect is covered by design
review rather than an automated assertion. This is called out here so the gap is
explicit.
