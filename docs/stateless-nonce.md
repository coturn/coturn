# Stateless nonce mode (`--stateless-nonce`)

This document describes the stateless challenge-nonce mode added for
[issue #1999](https://github.com/coturn/coturn/issues/1999). It covers the
attack it defends against, how it works, why it is wire-compatible with
standard TURN clients, and its known limitations.

## Why

TURN long-term authentication is a challenge/response flow: the first request
arrives without valid credentials and the server answers `401 Unauthorized`
with a `REALM` and a `NONCE`; the client retries with credentials derived
from them. The server must later recognize the nonce it handed out — and the
stock implementation does that by *storing* a random nonce in per-client
session state.

That storage is the problem on UDP. Early packet validation
(`--drop-invalid-packets`, PR #1768) discards malformed floods cheaply, but a
*structurally valid* STUN Allocate from a spoofed source still commits real
resources before any authentication:

- a child UDP socket in the listener's address map,
- an ~18KB `ts_ur_super_session`, allocated just to hold the nonce,
- a to-be-allocated timer that keeps both alive for 60 seconds
  (`TURN_MAX_ALLOCATE_TIMEOUT`).

At 10k spoofed packets/s that is hundreds of thousands of live sessions —
multiple GB of memory — from traffic that never authenticates.
`--unauthorized-ratelimit` (see [401-ratelimit.md](401-ratelimit.md))
suppresses the 401 *responses* (reflection defense) but the state has already
been allocated by the time it runs, so it does not bound memory.

## What it does

With `--stateless-nonce` the challenge nonce is no longer random per session;
it is derived:

```
nonce = hex( HMAC-SHA256( K, "<client-ip>:<port>|<window>" ) )[0..15]
window = now / nonce-lifetime      (lifetime = --stale-nonce, or 600s if unset)
```

`K` is a random 256-bit key generated once at process startup
(`turn_params.stateless_nonce_key`) and shared by every listener and relay
thread. Because the server can *recompute* the nonce, three things become
possible:

1. **Listener fast path** (`udp_stateless_nonce_fast_path` in
   `dtls_listener.c`): a MESSAGE-INTEGRITY-less request from an unknown UDP
   source is answered with the 401 challenge directly from the listener — no
   child socket, no session. Packets the relay would silently ignore for a
   fresh source (indications, unbound channel data, STUN that fails the full
   check) are dropped with no state either. The `--unauthorized-ratelimit`
   response suppression and the Prometheus 401 counters apply to this path
   exactly as they do to the session path.
2. **Fresh-session nonce acceptance** (`check_stun_auth` in
   `ns_turn_server.c`): when the client's authenticated retry arrives, the
   brand-new session accepts a presented nonce that derives correctly for the
   current window or an adjacent one (window ± 1, covering challenges issued
   just before a window roll). Without the flag a fresh session rejects any
   presented nonce with `438 Wrong nonce`.
3. **Challenge-session teardown**: a UDP session whose response was only an
   auth challenge (401/438) and that has no allocation is torn down
   immediately after the response is written, instead of lingering for the
   60s to-be-allocated timeout. This is what bounds memory against floods
   that *do* attach a (garbage) MESSAGE-INTEGRITY attribute and therefore
   have to travel the session path.

The result: for MESSAGE-INTEGRITY-less floods the attacker's memory cost is
zero; for garbage-MI floods it is one transient session per packet, freed as
soon as the challenge is sent.

## Wire compatibility

The mode is designed to be invisible to clients:

- The fast-path 401 carries the same attributes in the same order as the
  session path's `create_challenge_response`: error response, `NONCE`,
  `REALM`, `THIRD-PARTY-AUTHORIZATION` (oauth only), `SOFTWARE` (unless
  disabled), `FINGERPRINT` (if the server enforces it or the request used
  one). Realm selection by `ORIGIN` on ALLOCATE is replicated.
- A nonce is opaque to clients; only its *value generation* changed. RFC 8489
  relies on MESSAGE-INTEGRITY over the (random) transaction ID for
  per-request freshness — nonce reuse within its lifetime is already how the
  protocol works, and binding the nonce to the client's address is strictly
  stronger than a stored random nonce (a captured nonce is useless from
  another address).
- Established sessions keep the exact stock stale-nonce behavior: the session
  caches its nonce, `--stale-nonce` expiry regenerates it and answers `438`,
  and the client re-authenticates as usual.
- Cases the fast path cannot replicate byte-for-byte fall back to the session
  path automatically: BINDING (RFC 5780 alternate sockets), ALLOCATE when
  alternate/aux server redirection (300) is configured, REFRESH under
  `--mobility` (MOBILITY-TICKET may authenticate without a first-pass
  challenge), CONNECTION-BIND (exempt from the challenge), and any request
  carrying MESSAGE-INTEGRITY.

`examples/run_tests_stateless_nonce.sh` asserts all of this end-to-end: the
standard client workload must succeed unchanged over UDP/TCP (and TLS/DTLS on
Linux), and the server log must show the fast path actually engaged.

## Limitations

- **Off by default.** Enable with `--stateless-nonce` (config file:
  `stateless-nonce`).
- **Single-process key.** The key lives in process memory. After a restart,
  outstanding nonces stop validating and clients re-authenticate via the
  standard `438` round-trip (the same thing that happens today, since stored
  nonces die with their sessions). In a multi-server deployment behind a UDP
  load balancer, a retry that lands on a *different* server likewise costs
  one extra `438` round-trip. A shared/derived cluster key would remove that
  and is left as future work.
- **Nonce validity is up to ~2 lifetimes.** Accepting window ± 1 means a
  nonce can validate for up to twice `--stale-nonce` (or 2×600s) on a fresh
  session. This is within RFC 8489's stale-nonce intent; established sessions
  still rotate on the configured lifetime.
- **BINDING floods are out of scope.** BINDING is answerable without
  authentication, so an unknown-source BINDING still creates a session (as
  today). `--secure-stun` BINDING challenges do benefit from the
  challenge-session teardown, but not from the listener fast path.
- **TCP/TLS are unchanged.** Those transports cannot be source-spoofed and
  already pin a connection per client; sessions there keep stock behavior
  (the derived nonce is used, which is harmless).
