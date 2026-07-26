# RFC 3489 ("classic" STUN) deprecation

This document records why coturn's RFC 3489 support is being retired, what
changed in the first step, how to migrate, and what the second step will
remove. It is the reference for operators who currently enable classic-STUN
handling and for maintainers implementing the removal.

## Why

[RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489) is the original 2003
STUN specification. Its message header is:

    type (2) | length (2) | transaction ID (16)

[RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) (2008) carved the
first 32 bits of that transaction ID into a fixed magic cookie,
`0x2112A442`, leaving a 96-bit transaction ID. That single change is what
separates the two dialects on the wire, and it drives everything else: a
classic-STUN message is recognized precisely by *not* carrying the cookie, and
its response must echo the caller's original 32 bits verbatim, because to that
client those bytes are part of its transaction ID.

RFC 5389 deprecated the RFC 3489 mechanisms outright.
[RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) (2020), which
obsoletes RFC 5389, dropped the backward-compatibility language entirely.
WebRTC has never used classic STUN. The remaining population is a small tail of
legacy SIP hardphones, ATAs, and pre-WebRTC softphone stacks.

## The flag split

Historically a single option, `--stun-backward-compatibility`, controlled two
unrelated behaviors:

1. accepting RFC 3489 Binding requests, and
2. adding the deprecated `MAPPED-ADDRESS` attribute to *modern* RFC 5389
   Binding responses, alongside `XOR-MAPPED-ADDRESS`.

Only (1) is obsolete. (2) serves clients that speak RFC 5389 correctly but
cannot parse `XOR-MAPPED-ADDRESS`, and (2) is what the amplification warning in
`turnserver.conf` is actually about — the extra attribute widens every Binding
response, raising the gain factor available to a reflection attack.

Because the two rode one flag, retiring classic STUN by deleting that flag
would have silently removed (2) as well. So they were separated:

| Option | Controls | Status |
|---|---|---|
| `--stun-backward-compatibility` | `MAPPED-ADDRESS` on modern responses | supported |
| `--rfc3489-compatibility` | RFC 3489 request handling | **deprecated**, removal in next major |

Both default to off. A server that sets neither is unaffected by any of this.

`--rfc3489-compatibility` logs a warning at startup naming the removal release.
It also warns when it is set together with `--no-stun`, where it has no effect.

### Behavior matrix

Address attributes in the Binding response, by flag combination:

| Flags | Modern (RFC 5389) request | Classic (cookie-less) request |
|---|---|---|
| none (default) | `XOR-MAPPED-ADDRESS` | no response |
| `--stun-backward-compatibility` | `XOR-MAPPED-ADDRESS` + `MAPPED-ADDRESS` | no response |
| `--rfc3489-compatibility` | `XOR-MAPPED-ADDRESS` | `MAPPED-ADDRESS`, cookie echoed |
| both | `XOR-MAPPED-ADDRESS` + `MAPPED-ADDRESS` | `MAPPED-ADDRESS`, cookie echoed |

`MAPPED-ADDRESS` is the only address attribute RFC 3489 defines, so the
classic-STUN path always emits it regardless of
`--stun-backward-compatibility`; there is no `XOR-MAPPED-ADDRESS` in that
dialect to fall back on. On the modern path the attribute stays opt-in,
precisely because of the amplification cost.

## Migrating

Before the split, `--stun-backward-compatibility` enabled both behaviors.
Pick the row that matches why you set it:

- **You needed classic-STUN clients served** → set `--rfc3489-compatibility`.
- **You needed `MAPPED-ADDRESS` for modern clients** → keep
  `--stun-backward-compatibility` unchanged.
- **You are unsure, or need the exact previous behavior** → set both. This
  reproduces the old single-flag semantics precisely.

The same names work as config-file keys, without the leading dashes.

Since `--rfc3489-compatibility` is going away, treat "set both" as a temporary
position and work out which half you actually need.

### Do you still need it?

Classic-STUN requests are only answered when the option is on, so the cheapest
test is to turn it off and watch for clients that stop working.

To identify them beforehand, run with `--verbose --log-binding`: a served
classic-STUN Binding is logged as `OLD BINDING` (this needs *both* options —
`--verbose` alone will not show it). `--verbose` on its own additionally
reports the error and reject paths: `OLD STUN message` when a classic request
is answered with an error, `OLD STUN method ... ignored` for a non-Binding
classic method, and `Wrong OLD STUN message received` for a classic message
that is not a request.

If you find you still depend on classic STUN, please report the use case
upstream — the removal timeline is driven by whether anyone does.

## What is *not* affected

Two things are easy to conflate with this deprecation and are staying:

- **RFC 5780 NAT behavior discovery.** The `CHANGE-REQUEST` attribute (0x0003)
  is shared between RFC 3489 and
  [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780); `--rfc5780` is
  unaffected. Only the classic spelling of the reply
  (`SOURCE-ADDRESS` / `CHANGED-ADDRESS`) goes away, in favour of
  `RESPONSE-ORIGIN` / `OTHER-ADDRESS`.
- **`MAPPED-ADDRESS` on modern responses**, which remains available under
  `--stun-backward-compatibility`.

## Removal roadmap

### Step 1 — split and deprecate (done)

Introduce `--rfc3489-compatibility`, narrow `--stun-backward-compatibility` to
the modern-response behavior, emit a startup deprecation warning, and update
the shipped documentation. No default behavior changes.

### Step 2 — delete (next major release)

Because the flag can no longer be enabled, the classic-STUN code becomes
unreachable and comes out wholesale — roughly 300 lines:

| Location | What goes |
|---|---|
| [ns_turn_server.c](../src/server/ns_turn_server.c) | `handle_old_stun_command()`, its dispatch branch in `read_client_connection()`, and the `old_stun` parameter of `handle_turn_binding()` with its branches |
| [ns_turn_msg.c](../src/client/ns_turn_msg.c) | `old_stun_is_command_message_str()`, `old_stun_init_command_str()`, `old_stun_init_success_response_str()`, `old_stun_init_error_response_str()`, and the `cookie` / `old_stun` parameters of `stun_set_binding_response_str()` |
| [ns_turn_msg_defs.h](../src/client/ns_turn_msg_defs.h) | the `OLD_STUN_ATTRIBUTE_*` macros — all except `PASSWORD`, see below |
| [dtls_listener.c](../src/apps/relay/dtls_listener.c) | `UDP_PACKET_CLASS_OLD_STUN` and its classifier branch |
| [mainrelay.c](../src/apps/relay/mainrelay.c) | the option itself |
| `fuzzing/`, `tests/` | the classic-STUN harness and test cases |

Two details for whoever does this:

- **Keep `OLD_STUN_ATTRIBUTE_PASSWORD` (0x0007).** It is handled as a skipped
  attribute in `handle_turn_binding()` so that a modern client which
  gratuitously includes it is not answered `420 Unknown Attribute`. Deleting
  that case turns tolerated-and-ignored into a hard error.
- **This is an API break, which is why it needs a major version.** The
  `old_stun_*` functions and `OLD_STUN_ATTRIBUTE_*` macros are declared in
  `src/client/ns_turn_msg.h` and `ns_turn_msg_defs.h`, which the autotools
  build copies into `include/turn/client/` and installs alongside
  `lib/libturnclient.a` (see [Makefile.in](../Makefile.in)). Third-party code
  linking `libturnclient` will fail to compile. The `stun_set_binding_response_str()`
  signature change hits the same audience.

After removal, a cookie-less datagram is classified `UDP_PACKET_CLASS_INVALID`
and therefore covered by `--drop-invalid-packets`, which is the desired end
state.
