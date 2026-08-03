#!/usr/bin/env python3
# Mobility quota-bypass regression driver (see examples/run_tests_mobility_quota.sh).
#
# GHSA-f6hc-79w3-p8pq: under --mobility a client could create a mobility-enabled
# allocation over TCP and immediately disconnect. The first-stage mobility close
# kept the allocation and its relay port but released the user/total quota
# charge, so repeating the sequence held many live allocations past
# --user-quota / --total-quota until the relay port pool was exhausted (508).
#
# This driver runs two checks against a server started with
# --user-quota=1 --total-quota=1 --mobility:
#   * flood:  Allocate(+MOBILITY, UDP relay) over TCP then disconnect, repeated.
#             A fixed server admits exactly one and rejects the next with 486;
#             a vulnerable server admits many until 508 port exhaustion.
#   * resume: the legitimate mobility flow (allocate, disconnect, resume from a
#             fresh 5-tuple via REFRESH+MOBILITY-TICKET) must still succeed under
#             quota=1 — the fix must not double-charge the resuming session.
#
# Raw STUN over the standard library only (no coturn client dependency), so the
# test can drive the exact abuse pattern turnutils_uclient does not model.

import hashlib
import hmac
import os
import socket
import struct
import sys
import time

MAGIC = 0x2112A442
M_ALLOCATE = 0x0003
M_REFRESH = 0x0004
ALLOCATE_OK = 0x0103
REFRESH_OK = 0x0104

A_USERNAME = 0x0006
A_MI = 0x0008
A_ERROR = 0x0009
A_LIFETIME = 0x000D
A_REALM = 0x0014
A_NONCE = 0x0015
A_REQ_TRANSPORT = 0x0019
A_MOBILITY = 0x8030

# REQUESTED-TRANSPORT UDP (17): a UDP relay requested over a TCP control channel,
# matching the advisory PoC. The client disconnect is the TCP control close.
UDP_RELAY = b"\x11\0\0\0"


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * ((-len(v)) & 3)


def parse(msg):
    typ, ln, _magic, _tid = struct.unpack("!HHI12s", msg[:20])
    out = []
    p = 20
    while p + 4 <= min(len(msg), 20 + ln):
        t, n = struct.unpack("!HH", msg[p : p + 4])
        out.append((t, msg[p + 4 : p + 4 + n]))
        p += 4 + n + ((-n) & 3)
    return typ, out


def get(attrs, t):
    for k, v in attrs:
        if k == t:
            return v
    return None


def make(typ, attrs, key=None):
    tid = os.urandom(12)
    body = b"".join(attr(t, v) for t, v in attrs)
    if key is not None:
        # RFC 5389: length in the header used for the HMAC includes the
        # MESSAGE-INTEGRITY TLV (24 bytes) but the HMAC input stops before it.
        hdr = struct.pack("!HHI12s", typ, len(body) + 24, MAGIC, tid)
        mac = hmac.new(key, hdr + body, hashlib.sha1).digest()
        body += attr(A_MI, mac)
    return struct.pack("!HHI12s", typ, len(body), MAGIC, tid) + body


def recv_stun(sock):
    hdr = b""
    while len(hdr) < 20:
        chunk = sock.recv(20 - len(hdr))
        if not chunk:
            raise RuntimeError("connection closed before STUN header")
        hdr += chunk
    ln = struct.unpack("!H", hdr[2:4])[0]
    body = b""
    while len(body) < ln:
        chunk = sock.recv(ln - len(body))
        if not chunk:
            raise RuntimeError("connection closed before STUN body")
        body += chunk
    return hdr + body


def xact(sock, msg):
    sock.sendall(msg)
    return recv_stun(sock)


def errcode(attrs):
    v = get(attrs, A_ERROR)
    if not v or len(v) < 4:
        return None
    return (v[2] & 7) * 100 + v[3]


def challenge(sock, msg_type, extra):
    _typ, aa = parse(xact(sock, make(msg_type, extra)))
    return get(aa, A_REALM), get(aa, A_NONCE)


def allocate_then_disconnect(host, port, user, password):
    """Allocate(+MOBILITY, UDP relay) over TCP, then close the TCP control
    connection (the first-stage mobility close). Returns (ticket, err)."""
    sock = socket.create_connection((host, port), timeout=3)
    realm, nonce = challenge(sock, M_ALLOCATE, [(A_REQ_TRANSPORT, UDP_RELAY), (A_MOBILITY, b"")])
    if not realm or not nonce:
        sock.close()
        raise RuntimeError("server did not return a realm and nonce")
    key = hashlib.md5(user + b":" + realm + b":" + password).digest()
    typ, aa = parse(xact(sock, make(M_ALLOCATE, [
        (A_USERNAME, user), (A_REALM, realm), (A_NONCE, nonce),
        (A_REQ_TRANSPORT, UDP_RELAY), (A_MOBILITY, b""),
    ], key)))
    ticket = get(aa, A_MOBILITY)
    sock.close()
    if typ != ALLOCATE_OK:
        return None, errcode(aa)
    return ticket, None


def resume(host, port, user, password, ticket):
    sock = socket.create_connection((host, port), timeout=3)
    realm, nonce = challenge(sock, M_REFRESH, [(A_MOBILITY, ticket), (A_LIFETIME, struct.pack("!I", 600))])
    if not realm or not nonce:
        sock.close()
        return None
    key = hashlib.md5(user + b":" + realm + b":" + password).digest()
    typ, aa = parse(xact(sock, make(M_REFRESH, [
        (A_MOBILITY, ticket), (A_LIFETIME, struct.pack("!I", 600)),
        (A_USERNAME, user), (A_REALM, realm), (A_NONCE, nonce),
    ], key)))
    sock.close()
    return None if typ == REFRESH_OK else (errcode(aa) or -1)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    user = (sys.argv[3] if len(sys.argv) > 3 else "user").encode()
    password = (sys.argv[4] if len(sys.argv) > 4 else "pass").encode()
    attempts = int(sys.argv[5] if len(sys.argv) > 5 else 8)

    # First mobility allocation over TCP; capture its ticket, then disconnect
    # (first-stage mobility close). On a fixed server this allocation stays
    # charged against quota=1 across the disconnect and remains resumable.
    ticket, err = allocate_then_disconnect(host, port, user, password)
    if err is not None or not ticket:
        print(f"RESULT flood_accepted=0 flood_reject={err} resume=FAIL:alloc:{err}")
        return 1
    accepted = 1

    # Flood: more allocate-then-disconnect cycles. A fixed server rejects each
    # with 486 (the first allocation still holds the only quota unit); a
    # vulnerable server admits them until the relay port pool is exhausted (508).
    reject = None
    for _ in range(attempts - 1):
        time.sleep(0.08)
        _t, e = allocate_then_disconnect(host, port, user, password)
        if e is not None:
            reject = e
            break
        accepted += 1

    # Legitimate resume of the still-held first allocation must succeed under
    # quota=1: it reuses the existing allocation's quota unit, so the fix must
    # not charge the resuming session a second one.
    r = resume(host, port, user, password, ticket)
    resume_str = "OK" if r is None else f"FAIL:{r}"
    print(f"RESULT flood_accepted={accepted} flood_reject={reject} resume={resume_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
