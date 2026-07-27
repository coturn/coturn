#!/usr/bin/env python3
# Chained-mobility-resume load driver for the RFC 8016 handoff regression test
# (see examples/run_tests_mobility_resume_flood.sh).
#
# Allocates one mobility-enabled TURN allocation, then repeatedly resumes it
# from fresh UDP 5-tuples WITHOUT ever completing a handoff (it never sends a
# Send/ChannelData on the new path). Each accepted resume opens a new pending
# transition. A server that does not bound pending resumes per allocation
# accumulates one orphaned server-side session per resume; a fixed server tears
# down the superseded pending on every subsequent resume, so the live session
# count stays bounded.
#
# Raw STUN over the standard library only (no coturn client dependency), so the
# test can drive the exact abuse pattern turnutils_uclient does not model.

import hashlib
import hmac
import os
import socket
import struct
import sys

MAGIC = 0x2112A442
M_ALLOCATE = 0x0003
M_REFRESH = 0x0004
ALLOCATE_OK = 0x0103
REFRESH_OK = 0x0104

A_USERNAME = 0x0006
A_MI = 0x0008
A_ERROR = 0x0009
A_REALM = 0x0014
A_NONCE = 0x0015
A_REQ_TRANSPORT = 0x0019
A_MOBILITY = 0x8030
A_LIFETIME = 0x000D


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


def xact(sock, msg, host, port):
    sock.sendto(msg, (host, port))
    return sock.recvfrom(4096)[0]


def errcode(attrs):
    v = get(attrs, A_ERROR)
    if not v or len(v) < 4:
        return None
    return (v[2] & 7) * 100 + v[3]


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    user = (sys.argv[3] if len(sys.argv) > 3 else "user").encode()
    password = (sys.argv[4] if len(sys.argv) > 4 else "pass").encode()
    count = int(sys.argv[5] if len(sys.argv) > 5 else 100)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    # Unauthenticated Allocate to obtain the realm/nonce challenge.
    typ, aa = parse(xact(s, make(M_ALLOCATE, [(A_REQ_TRANSPORT, b"\x11\0\0\0"), (A_MOBILITY, b"")]), host, port))
    realm = get(aa, A_REALM)
    nonce = get(aa, A_NONCE)
    if not realm or not nonce:
        print(f"FAIL: no challenge (type={typ:#x} err={errcode(aa)})")
        return 2

    key = hashlib.md5(user + b":" + realm + b":" + password).digest()
    req = [
        (A_USERNAME, user),
        (A_REALM, realm),
        (A_NONCE, nonce),
        (A_REQ_TRANSPORT, b"\x11\0\0\0"),
        (A_MOBILITY, b""),
    ]
    typ, aa = parse(xact(s, make(M_ALLOCATE, req, key), host, port))
    ticket = get(aa, A_MOBILITY)
    if typ != ALLOCATE_OK or not ticket:
        print(f"FAIL: allocate rejected (type={typ:#x} err={errcode(aa)})")
        return 2

    held = []
    for i in range(count):
        q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        q.settimeout(3)
        attrs = [
            (A_USERNAME, user),
            (A_REALM, realm),
            (A_NONCE, nonce),
            (A_LIFETIME, struct.pack("!I", 600)),
            (A_MOBILITY, ticket),
        ]
        typ, aa = parse(xact(q, make(M_REFRESH, attrs, key), host, port))
        nt = get(aa, A_MOBILITY)
        if typ != REFRESH_OK or not nt:
            print(f"FAIL: resume {i} rejected (type={typ:#x} err={errcode(aa)})")
            return 2
        held.append(q)  # keep the client socket open (never complete the handoff)
        ticket = nt

    print(f"RESULT resumes={len(held)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
