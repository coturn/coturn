#!/usr/bin/env python3
# Wire probe for the listener-side STUN Binding fast path (see
# examples/run_tests_stateless_binding.sh).
#
# A Binding request from an unknown UDP source is answered by the listener
# itself, so every reply shape has to match what the relay's handle_turn_binding
# would have produced from a session: the success response and its
# XOR-MAPPED-ADDRESS, the 420 UNKNOWN-ATTRIBUTES list, the attributes ICE
# clients attach (USERNAME/PRIORITY/MESSAGE-INTEGRITY/FINGERPRINT are accepted
# without authentication), and the RFC 5780 probes, which must still reach the
# relay because only it owns the alternate sockets.
#
# Usage: stateless_binding_probe.py <host> <port> [mode]
#   mode: wire (default) | silent | challenge | flood <count>

import binascii
import os
import socket
import struct
import sys

MAGIC = 0x2112A442
M_BINDING = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

A_MAPPED = 0x0001
A_CHANGE_REQUEST = 0x0003
A_USERNAME = 0x0006
A_MI = 0x0008
A_ERROR = 0x0009
A_UNKNOWN_ATTRS = 0x000A
A_XOR_MAPPED = 0x0020
A_PRIORITY = 0x0024
A_PADDING = 0x0026
A_RESPONSE_PORT = 0x0027
A_SOFTWARE = 0x8022
A_FINGERPRINT = 0x8028


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * ((-len(v)) & 3)


def make(attrs, tid=None, fingerprint=False):
    body = b"".join(attr(t, v) for t, v in attrs)
    tid = tid or os.urandom(12)
    if fingerprint:
        hdr = struct.pack("!HHI12s", M_BINDING, len(body) + 8, MAGIC, tid)
        crc = (binascii.crc32(hdr + body) & 0xFFFFFFFF) ^ 0x5354554E
        body += attr(A_FINGERPRINT, struct.pack("!I", crc))
    return struct.pack("!HHI12s", M_BINDING, len(body), MAGIC, tid) + body


def parse(msg):
    typ, ln, _magic, tid = struct.unpack("!HHI12s", msg[:20])
    out = []
    p = 20
    while p + 4 <= min(len(msg), 20 + ln):
        t, n = struct.unpack("!HH", msg[p : p + 4])
        out.append((t, msg[p + 4 : p + 4 + n]))
        p += 4 + n + ((-n) & 3)
    return typ, tid, out


def get(attrs, t):
    for k, v in attrs:
        if k == t:
            return v
    return None


def errcode(attrs):
    v = get(attrs, A_ERROR)
    return (v[2] & 7) * 100 + v[3] if v and len(v) >= 4 else None


def xor_port(value):
    """Port from an XOR-MAPPED-ADDRESS value."""
    return struct.unpack("!H", value[2:4])[0] ^ (MAGIC >> 16)


def xact(sock, msg, host, port):
    sock.sendto(msg, (host, port))
    return parse(sock.recvfrom(4096)[0])


def wire(host, port):
    ok = True
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.bind(("127.0.0.1", 0))
    src_port = s.getsockname()[1]

    # Plain Binding: success, and the reflexive port must be this socket's.
    tid = os.urandom(12)
    typ, rtid, aa = xact(s, make([], tid=tid), host, port)
    xm = get(aa, A_XOR_MAPPED)
    if typ != BINDING_SUCCESS or rtid != tid or not xm or xor_port(xm) != src_port:
        print(f"FAIL: plain Binding: type={typ:#x} tid_match={rtid == tid} xor_port={xm and xor_port(xm)} want {src_port}")
        ok = False
    else:
        print(f"OK: plain Binding: success, XOR-MAPPED-ADDRESS port {src_port}")

    # ICE-style attributes are accepted without authentication, and a request
    # that carries FINGERPRINT gets one back.
    typ, _t, aa = xact(
        s,
        make([(A_USERNAME, b"remote:local"), (A_PRIORITY, b"\x7f\0\0\0"), (A_MI, b"\0" * 20)], fingerprint=True),
        host,
        port,
    )
    if typ != BINDING_SUCCESS or not get(aa, A_XOR_MAPPED) or get(aa, A_FINGERPRINT) is None:
        print(f"FAIL: ICE-style Binding: type={typ:#x} fingerprint={get(aa, A_FINGERPRINT)}")
        ok = False
    else:
        print("OK: ICE-style Binding (USERNAME/PRIORITY/MESSAGE-INTEGRITY/FINGERPRINT): success + FINGERPRINT")

    # A comprehension-required attribute the server does not know: 420, and the
    # attribute is echoed in UNKNOWN-ATTRIBUTES.
    typ, _t, aa = xact(s, make([(0x0033, b"xy"), (0x0034, b"zw")]), host, port)
    ua = get(aa, A_UNKNOWN_ATTRS)
    if typ != BINDING_ERROR or errcode(aa) != 420 or ua != b"\x00\x33\x00\x34":
        print(f"FAIL: unknown required attrs: type={typ:#x} err={errcode(aa)} unknown={ua!r}")
        ok = False
    else:
        print("OK: unknown comprehension-required attributes: 420 + UNKNOWN-ATTRIBUTES")

    # Comprehension-optional attributes are ignored.
    typ, _t, aa = xact(s, make([(0x8033, b"xy")]), host, port)
    if typ != BINDING_SUCCESS:
        print(f"FAIL: unknown optional attribute: type={typ:#x} err={errcode(aa)}")
        ok = False
    else:
        print("OK: unknown comprehension-optional attribute: ignored")

    # RFC 5780 probes must still be answered (by the relay, which owns the
    # alternate sockets). Without --rfc5780 a CHANGE-REQUEST asking for a
    # different address is a 420.
    typ, _t, aa = xact(s, make([(A_CHANGE_REQUEST, b"\0\0\0\x04")]), host, port)
    if typ != BINDING_ERROR or errcode(aa) != 420:
        print(f"FAIL: CHANGE-REQUEST: type={typ:#x} err={errcode(aa)}")
        ok = False
    else:
        print("OK: CHANGE-REQUEST reaches the relay: 420 (no --rfc5780)")

    for label, a in (("RESPONSE-PORT", (A_RESPONSE_PORT, b"\x30\x39\0\0")), ("PADDING", (A_PADDING, b""))):
        typ, _t, aa = xact(s, make([a]), host, port)
        if typ != BINDING_SUCCESS:
            print(f"FAIL: {label}: type={typ:#x} err={errcode(aa)}")
            ok = False
        else:
            print(f"OK: {label} reaches the relay: success")

    return 0 if ok else 2


def silent(host, port):
    """--no-stun: the request is ignored, with no reply at all."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(make([]), (host, port))
    try:
        s.recvfrom(4096)
    except socket.timeout:
        print("OK: --no-stun: Binding ignored, no reply")
        return 0
    print("FAIL: --no-stun: server answered a Binding request")
    return 2


def challenge(host, port):
    """--secure-stun: Binding needs credentials, so it must reach the relay."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        typ, _t, aa = xact(s, make([]), host, port)
    except socket.timeout:
        print("FAIL: --secure-stun: no reply to an unauthenticated Binding")
        return 2
    if typ != BINDING_ERROR or errcode(aa) != 401:
        print(f"FAIL: --secure-stun: type={typ:#x} err={errcode(aa)}, want 401")
        return 2
    print("OK: --secure-stun: Binding challenged with 401")
    return 0


def flood(host, port, count):
    """One Binding request per source port, so each would have cost the relay a
    child socket and a session."""
    socks = []
    replied = 0
    msg = make([])

    def drain(batch):
        got = 0
        for held in batch:
            try:
                held.recvfrom(4096)
                got += 1
            except socket.timeout:
                pass
        return got

    for _ in range(count):
        q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        q.settimeout(0.2)
        q.sendto(msg, (host, port))
        socks.append(q)
        # Drain as we go: the receive buffers are small and the sockets stay
        # open so the server keeps seeing distinct sources.
        if len(socks) % 200 == 0:
            replied += drain(socks[-200:])
    replied += drain(socks[len(socks) - (len(socks) % 200) :])
    print(f"RESULT flood sent={count} replied={replied}")
    return 0


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    mode = sys.argv[3] if len(sys.argv) > 3 else "wire"

    if mode == "silent":
        return silent(host, port)
    if mode == "challenge":
        return challenge(host, port)
    if mode == "flood":
        return flood(host, port, int(sys.argv[4]) if len(sys.argv) > 4 else 1000)
    return wire(host, port)


if __name__ == "__main__":
    sys.exit(main())
