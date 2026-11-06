#!/usr/bin/env python3
# Relayed TTL must not leak into the server's own UDP replies (see
# examples/run_tests_relay_ttl.sh).
#
# Every per-session UDP client socket shares the listener's fd, so IP_TTL set
# for one relayed datagram is the TTL of everything the server sends next on
# that listener. A peer datagram that arrives with TTL 2 is relayed to its
# client with TTL 1; after that, Binding answers to new clients and responses
# to other sessions must still go out with the default TTL.
#
# Usage: relay_ttl_probe.py <host> <port> [probes]
# Exits 0 on pass, 1 on failure, 77 when the platform cannot observe TTLs.

import os
import socket
import struct
import sys

SKIP = 77

MAGIC = 0x2112A442
M_BINDING = 0x0001
M_ALLOCATE = 0x0003
M_CREATE_PERMISSION = 0x0008
BINDING_SUCCESS = 0x0101
ALLOCATE_SUCCESS = 0x0103
CREATE_PERMISSION_SUCCESS = 0x0108
DATA_INDICATION = 0x0017

A_XOR_PEER = 0x0012
A_DATA = 0x0013
A_XOR_RELAYED = 0x0016
A_REQUESTED_TRANSPORT = 0x0019

# CPython does not export IP_RECVTTL on Linux; 12 is its value in <linux/in.h>.
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12 if sys.platform.startswith("linux") else None)


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * ((-len(v)) & 3)


def make(method, attrs):
    body = b"".join(attr(t, v) for t, v in attrs)
    return struct.pack("!HHI12s", method, len(body), MAGIC, os.urandom(12)) + body


def parse(msg):
    typ, ln = struct.unpack("!HH", msg[:4])
    out = {}
    p = 20
    while p + 4 <= min(len(msg), 20 + ln):
        t, n = struct.unpack("!HH", msg[p : p + 4])
        out.setdefault(t, msg[p + 4 : p + 4 + n])
        p += 4 + n + ((-n) & 3)
    return typ, out


def xor_ip(b):
    return bytes(x ^ y for x, y in zip(b, struct.pack("!I", MAGIC)))


def xor_addr(ip, port):
    return struct.pack("!BBH4s", 0, 1, port ^ (MAGIC >> 16), xor_ip(socket.inet_aton(ip)))


def unxor_addr(v):
    return socket.inet_ntoa(xor_ip(v[4:8])), struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)


def client():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    s.bind(("127.0.0.1", 0))
    return s


def recv(s):
    """One datagram and the IP TTL it arrived with."""
    data, anc, _flags, _src = s.recvmsg(4096, socket.CMSG_SPACE(4))
    for level, ctype, cdata in anc:
        if level == socket.IPPROTO_IP and ctype in (socket.IP_TTL, IP_RECVTTL):
            # Linux reports an int, the BSDs a single byte.
            return data, (struct.unpack("=i", cdata[:4])[0] if len(cdata) >= 4 else cdata[0])
    return data, None


def xact(s, msg, server, want):
    s.sendto(msg, server)
    data, ttl = recv(s)
    typ, aa = parse(data)
    if typ != want:
        raise RuntimeError(f"expected {want:#06x}, got {typ:#06x}")
    return aa, ttl


def allocate(server, peer_ip):
    s = client()
    aa, _ttl = xact(s, make(M_ALLOCATE, [(A_REQUESTED_TRANSPORT, b"\x11\0\0\0")]), server, ALLOCATE_SUCCESS)
    relay = unxor_addr(aa[A_XOR_RELAYED])
    xact(s, make(M_CREATE_PERMISSION, [(A_XOR_PEER, xor_addr(peer_ip, 0))]), server, CREATE_PERMISSION_SUCCESS)
    return s, relay


def relay_from_peer(peer, relay, ttl, alloc):
    """Send one datagram from the peer at the given IP TTL; return the TTL its Data indication arrived with."""
    peer.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    peer.sendto(b"ttl-probe", relay)
    data, arrival = recv(alloc)
    typ, aa = parse(data)
    if typ != DATA_INDICATION or aa.get(A_DATA) != b"ttl-probe":
        raise RuntimeError(f"expected a Data indication, got {typ:#06x}")
    return arrival


def binding_ttls(server, count):
    ttls = []
    for _ in range(count):
        s = client()
        ttls.append(xact(s, make(M_BINDING, []), server, BINDING_SUCCESS)[1])
        s.close()
    return ttls


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    probes = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    server = (host, port)

    if IP_RECVTTL is None:
        print("SKIP: IP_RECVTTL is not available on this platform")
        return SKIP

    default_ttl = binding_ttls(server, 1)[0]
    if default_ttl is None or default_ttl < 3:
        print(f"SKIP: cannot read a usable reply TTL (got {default_ttl})")
        return SKIP

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind((host, 0))
    alloc_a, relay_a = allocate(server, host)
    alloc_b, _relay_b = allocate(server, host)

    arrived = relay_from_peer(peer, relay_a, 2, alloc_a)
    if arrived is None:
        print("SKIP: cannot read the TTL of a relayed datagram")
        return SKIP
    if arrived != 1:
        print(f"FAIL: a peer datagram sent with TTL 2 reached the client with TTL {arrived}, want 1")
        return 1
    print("OK: peer datagram sent with TTL 2 relayed to the client with TTL 1")

    ok = True

    # Another session's response goes out through its own client socket.
    _aa, ttl = xact(alloc_b, make(M_BINDING, []), server, BINDING_SUCCESS)
    if ttl != default_ttl:
        print(f"FAIL: another session's Binding response left with TTL {ttl}, want {default_ttl}")
        ok = False
    else:
        print(f"OK: another session's Binding response left with TTL {ttl}")

    # New clients are answered by the listener itself.
    relay_from_peer(peer, relay_a, 2, alloc_a)
    ttls = binding_ttls(server, probes)
    bad = [t for t in ttls if t != default_ttl]
    if bad:
        print(f"FAIL: {len(bad)}/{probes} Binding responses to new clients left with TTL {sorted(set(bad))}")
        ok = False
    else:
        print(f"OK: {probes}/{probes} Binding responses to new clients left with TTL {default_ttl}")

    # TTL propagation must keep working once the listener has reset the fd.
    arrived = relay_from_peer(peer, relay_a, 5, alloc_a)
    if arrived != 4:
        print(f"FAIL: a peer datagram sent with TTL 5 reached the client with TTL {arrived}, want 4")
        ok = False
    else:
        print("OK: peer datagram sent with TTL 5 relayed to the client with TTL 4")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
