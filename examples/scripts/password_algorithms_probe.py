#!/usr/bin/env python3
"""Probe the UDP listener's RFC 8489 behaviour (run_tests_password_algorithms.sh).

Usage: password_algorithms_probe.py HOST PORT ALGS_HEX    server run with --password-algorithms
       password_algorithms_probe.py HOST PORT legacy      server run without it
       password_algorithms_probe.py HOST PORT implied     server run with sha256,md5

ALGS_HEX: sends an unauthenticated ALLOCATE and expects 401 with an obMatJos2AAAB nonce and
PASSWORD-ALGORITHMS == ALGS_HEX; then presents a stripped-cookie nonce and a legacy 16-hex nonce with a
MESSAGE-INTEGRITY and expects 438 carrying a fresh cookie nonce and PASSWORD-ALGORITHMS again.
legacy: the 401 has no PASSWORD-ALGORITHMS and a legacy-format nonce, and a request carrying
MESSAGE-INTEGRITY-SHA256 gets 420. implied: an MD5 request (no PASSWORD-ALGORITHM(S)) signed with
MESSAGE-INTEGRITY-SHA256 gets a MESSAGE-INTEGRITY response.
The server must have the user alice:wonderland in realm north.gov (legacy, implied).
"""
import hashlib
import hmac
import os
import re
import socket
import struct
import sys

MAGIC = 0x2112A442
MI, MI256, ERROR_CODE, TRANSPORT_ATTR = 0x0008, 0x001C, 0x0009, 0x0019


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * (-len(v) % 4)


def request(sock, addr, attrs):
    tid = os.urandom(12)
    body = b"".join(attrs)
    sock.sendto(struct.pack("!HHI", 0x0003, len(body), MAGIC) + tid + body, addr)
    data, _ = sock.recvfrom(2048)
    assert data[8:20] == tid, "transaction id mismatch"
    out, off = {}, 20
    while off + 4 <= len(data):
        t, l = struct.unpack("!HH", data[off:off + 4])
        out[t] = data[off + 4:off + 4 + l]
        off += 4 + l + (-l % 4)
    code = out.get(ERROR_CODE)
    return (code[2] * 100 + code[3]) if code else 0, out


def signed(attrs, kind, key):
    """ALLOCATE body: attrs followed by MESSAGE-INTEGRITY (HMAC-SHA1) or MESSAGE-INTEGRITY-SHA256."""
    body = b"".join(attrs)
    size, digest, t = (20, hashlib.sha1, MI) if kind == "sha1" else (32, hashlib.sha256, MI256)
    length = len(body) + 4 + size
    head = struct.pack("!HHI", 0x0003, length, MAGIC)
    return t, size, digest, head, body


def request_signed(sock, addr, attrs, kind, key):
    t, size, digest, head, body = signed(attrs, kind, key)
    tid = os.urandom(12)
    mac = hmac.new(key, head + tid + body, digest).digest()
    sock.sendto(head + tid + body + attr(t, mac), addr)
    data, _ = sock.recvfrom(2048)
    assert data[8:20] == tid, "transaction id mismatch"
    out, off = {}, 20
    while off + 4 <= len(data):
        tt, l = struct.unpack("!HH", data[off:off + 4])
        out[tt] = data[off + 4:off + 4 + l]
        off += 4 + l + (-l % 4)
    code = out.get(ERROR_CODE)
    return (code[2] * 100 + code[3]) if code else 0, struct.unpack("!H", data[:2])[0], out


def md5_key(realm):
    return hashlib.md5(b"alice:" + realm + b":wonderland").digest()


def main():
    host, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    addr = (host, port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    transport = attr(TRANSPORT_ATTR, b"\x11\0\0\0")

    code, a = request(s, addr, [transport])
    assert code == 401, "expected 401, got %d" % code
    nonce, realm = a[0x0015], a[0x0014]

    if mode == "legacy":
        assert 0x8002 not in a, "401 carries PASSWORD-ALGORITHMS without --password-algorithms"
        assert not nonce.startswith(b"obMatJos2"), "nonce cookie without --password-algorithms"
        assert re.fullmatch(rb"[0-9a-f]{16}|[0-9a-f]{24}", nonce), "not a legacy nonce: %r" % nonce
        attrs = [transport, attr(0x0006, b"alice"), attr(0x0014, realm), attr(0x0015, nonce), attr(MI256, b"\0" * 32)]
        code, _, _ = request_signed(s, addr, attrs, "sha1", md5_key(realm))
        assert code == 420, "MESSAGE-INTEGRITY-SHA256 without --password-algorithms: expected 420, got %d" % code
    elif mode == "implied":
        assert nonce.startswith(b"obMatJos2AAAB"), "bad cookie in 401: %r" % nonce
        attrs = [transport, attr(0x0006, b"alice"), attr(0x0014, realm), attr(0x0015, nonce)]
        code, mtype, a = request_signed(s, addr, attrs, "sha256", md5_key(realm))
        assert mtype == 0x0103, "implied-MD5 request with MESSAGE-INTEGRITY-SHA256 failed: %d" % code
        assert MI in a and MI256 not in a, "implied-MD5 response must carry MESSAGE-INTEGRITY only"
    else:
        algs = bytes.fromhex(mode)
        assert nonce.startswith(b"obMatJos2AAAB"), "bad cookie in 401: %r" % nonce
        assert a[0x8002] == algs, "401 PASSWORD-ALGORITHMS %r != %r" % (a[0x8002], algs)

        def authed(n):
            return [transport, attr(0x0006, b"user"), attr(0x0014, realm), attr(0x0015, n), attr(MI, b"\0" * 20)]

        for label, bad in (("stripped-cookie", nonce[13:]), ("legacy-format", b"0123456789abcdef")):
            code, a = request(s, addr, authed(bad))
            assert code == 438, "%s nonce: expected 438, got %d" % (label, code)
            assert a[0x0015].startswith(b"obMatJos2AAAB"), "%s: 438 without cookie nonce" % label
            assert a[0x8002] == algs, "%s: 438 without PASSWORD-ALGORITHMS" % label
    print("probe OK")


main()
