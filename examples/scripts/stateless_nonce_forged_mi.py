#!/usr/bin/env python3
# Forged-MESSAGE-INTEGRITY probe for the stateless-nonce listener fast path
# (see examples/run_tests_stateless_nonce.sh).
#
# A request that carries MESSAGE-INTEGRITY is only worth a session once its
# NONCE proves to be one the server issued to that very source address. The
# listener therefore answers the pre-credential rejections itself, and the
# replies must be byte-compatible with what check_stun_auth() would have sent
# from a session: 438 for a nonce the server never issued, 437/441 for a
# mismatched realm, 400 for missing/malformed credentials attributes - and a
# valid nonce must still be admitted to the session path (401, because the
# forged integrity fails there).
#
# Raw STUN over the standard library only, so the test can send the exact
# malformed shapes turnutils_uclient will never produce.

import os
import socket
import struct
import sys

MAGIC = 0x2112A442
M_ALLOCATE = 0x0003
M_REFRESH = 0x0004

A_USERNAME = 0x0006
A_MI = 0x0008
A_ERROR = 0x0009
A_REALM = 0x0014
A_NONCE = 0x0015
A_REQ_TRANSPORT = 0x0019

FORGED_MI = b"\0" * 20  # right length, wrong HMAC
FORGED_NONCE = b"deadbeefdeadbeefdeadbeef"  # right format, never issued here


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * ((-len(v)) & 3)


def make(typ, attrs):
    body = b"".join(attr(t, v) for t, v in attrs)
    return struct.pack("!HHI12s", typ, len(body), MAGIC, os.urandom(12)) + body


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


def errcode(attrs):
    v = get(attrs, A_ERROR)
    if not v or len(v) < 4:
        return None
    return (v[2] & 7) * 100 + v[3]


def xact(sock, msg, host, port):
    sock.sendto(msg, (host, port))
    return parse(sock.recvfrom(4096)[0])


def check(label, sock, host, port, msg, want):
    try:
        _typ, aa = xact(sock, msg, host, port)
    except socket.timeout:
        print(f"FAIL: {label}: no response (want {want})")
        return False
    got = errcode(aa)
    if got != want:
        print(f"FAIL: {label}: got error {got}, want {want}")
        return False
    print(f"OK: {label}: {got}")
    return True


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    user = (sys.argv[3] if len(sys.argv) > 3 else "user").encode()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    # A first request without MESSAGE-INTEGRITY: the plain fast-path challenge,
    # and the source of a genuinely issued nonce for the last check.
    try:
        _typ, aa = xact(s, make(M_ALLOCATE, [(A_REQ_TRANSPORT, b"\x11\0\0\0")]), host, port)
    except socket.timeout:
        print("FAIL: no 401 challenge for the unauthenticated request")
        return 2
    realm = get(aa, A_REALM)
    issued_nonce = get(aa, A_NONCE)
    if errcode(aa) != 401 or not realm or not issued_nonce:
        print(f"FAIL: unauthenticated request: err={errcode(aa)} realm={realm} nonce={issued_nonce}")
        return 2
    print(f"OK: unauthenticated challenge: 401 realm={realm.decode()}")

    creds = [(A_USERNAME, user), (A_REALM, realm)]
    ok = True

    # A nonce this server never issued to this address: 438, no session.
    ok &= check(
        "forged MI, unissued nonce",
        s,
        host,
        port,
        make(M_ALLOCATE, creds + [(A_NONCE, FORGED_NONCE), (A_REQ_TRANSPORT, b"\x11\0\0\0"), (A_MI, FORGED_MI)]),
        438,
    )

    # Realm mismatch is rejected before the nonce is even looked at.
    ok &= check(
        "forged MI, wrong realm (ALLOCATE)",
        s,
        host,
        port,
        make(
            M_ALLOCATE,
            [(A_USERNAME, user), (A_REALM, b"wrong.realm"), (A_NONCE, issued_nonce), (A_MI, FORGED_MI)],
        ),
        437,
    )
    ok &= check(
        "forged MI, wrong realm (REFRESH)",
        s,
        host,
        port,
        make(
            M_REFRESH,
            [(A_USERNAME, user), (A_REALM, b"wrong.realm"), (A_NONCE, issued_nonce), (A_MI, FORGED_MI)],
        ),
        441,
    )

    ok &= check(
        "forged MI, no NONCE",
        s,
        host,
        port,
        make(M_ALLOCATE, creds + [(A_REQ_TRANSPORT, b"\x11\0\0\0"), (A_MI, FORGED_MI)]),
        400,
    )
    ok &= check(
        "forged MI, no USERNAME",
        s,
        host,
        port,
        make(M_ALLOCATE, [(A_REALM, realm), (A_NONCE, issued_nonce), (A_MI, FORGED_MI)]),
        400,
    )

    # The nonce the server issued to this socket must still be admitted to the
    # session path, where the forged integrity is what fails (401).
    ok &= check(
        "forged MI, issued nonce (admitted to session path)",
        s,
        host,
        port,
        make(M_ALLOCATE, creds + [(A_NONCE, issued_nonce), (A_REQ_TRANSPORT, b"\x11\0\0\0"), (A_MI, FORGED_MI)]),
        401,
    )

    if not ok:
        return 2
    print("RESULT forged-mi-probe=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
