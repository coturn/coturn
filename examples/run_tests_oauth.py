#!/usr/bin/env python3
"""Exercise OAuth Allocate/Refresh against a local turnserver (standard library only)."""

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time


SERVER_NAME = "oauth-test.example"
KID = b"oauth-test"
AS_RS_KEY = b"0123456789abcdef0123456789abcdef"
MAC_KEY = b"0123456789abcdefghij"
COOKIE = 0x2112A442
ACCESS_TOKEN = 0x001B
USERNAME = 0x0006
REALM = 0x0014
NONCE = 0x0015
MESSAGE_INTEGRITY = 0x0008
LIFETIME = 0x000D


def attribute(kind, value):
    return struct.pack("!HH", kind, len(value)) + value + b"\0" * ((-len(value)) % 4)


def request(method, attributes, key=None):
    tid = os.urandom(12)
    body = b"".join(attribute(kind, value) for kind, value in attributes)
    if key is not None:
        header = struct.pack("!HHI12s", method, len(body) + 24, COOKIE, tid)
        mac = hmac.new(key, header + body, hashlib.sha1).digest()
        body += attribute(MESSAGE_INTEGRITY, mac)
    return struct.pack("!HHI12s", method, len(body), COOKIE, tid) + body, tid


def response(sock, method, attributes, key=None):
    packet, tid = request(method, attributes, key)
    sock.send(packet)
    data = sock.recv(2048)
    if len(data) < 20 or data[8:20] != tid:
        raise AssertionError("invalid STUN response or transaction ID")
    found = {}
    end = 20 + struct.unpack_from("!H", data, 2)[0]
    offset = 20
    while offset + 4 <= end:
        kind, length = struct.unpack_from("!HH", data, offset)
        found[kind] = data[offset + 4:offset + 4 + length]
        offset += 4 + ((length + 3) & ~3)
    error = found.get(0x0009)
    if error is not None:
        return error[2] * 100 + error[3], found
    return 0, found


def token(oauth_bin, key, lifetime, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())
    command = [str(oauth_bin), "-e", "--server-name", SERVER_NAME,
               "--auth-key-id", KID.decode(), "--auth-key", base64.b64encode(key).decode(),
               "--auth-key-timestamp", "1", "--auth-key-lifetime", "4000000000",
               "--token-mac-key", base64.b64encode(MAC_KEY).decode(),
               "--token-lifetime", str(lifetime), "--token-timestamp", str(timestamp << 16)]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return base64.b64decode(json.loads(result.stdout)["access_token"])


def challenge(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.connect(address)
    sock.settimeout(2)
    for _ in range(20):
        try:
            code, attrs = response(sock, 0x0003, [(0x0019, b"\x11\0\0\0")])
            if code != 401:
                raise AssertionError(f"expected Allocate challenge, got {code}")
            return sock, attrs[REALM], attrs[NONCE]
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(0.1)
    raise AssertionError("turnserver did not start")


def authenticated(sock, method, realm, nonce, access_token, extra=()):
    attrs = list(extra) + [(USERNAME, KID), (REALM, realm), (NONCE, nonce)]
    if access_token is not None:
        attrs.append((ACCESS_TOKEN, access_token))
    # Coturn's SHA-1 integrity helper uses the first 16 bytes of hmackey_t.
    return response(sock, method, attrs, MAC_KEY[:16])


def expect(code, actual, description):
    if actual != code:
        raise AssertionError(f"{description}: expected {code}, got {actual}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bindir", type=Path, default=Path(__file__).resolve().parents[1] / "build/bin")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="coturn-oauth-") as tmp:
        tmp = Path(tmp)
        db = tmp / "turn.db"
        with sqlite3.connect(db) as conn:
            conn.executescript((repo / "turndb/schema.sql").read_text())
            conn.execute("INSERT INTO oauth_key VALUES (?, ?, 1, 4000000000, 'A256GCM', ?)",
                         (KID.decode(), base64.b64encode(AS_RS_KEY).decode(), SERVER_NAME))

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        command = [str(args.bindir / "turnserver"), "--oauth", "--lt-cred-mech",
                   f"--server-name={SERVER_NAME}", f"--realm={SERVER_NAME}", f"--db={db}",
                   "--listening-ip=127.0.0.1", "--relay-ip=127.0.0.1", f"--listening-port={port}",
                   "--no-tls", "--cli=false", "--stateless-nonce=false", "--log-file=stdout", "-f", "-v"]
        with (tmp / "turnserver.log").open("w+") as log:
            server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            sockets = []
            try:
                sock, realm, nonce = challenge(("127.0.0.1", port))
                sockets.append(sock)
                first_token = token(args.bindir / "turnutils_oauth", AS_RS_KEY, 30)
                code, attrs = authenticated(sock, 0x0003, realm, nonce, first_token,
                                            [(0x0019, b"\x11\0\0\0")])
                expect(0, code, "valid Allocate")
                first_lifetime = struct.unpack("!I", attrs[LIFETIME])[0]
                if not 0 < first_lifetime <= 35:
                    raise AssertionError(f"Allocate lifetime {first_lifetime} exceeds token")

                time.sleep(2)
                code, attrs = authenticated(sock, 0x0004, realm, nonce, first_token)
                expect(0, code, "same-token Refresh")
                refreshed_lifetime = struct.unpack("!I", attrs[LIFETIME])[0]
                if refreshed_lifetime >= first_lifetime:
                    raise AssertionError("Refresh reset the token's original lifetime")

                replacement = token(args.bindir / "turnutils_oauth", AS_RS_KEY, 60)
                code, attrs = authenticated(sock, 0x0004, realm, nonce, replacement)
                expect(0, code, "replacement-token Refresh")
                if struct.unpack("!I", attrs[LIFETIME])[0] <= refreshed_lifetime:
                    raise AssertionError("replacement token did not extend the allocation")

                code, _ = authenticated(sock, 0x0004, realm, nonce, None)
                expect(401, code, "Refresh without ACCESS-TOKEN")

                for description, lifetime, timestamp in [
                    ("future timestamp", 60, int(time.time()) + 10 * 86400),
                    ("zero lifetime", 0, int(time.time()) - 30 * 86400),
                ]:
                    other, other_realm, other_nonce = challenge(("127.0.0.1", port))
                    sockets.append(other)
                    bad_token = token(args.bindir / "turnutils_oauth", AS_RS_KEY, lifetime, timestamp)
                    code, _ = authenticated(other, 0x0003, other_realm, other_nonce, bad_token,
                                            [(0x0019, b"\x11\0\0\0")])
                    expect(401, code, description)

                with sqlite3.connect(db) as conn:
                    conn.execute("DELETE FROM oauth_key WHERE kid=?", (KID.decode(),))
                code, _ = authenticated(sock, 0x0004, realm, nonce, replacement)
                expect(401, code, "Refresh after AS-RS key removal")

                with sqlite3.connect(db) as conn:
                    conn.execute("INSERT INTO oauth_key VALUES (?, '', 1, 4000000000, 'A256GCM', ?)",
                                 (KID.decode(), SERVER_NAME))
                other, other_realm, other_nonce = challenge(("127.0.0.1", port))
                sockets.append(other)
                zero_key_token = token(args.bindir / "turnutils_oauth", bytes(32), 60)
                code, _ = authenticated(other, 0x0003, other_realm, other_nonce, zero_key_token,
                                        [(0x0019, b"\x11\0\0\0")])
                expect(401, code, "empty configured key with zero-key token")

                with sqlite3.connect(db) as conn:
                    conn.execute("UPDATE oauth_key SET ikm_key=? WHERE kid=?",
                                 (base64.b64encode(AS_RS_KEY).decode(), KID.decode()))
                expiring_sock, expiring_realm, expiring_nonce = challenge(("127.0.0.1", port))
                sockets.append(expiring_sock)
                expiring = token(args.bindir / "turnutils_oauth", AS_RS_KEY, 24, int(time.time()) - 20)
                code, _ = authenticated(expiring_sock, 0x0003, expiring_realm, expiring_nonce, expiring,
                                        [(0x0019, b"\x11\0\0\0")])
                expect(0, code, "short-lived Allocate")
                time.sleep(3)
                code, _ = authenticated(expiring_sock, 0x0004, expiring_realm, expiring_nonce, expiring)
                expect(0, code, "short-lived Refresh before expiration")
                time.sleep(6)
                code, _ = authenticated(expiring_sock, 0x0004, expiring_realm, expiring_nonce, expiring)
                if code == 0:
                    raise AssertionError("Refresh succeeded after the token expired")
                print("OAuth Allocate/Refresh regression checks passed")
            except Exception:
                log.flush()
                output = (tmp / "turnserver.log").read_text()
                print(output[:2000] + output[-2000:])
                raise
            finally:
                for sock in sockets:
                    sock.close()
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
