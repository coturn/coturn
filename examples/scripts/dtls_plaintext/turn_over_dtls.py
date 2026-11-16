#!/usr/bin/env python3
"""TURN over DTLS via dtls_proxy :7001, then plaintext STUN/ChannelData on the
same 5-tuple via :7002. A peer listener records what the relay delivers.

usage: turn_over_dtls.py <peer-ip> <peer-port> <user> <pw>
       turn_over_dtls.py --self-test

Exit codes:
  10  plaintext rejected and the encrypted Send control was delivered
  11  plaintext processed (payload relayed or Binding answered inside DTLS)
   2  harness error (setup failure, missing encrypted control, uncaught exception)
"""
import hashlib, hmac, os, socket, struct, subprocess, sys, threading, time

MAGIC = 0x2112A442

# A rejected injection is a pass only when the encrypted control was delivered.
EXIT_HARNESS = 2
EXIT_REJECTED = 10
EXIT_PROCESSED = 11


def _harness_excepthook(exc_type, exc, tb):
    # SystemExit never reaches this hook, so sys.exit keeps its status.
    sys.__excepthook__(exc_type, exc, tb)
    os._exit(EXIT_HARNESS)


sys.excepthook = _harness_excepthook
threading.excepthook = lambda args: _harness_excepthook(args.exc_type, args.exc_value, args.exc_traceback)


def decide_exit(plaintext_relayed, binding_reply, encrypted_delivered):
    if plaintext_relayed or binding_reply:
        return EXIT_PROCESSED
    if encrypted_delivered:
        return EXIT_REJECTED
    return EXIT_HARNESS


def _loaded_child(trailer):
    script = os.path.abspath(__file__)
    code = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('turn_over_dtls', %r)\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
    ) % script + trailer + "\n"
    # The child must not be asked to bind or to speak TURN; it only loads the hook.
    return subprocess.run([sys.executable, "-c", code], capture_output=True)


def self_test():
    failed = False
    if (EXIT_HARNESS, EXIT_REJECTED, EXIT_PROCESSED) != (2, 10, 11):
        print("FAIL: exit-code constants drifted", file=sys.stderr)
        failed = True

    proc = _loaded_child("raise RuntimeError('self-test uncaught exception')")
    if proc.returncode != EXIT_HARNESS or b"self-test uncaught exception" not in proc.stderr:
        print(
            "FAIL: uncaught exception exited %s, want %s" % (proc.returncode, EXIT_HARNESS),
            file=sys.stderr,
        )
        if proc.stderr:
            sys.stderr.buffer.write(proc.stderr)
        failed = True

    # sys.exit must survive the hook with the status it was given.
    for code in (EXIT_HARNESS, EXIT_REJECTED, EXIT_PROCESSED):
        proc = _loaded_child("sys.exit(%d)" % code)
        if proc.returncode != code:
            print("FAIL: sys.exit(%s) became %s" % (code, proc.returncode), file=sys.stderr)
            if proc.stderr:
                sys.stderr.buffer.write(proc.stderr)
            failed = True

    cases = (
        (False, False, False, EXIT_HARNESS, "encrypted control missing and no plaintext"),
        (True, False, False, EXIT_PROCESSED, "plaintext payload seen"),
        (False, True, False, EXIT_PROCESSED, "plaintext Binding seen"),
        (True, True, True, EXIT_PROCESSED, "plaintext seen"),
        (False, False, True, EXIT_REJECTED, "encrypted delivered and no plaintext"),
    )
    for relayed, binding, encrypted, want, label in cases:
        got_code = decide_exit(relayed, binding, encrypted)
        if got_code != want:
            print("FAIL: %s -> %s, want %s" % (label, got_code, want), file=sys.stderr)
            failed = True

    if failed:
        sys.exit(1)
    print("OK: DTLS plaintext-reject exit-code self-test")


def attr(t, v): return struct.pack('!HH', t, len(v)) + v + b'\0' * ((4 - len(v) % 4) % 4)
def msg(mtype, attrs, tid=None):
    tid = tid or os.urandom(12); body = b''.join(attrs)
    return struct.pack('!HHI', mtype, len(body), MAGIC) + tid + body
def with_mi(mtype, attrs, key):
    tid = os.urandom(12); body = b''.join(attrs)
    hdr = struct.pack('!HHI', mtype, len(body) + 24, MAGIC) + tid
    return hdr + body + attr(0x0008, hmac.new(key, hdr + body, hashlib.sha1).digest())
def parse(data):
    mtype, mlen, _ = struct.unpack('!HHI', data[:8]); out, off = {}, 20
    while off + 4 <= 20 + mlen:
        t, l = struct.unpack('!HH', data[off:off + 4]); out.setdefault(t, data[off + 4:off + 4 + l])
        off += 4 + l + (4 - l % 4) % 4
    return mtype, data[8:20], out
def xor_addr(ip, port):
    xa = bytes(x ^ y for x, y in zip(socket.inet_aton(ip), struct.pack('!I', MAGIC)))
    return struct.pack('!BBH', 0, 1, port ^ (MAGIC >> 16)) + xa
def err(out):
    e = out.get(0x0009); return (e[2] & 7) * 100 + e[3] if e else 0


def run(peer_ip, peer_port, user, pw):
    got = []
    ps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ps.bind((peer_ip, peer_port)); ps.settimeout(0.5)
    stop = False
    def peer():
        while not stop:
            try:
                d, a = ps.recvfrom(4096); got.append((d, a)); print('PEER RECEIVED %r from %s' % (d, a), flush=True)
            except socket.timeout:
                pass
    threading.Thread(target=peer, daemon=True).start()

    enc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); enc.settimeout(3)
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    E, R = ('127.0.0.1', 7001), ('127.0.0.1', 7002)
    def req(m):
        for _ in range(3):
            enc.sendto(m, E)
            try: return parse(enc.recv(65536))
            except socket.timeout: continue
        print('NO REPLY'); sys.exit(EXIT_HARNESS)

    rt = attr(0x0019, bytes([17, 0, 0, 0]))
    _, _, out = req(msg(0x0003, [rt]))
    realm, nonce = out[0x0014], out[0x0015]
    key = hashlib.md5(user.encode() + b':' + realm + b':' + pw.encode()).digest()
    auth = [attr(0x0006, user.encode()), attr(0x0014, realm), attr(0x0015, nonce)]
    mt, _, out = req(with_mi(0x0003, [rt] + auth, key)); print('[DTLS] ALLOCATE ->', hex(mt), 'error', err(out))
    if mt != 0x0103: sys.exit(EXIT_HARNESS)
    pa = attr(0x0012, xor_addr(peer_ip, peer_port))
    mt, _, out = req(with_mi(0x0008, [pa] + auth, key)); print('[DTLS] CREATE_PERMISSION ->', hex(mt), 'error', err(out))
    mt, _, out = req(with_mi(0x0009, [attr(0x000C, b'\x40\x01\x00\x00'), pa] + auth, key)); print('[DTLS] CHANNEL_BIND 0x4001 ->', hex(mt), 'error', err(out))
    if mt != 0x0109: sys.exit(EXIT_HARNESS)

    enc.sendto(msg(0x0016, [pa, attr(0x0013, b'ENCRYPTED-SEND-VIA-DTLS')]), E)
    time.sleep(1)
    print('--- now sending PLAINTEXT (no DTLS) datagrams on the victim 5-tuple ---', flush=True)
    raw.sendto(msg(0x0016, [pa, attr(0x0013, b'PLAINTEXT-SEND-INDICATION-INJECTED')]), R)
    time.sleep(0.5)
    data = b'PLAINTEXT-CHANNELDATA-INJECTED'
    raw.sendto(struct.pack('!HH', 0x4001, len(data)) + data, R)
    time.sleep(0.5)
    tid = b'PLAINBINDING'
    raw.sendto(msg(0x0001, [], tid), R)
    binding_reply = False
    try:
        while True:
            mt, rtid, out = parse(enc.recv(65536))
            print('[DTLS reply] type', hex(mt), 'tid', rtid)
            if rtid == tid and mt == 0x0101: binding_reply = True
    except socket.timeout:
        pass
    time.sleep(1); stop = True
    inj = [d for d, a in got if d.startswith(b'PLAINTEXT')]
    encrypted_delivered = any(d.startswith(b'ENCRYPTED') for d, a in got)
    print('RESULT: encrypted sanity delivered:', encrypted_delivered)
    print('RESULT: plaintext payloads relayed to peer:', inj)
    print('RESULT: plaintext Binding answered inside DTLS:', binding_reply)
    sys.exit(decide_exit(bool(inj), binding_reply, encrypted_delivered))


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        self_test()
        return
    if len(argv) != 5:
        print("usage: turn_over_dtls.py <peer-ip> <peer-port> <user> <pw>", file=sys.stderr)
        print("       turn_over_dtls.py --self-test", file=sys.stderr)
        sys.exit(EXIT_HARNESS)
    run(argv[1], int(argv[2]), argv[3], argv[4])


if __name__ == "__main__":
    main(sys.argv)
