#!/bin/bash

# Oversize or undecodable TCP stream frames must close promptly so the relay
# cannot busy-loop at the bufferevent high watermark.
#
# 1. oversize ChannelData header -> peer sees close quickly
# 2. STUN_BUFFER_SIZE of zeros -> same
# 3. incomplete legal ChannelData stays open
# 4. Binding after the probes still gets a STUN reply

OVERSIZE_LOG="/tmp/run_tests_oversize_stream_frame.$$.log"
turnserver_pid=""
SERVER_PORT=3498
FAIL=0

cleanup() {
    if [ -n "$turnserver_pid" ]; then
        kill "$turnserver_pid" 2>/dev/null
        wait "$turnserver_pid" 2>/dev/null
    fi
    rm -f "$OVERSIZE_LOG"
}
trap cleanup EXIT

BINDIR="../bin"
if [ ! -f "$BINDIR/turnserver" ]; then
    BINDIR="../build/bin"
fi

wait_for_turnserver() {
    local i
    for i in $(seq 1 40); do
        if grep -q "Total auth threads:" "$OVERSIZE_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$turnserver_pid" 2>/dev/null; then
            echo "FATAL: turnserver (pid $turnserver_pid) exited before init completed"
            cat "$OVERSIZE_LOG" 2>/dev/null || true
            return 1
        fi
        sleep 0.5
    done
    echo "FATAL: turnserver never reached 'Total auth threads:' init line within 20s"
    tail -30 "$OVERSIZE_LOG" 2>/dev/null || true
    return 1
}

: > "$OVERSIZE_LOG"
"$BINDIR/turnserver" --use-auth-secret --static-auth-secret=secret --realm=north.gov \
    --allow-loopback-peers --no-tls --relay-threads 1 \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --listening-port="$SERVER_PORT" \
    --log-file=stdout \
    > "$OVERSIZE_LOG" 2>&1 &
turnserver_pid="$!"
wait_for_turnserver || exit 1

python3 - "$SERVER_PORT" <<'PY'
import socket
import struct
import sys
import time

port = int(sys.argv[1])
host = "127.0.0.1"
fail = 0


def connect():
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(0.2)
    return s


def closed_quickly(sock, label, budget=3.0):
    """Return True if the peer closes (EOF/RST) within budget seconds."""
    t0 = time.monotonic()
    sock.settimeout(0.2)
    while time.monotonic() - t0 < budget:
        try:
            data = sock.recv(64)
            if data == b"":
                print("PASS: %s closed by server after %.2fs" % (label, time.monotonic() - t0))
                return True
        except socket.timeout:
            continue
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("PASS: %s reset by server after %.2fs" % (label, time.monotonic() - t0))
            return True
        except OSError as e:
            print("PASS: %s OSError %s after %.2fs" % (label, e, time.monotonic() - t0))
            return True
    print("FAIL: %s still open after %.1fs" % (label, budget))
    return False


# 1) ChannelData declaring 65535 bytes — never fits STUN_BUFFER_SIZE.
s = connect()
s.sendall(b"\x40\x00\xff\xff")
if not closed_quickly(s, "oversize ChannelData header"):
    fail = 1
s.close()

# 2) Full read-buffer of zeros — undecodable, must close once copyout is full.
s = connect()
payload = b"\x00" * 65507
sent = 0
s.settimeout(5)
while sent < len(payload):
    sent += s.send(payload[sent:])
if not closed_quickly(s, "STUN_BUFFER_SIZE zeros"):
    fail = 1
s.close()

# 3) Incomplete legal ChannelData must NOT be closed within a short window.
s = connect()
s.sendall(b"\x40\x00\x03\xe8" + b"\x00" * 500)  # length 1000, only 500 bytes of body
s.settimeout(0.2)
t0 = time.monotonic()
premature = False
while time.monotonic() - t0 < 1.0:
    try:
        data = s.recv(64)
        if data == b"":
            premature = True
            break
    except socket.timeout:
        continue
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        premature = True
        break
if premature:
    print("FAIL: incomplete legal ChannelData was closed early")
    fail = 1
else:
    print("PASS: incomplete legal ChannelData stayed open")
s.close()

# 4) Fresh Binding still works after the attacks (server not wedged).
binding = bytearray(20)
struct.pack_into("!HHI", binding, 0, 0x0001, 0, 0x2112A442)  # Binding request
binding[8:20] = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
s = connect()
s.settimeout(3)
s.sendall(binding)
try:
    resp = s.recv(64)
except Exception as e:
    print("FAIL: Binding after attacks raised %s" % e)
    fail = 1
    resp = b""
if len(resp) >= 20 and (resp[0] & 0xC0) == 0:
    print("PASS: Binding after attacks got a STUN reply (%d bytes)" % len(resp))
else:
    print("FAIL: Binding after attacks got %r" % resp)
    fail = 1
s.close()

sys.exit(fail)
PY
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FAIL: oversize stream-frame regression"
    echo "--- turnserver log (last 40 lines) ---"
    tail -40 "$OVERSIZE_LOG" 2>/dev/null || true
    FAIL=1
else
    echo "OK: oversize stream-frame regression"
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
exit 0
