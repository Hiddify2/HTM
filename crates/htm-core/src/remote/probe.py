#!/usr/bin/env python3
"""HTM throughput and jitter probe.

A dependency-free stand-in for iperf3, uploaded to both servers by HTM so that
benchmarking works on hosts where installing packages is impossible or
unwanted. Only the Python 3 standard library is used, and nothing newer than
Python 3.6 syntax.

Two roles:

    probe.py serve  --bind IP --port P --mode tcp|udp --seconds N --out FILE
    probe.py client --host IP --port P --mode tcp|udp --seconds N [...]

The server runs a single measurement and then exits, writing its results to
--out as JSON. The client prints its own results to stdout as JSON. HTM reads
whichever side was the *receiver*, because the receiver's byte count is the
only one that reflects what actually crossed the tunnel.

Wire format
-----------
TCP: each connection opens with a 16 byte header

    magic[8] = b"HTMP0001"
    role[1]  = 0 upload (client sends), 1 download (server sends)
    streams[1]
    seconds[2] big endian
    pad[4]

after which the sending side writes as fast as it can for `seconds`, then
half-closes. The receiving side counts bytes until EOF.

UDP: every datagram is

    magic[8] = b"HTMP0001"
    seq[4]   big endian, 0xFFFFFFFF marks end of test
    ts[8]    big endian nanoseconds from the sender's monotonic clock
    padding to the configured datagram size
"""

import argparse
import json
import socket
import struct
import sys
import threading
import time

MAGIC = b"HTMP0001"
HEADER = struct.Struct(">8sBBHI")          # magic, role, streams, seconds, pad
UDP_HEADER = struct.Struct(">8sIQ")        # magic, seq, timestamp
BLOCK_SIZE = 128 * 1024
UDP_FIN = 0xFFFFFFFF
ROLE_UPLOAD = 0
ROLE_DOWNLOAD = 1


def monotonic_ns():
    # time.monotonic_ns() only exists from 3.7; keep 3.6 working.
    return int(time.monotonic() * 1e9)


def make_payload(size):
    # A repeating, non-compressible-enough pattern. Content does not matter for
    # throughput, only volume, but an all-zero buffer can be optimised by some
    # virtual NICs.
    chunk = bytes(bytearray((i * 31 + 7) & 0xFF for i in range(256)))
    reps = (size // len(chunk)) + 1
    return (chunk * reps)[:size]


def socks5_connect(proxy, dst_host, dst_port, timeout):
    """Open a TCP socket to dst via a SOCKS5 proxy "host:port".

    Used to measure a tunnel whose relay exposes only a SOCKS5 proxy: the probe
    client reaches the exit's measurement server through it, with no auth. Only
    the small slice of RFC 1928 the probe needs is implemented.
    """
    phost, pport = proxy.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((phost, int(pport)))
    # Greeting: version 5, one method, "no authentication".
    sock.sendall(b"\x05\x01\x00")
    reply = _recv_exact(sock, 2)
    if reply[0:1] != b"\x05" or reply[1:2] != b"\x00":
        raise OSError("SOCKS5 proxy refused the no-auth method")
    # CONNECT request, address as a domain/literal so the proxy resolves it.
    host_bytes = dst_host.encode("idna") if isinstance(dst_host, str) else dst_host
    req = b"\x05\x01\x00\x03" + struct.pack("B", len(host_bytes)) + host_bytes
    req += struct.pack(">H", dst_port)
    sock.sendall(req)
    head = _recv_exact(sock, 4)
    if head[1:2] != b"\x00":
        raise OSError("SOCKS5 CONNECT failed with code %d" % head[1])
    atyp = head[3:4]
    if atyp == b"\x01":
        _recv_exact(sock, 4 + 2)
    elif atyp == b"\x04":
        _recv_exact(sock, 16 + 2)
    elif atyp == b"\x03":
        ln = _recv_exact(sock, 1)[0]
        _recv_exact(sock, ln + 2)
    else:
        raise OSError("SOCKS5 proxy returned an unknown address type")
    return sock


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise OSError("connection closed during SOCKS5 negotiation")
        buf += part
    return buf


def open_stream(host, port, timeout, socks=None):
    """A TCP socket to host:port, directly or through a SOCKS5 proxy."""
    if socks:
        return socks5_connect(socks, host, port, timeout)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


# ─────────────────────────────────────────────────────────────────────────────
# TCP
# ─────────────────────────────────────────────────────────────────────────────


class TcpStreamStats(object):
    def __init__(self):
        self.bytes = 0
        self.first = None
        self.last = None
        self.error = None

    def mark(self, count):
        t = time.monotonic()
        if self.first is None:
            self.first = t
        self.last = t
        self.bytes += count


def tcp_send_for(sock, seconds, stats, payload):
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            sent = sock.send(payload)
            if sent <= 0:
                break
            stats.mark(sent)
    except socket.timeout:
        pass
    except OSError as exc:
        stats.error = str(exc)
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def tcp_recv_until_eof(sock, stats):
    try:
        while True:
            data = sock.recv(BLOCK_SIZE)
            if not data:
                break
            stats.mark(len(data))
    except socket.timeout:
        pass
    except OSError as exc:
        stats.error = str(exc)


def aggregate(stats_list):
    total = 0
    first = None
    last = None
    errors = []
    for s in stats_list:
        total += s.bytes
        if s.error:
            errors.append(s.error)
        if s.first is not None and (first is None or s.first < first):
            first = s.first
        if s.last is not None and (last is None or s.last > last):
            last = s.last
    elapsed = 0.0
    if first is not None and last is not None:
        elapsed = max(last - first, 0.0)
    bps = (total * 8.0 / elapsed) if elapsed > 0.001 else 0.0
    return {
        "bytes": total,
        "seconds": round(elapsed, 6),
        "bits_per_second": round(bps, 2),
        "streams": len(stats_list),
        "errors": errors,
    }


def serve_tcp(bind, port, seconds, expect_streams):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(128)
    # Generous: the client still has to be started and may be slow to connect.
    srv.settimeout(seconds + 60)

    payload = make_payload(BLOCK_SIZE)
    stats_list = []
    threads = []
    role_seen = [ROLE_UPLOAD]

    def handle(conn):
        stats = TcpStreamStats()
        stats_list.append(stats)
        try:
            conn.settimeout(seconds + 45)
            head = b""
            while len(head) < HEADER.size:
                part = conn.recv(HEADER.size - len(head))
                if not part:
                    stats.error = "client closed before sending a header"
                    return
                head += part
            magic, role, streams, secs, _pad = HEADER.unpack(head)
            if magic != MAGIC:
                stats.error = "bad magic in header"
                return
            role_seen[0] = role
            if role == ROLE_UPLOAD:
                tcp_recv_until_eof(conn, stats)
            else:
                tcp_send_for(conn, secs, stats, payload)
                # Wait for the peer to acknowledge EOF so the final bytes are
                # counted on its side before the socket disappears.
                try:
                    conn.recv(1)
                except OSError:
                    pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    accepted = 0
    try:
        while accepted < expect_streams:
            conn, _addr = srv.accept()
            accepted += 1
            t = threading.Thread(target=handle, args=(conn,))
            t.daemon = True
            t.start()
            threads.append(t)
    except socket.timeout:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass

    for t in threads:
        t.join(seconds + 90)

    result = aggregate(stats_list)
    result["mode"] = "tcp"
    result["side"] = "server"
    result["role"] = "upload" if role_seen[0] == ROLE_UPLOAD else "download"
    result["accepted_streams"] = accepted
    return result


def client_tcp(host, port, seconds, streams, reverse, connect_timeout, socks=None):
    role = ROLE_DOWNLOAD if reverse else ROLE_UPLOAD
    payload = make_payload(BLOCK_SIZE)
    header = HEADER.pack(MAGIC, role, streams, seconds, 0)

    socks_conns = []
    for _ in range(streams):
        s = open_stream(host, port, connect_timeout, socks)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(header)
        s.settimeout(seconds + 45)
        socks_conns.append(s)

    stats_list = []
    threads = []
    # A barrier makes every stream start measuring at the same instant, so the
    # aggregate rate is not skewed by staggered connection setup.
    barrier = threading.Barrier(streams) if streams > 1 else None

    def run(sock):
        stats = TcpStreamStats()
        stats_list.append(stats)
        if barrier is not None:
            try:
                barrier.wait(timeout=30)
            except threading.BrokenBarrierError:
                pass
        if role == ROLE_UPLOAD:
            tcp_send_for(sock, seconds, stats, payload)
            # Let the server finish reading and close.
            try:
                sock.recv(1)
            except OSError:
                pass
        else:
            tcp_recv_until_eof(sock, stats)
        try:
            sock.close()
        except OSError:
            pass

    for s in socks_conns:
        t = threading.Thread(target=run, args=(s,))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join(seconds + 90)

    result = aggregate(stats_list)
    result["mode"] = "tcp"
    result["side"] = "client"
    result["role"] = "download" if reverse else "upload"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Latency (TCP connect round-trip)
# ─────────────────────────────────────────────────────────────────────────────
#
# A tunnel with no TUN link cannot be pinged with ICMP, so round-trip time is
# taken from how long a TCP connection to the exit's measurement server takes to
# establish through the tunnel. It is a connection-setup RTT, not an echo, but it
# tracks the path latency closely enough to rank configurations against it.


def serve_latency(bind, port, count, seconds):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(128)
    srv.settimeout(seconds + 60)
    accepted = 0
    try:
        while accepted < count:
            try:
                conn, _addr = srv.accept()
            except socket.timeout:
                break
            accepted += 1
            try:
                conn.close()
            except OSError:
                pass
    finally:
        try:
            srv.close()
        except OSError:
            pass
    return {"mode": "latency", "side": "server", "accepted": accepted, "errors": []}


def client_latency(host, port, count, connect_timeout, socks=None):
    samples = []
    lost = 0
    for _ in range(max(count, 1)):
        start = time.monotonic()
        try:
            s = open_stream(host, port, connect_timeout, socks)
            elapsed_ms = (time.monotonic() - start) * 1000.0
            samples.append(elapsed_ms)
            try:
                s.close()
            except OSError:
                pass
        except OSError:
            lost += 1
        time.sleep(0.05)

    if samples:
        mn = min(samples)
        mx = max(samples)
        avg = sum(samples) / len(samples)
        mdev = sum(abs(x - avg) for x in samples) / len(samples)
    else:
        mn = mx = avg = mdev = 0.0
    total = len(samples) + lost
    return {
        "mode": "latency",
        "side": "client",
        "min_ms": round(mn, 4),
        "avg_ms": round(avg, 4),
        "max_ms": round(mx, 4),
        "mdev_ms": round(mdev, 4),
        "samples": len(samples),
        "lost": lost,
        "loss_percent": round((lost * 100.0 / total) if total else 0.0, 4),
        "errors": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# UDP
# ─────────────────────────────────────────────────────────────────────────────


def serve_udp(bind, port, seconds, datagram_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.bind((bind, port))
    sock.settimeout(seconds + 60)

    received = 0
    out_of_order = 0
    highest_seq = -1
    last_seq = -1
    total_bytes = 0
    first_arrival = None
    last_arrival = None
    jitter = 0.0
    prev_transit = None
    finished = False

    idle_deadline = None
    try:
        while True:
            if idle_deadline is not None:
                remaining = idle_deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            if len(data) < UDP_HEADER.size:
                continue
            magic, seq, sent_ns = UDP_HEADER.unpack(data[: UDP_HEADER.size])
            if magic != MAGIC:
                continue

            if seq == UDP_FIN:
                finished = True
                # Give stragglers a moment, then stop.
                idle_deadline = time.monotonic() + 1.0
                continue

            arrival = time.monotonic()
            if first_arrival is None:
                first_arrival = arrival
            last_arrival = arrival
            received += 1
            total_bytes += len(data)

            if seq > highest_seq:
                highest_seq = seq
            if seq < last_seq:
                out_of_order += 1
            last_seq = seq

            # RFC 3550 interarrival jitter. Both clocks are monotonic and
            # unsynchronised, but the constant offset cancels in the difference.
            transit = arrival - (sent_ns / 1e9)
            if prev_transit is not None:
                d = abs(transit - prev_transit)
                jitter += (d - jitter) / 16.0
            prev_transit = transit

            # Once traffic is flowing, a 3 second gap without a FIN means the
            # sender died; stop rather than waiting out the long timeout.
            if idle_deadline is None:
                sock.settimeout(3.0)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    expected = highest_seq + 1 if highest_seq >= 0 else 0
    lost = max(expected - received, 0)
    elapsed = 0.0
    if first_arrival is not None and last_arrival is not None:
        elapsed = max(last_arrival - first_arrival, 0.0)
    bps = (total_bytes * 8.0 / elapsed) if elapsed > 0.001 else 0.0

    return {
        "mode": "udp",
        "side": "server",
        "role": "upload",
        "bytes": total_bytes,
        "seconds": round(elapsed, 6),
        "bits_per_second": round(bps, 2),
        "packets_received": received,
        "packets_expected": expected,
        "packets_lost": lost,
        "lost_percent": round((lost * 100.0 / expected) if expected else 0.0, 4),
        "jitter_ms": round(jitter * 1000.0, 4),
        "out_of_order": out_of_order,
        "saw_fin": finished,
        "datagram_size": datagram_size,
        "errors": [],
    }


def client_udp(host, port, seconds, mbits, datagram_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.connect((host, port))

    filler = make_payload(max(datagram_size - UDP_HEADER.size, 0))
    target_bps = max(mbits, 1) * 1000000.0
    packets_per_sec = max(target_bps / 8.0 / datagram_size, 1.0)
    interval = 1.0 / packets_per_sec

    sent = 0
    errors = []
    start = time.monotonic()
    deadline = start + seconds
    next_send = start

    while True:
        nowt = time.monotonic()
        if nowt >= deadline:
            break
        if nowt < next_send:
            sleep_for = next_send - nowt
            # Below a millisecond, sleeping costs more than it saves.
            if sleep_for > 0.0005:
                time.sleep(sleep_for)
            continue
        packet = UDP_HEADER.pack(MAGIC, sent & 0x7FFFFFFF, monotonic_ns()) + filler
        try:
            sock.send(packet)
            sent += 1
        except OSError as exc:
            # ENOBUFS under load is expected; record it once and keep going.
            msg = str(exc)
            if msg not in errors:
                errors.append(msg)
            time.sleep(0.001)
        next_send += interval
        # If we have fallen far behind, give up on catching up rather than
        # bursting, which would distort the measurement.
        if next_send < nowt - 0.25:
            next_send = nowt

    elapsed = max(time.monotonic() - start, 0.000001)
    fin = UDP_HEADER.pack(MAGIC, UDP_FIN, monotonic_ns()) + filler[:64]
    for _ in range(8):
        try:
            sock.send(fin)
        except OSError:
            pass
        time.sleep(0.02)
    try:
        sock.close()
    except OSError:
        pass

    total_bytes = sent * datagram_size
    return {
        "mode": "udp",
        "side": "client",
        "role": "upload",
        "bytes": total_bytes,
        "seconds": round(elapsed, 6),
        "bits_per_second": round(total_bytes * 8.0 / elapsed, 2),
        "packets_sent": sent,
        "target_mbits": mbits,
        "datagram_size": datagram_size,
        "errors": errors,
    }


# ─────────────────────────────────────────────────────────────────────────────


def main(argv):
    parser = argparse.ArgumentParser(description="HTM throughput probe")
    sub = parser.add_subparsers(dest="command")

    s = sub.add_parser("serve")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--mode", choices=["tcp", "udp", "latency"], default="tcp")
    s.add_argument("--seconds", type=int, default=10)
    s.add_argument("--streams", type=int, default=1)
    s.add_argument("--count", type=int, default=20)
    s.add_argument("--datagram-size", type=int, default=1200)
    s.add_argument("--out", required=True)

    c = sub.add_parser("client")
    c.add_argument("--host", required=True)
    c.add_argument("--port", type=int, required=True)
    c.add_argument("--mode", choices=["tcp", "udp", "latency"], default="tcp")
    c.add_argument("--seconds", type=int, default=10)
    c.add_argument("--streams", type=int, default=1)
    c.add_argument("--count", type=int, default=20)
    c.add_argument("--reverse", action="store_true")
    c.add_argument("--mbits", type=int, default=50)
    c.add_argument("--datagram-size", type=int, default=1200)
    c.add_argument("--connect-timeout", type=float, default=20.0)
    # When set, reach the server through this SOCKS5 proxy "host:port" instead of
    # dialling it directly — for tunnels whose relay exposes only a SOCKS proxy.
    c.add_argument("--socks", default=None)

    args = parser.parse_args(argv)

    if args.command == "serve":
        if args.mode == "tcp":
            result = serve_tcp(args.bind, args.port, args.seconds, max(args.streams, 1))
        elif args.mode == "latency":
            result = serve_latency(args.bind, args.port, max(args.count, 1), args.seconds)
        else:
            result = serve_udp(args.bind, args.port, args.seconds, args.datagram_size)
        with open(args.out, "w") as fh:
            json.dump(result, fh)
            fh.write("\n")
        return 0

    if args.command == "client":
        if args.mode == "tcp":
            result = client_tcp(
                args.host,
                args.port,
                args.seconds,
                max(args.streams, 1),
                args.reverse,
                args.connect_timeout,
                args.socks,
            )
        elif args.mode == "latency":
            result = client_latency(
                args.host, args.port, max(args.count, 1), args.connect_timeout, args.socks
            )
        else:
            result = client_udp(
                args.host, args.port, args.seconds, args.mbits, args.datagram_size
            )
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - report, never traceback into logs
        sys.stdout.write(json.dumps({"error": str(exc)}) + "\n")
        sys.exit(1)
