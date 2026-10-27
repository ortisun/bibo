#!/usr/bin/env python3
"""A labelled FAKE network sinkhole for the agent runtime spike (work package s0-agent-runtime-spike).

Fidelity: fake. It answers every DNS question with its own address and accepts TCP connections on
80 and 443, so that the host names a command line tool tries to reach become visible without any
traffic leaving the machine. It is an observation tool, not a proxy: it reads the TLS server name
(SNI) from the first bytes of a TLS handshake, or the Host header of a plain request, writes one JSON
line per attempt to --log, and closes the connection. It never answers a TLS handshake.

The container that runs it sits on a Docker network created with --internal, so even a tool that
connects to a hard-coded address finds no route. Such attempts are NOT visible here; only names are.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

LOCK = threading.Lock()
START = time.monotonic()
LOG_PATH = Path("/out/sinkhole.jsonl")


def log(entry: dict[str, Any]) -> None:
    entry["t_ms"] = int((time.monotonic() - START) * 1000)
    with LOCK, LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def parse_qname(packet: bytes) -> tuple[str, int, int]:
    """Return (name, type, end offset of the question) for the first question of a DNS packet."""
    pos = 12
    labels: list[str] = []
    while pos < len(packet) and packet[pos] != 0:
        length = packet[pos]
        labels.append(packet[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    qtype = struct.unpack("!H", packet[pos + 1 : pos + 3])[0]
    return ".".join(labels).lower(), qtype, pos + 5


def dns_server(sink_ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))  # noqa: S104 - isolated spike network
    address = socket.inet_aton(sink_ip)
    while True:
        packet, client = sock.recvfrom(2048)
        try:
            name, qtype, end = parse_qname(packet)
        except (struct.error, IndexError):
            continue
        log({"kind": "dns", "name": name, "qtype": qtype, "client": client[0]})
        header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1 if qtype == 1 else 0, 0, 0)
        question = packet[12:end]
        answer = b""
        if qtype == 1:  # A record: point at the sinkhole
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + address
        sock.sendto(header + question + answer, client)


def sni_of(hello: bytes) -> str | None:
    """Server name from a TLS ClientHello, or None."""
    try:
        if hello[0] != 0x16:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        pos += 1 + hello[pos]  # session id
        pos += 2 + struct.unpack("!H", hello[pos : pos + 2])[0]  # cipher suites
        pos += 1 + hello[pos]  # compression
        ext_end = pos + 2 + struct.unpack("!H", hello[pos : pos + 2])[0]
        pos += 2
        while pos + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", hello[pos : pos + 4])
            if ext_type == 0:
                name_len = struct.unpack("!H", hello[pos + 7 : pos + 9])[0]
                return hello[pos + 9 : pos + 9 + name_len].decode("ascii", "replace").lower()
            pos += 4 + ext_len
    except (IndexError, struct.error):
        return None
    return None


def tcp_listener(port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))  # noqa: S104 - isolated spike network
    server.listen(64)
    while True:
        conn, client = server.accept()
        threading.Thread(target=handle, args=(conn, client[0], port), daemon=True).start()


def handle(conn: socket.socket, client: str, port: int) -> None:
    conn.settimeout(3)
    try:
        data = conn.recv(4096)
    except OSError:
        data = b""
    entry: dict[str, Any] = {"kind": "tcp", "port": port, "client": client, "first_bytes": len(data)}
    if data[:1] == b"\x16":
        entry["protocol"] = "tls"
        entry["sni"] = sni_of(data)
    elif data[:4] in {b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"CONN"}:
        entry["protocol"] = "http"
        lines = data.decode("latin-1").split("\r\n")
        entry["request_line"] = lines[0][:200]
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                entry["host"] = line.split(":", 1)[1].strip().lower()
        try:
            conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
    else:
        entry["protocol"] = "unknown"
    log(entry)
    conn.close()


def main(argv: list[str]) -> int:
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sink-ip", required=True, help="the address this container has on the spike network")
    parser.add_argument("--log", default="/out/sinkhole.jsonl")
    parser.add_argument("--ports", default="80,443", help="TCP ports to accept connections on")
    args = parser.parse_args(argv)
    LOG_PATH = Path(args.log)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=dns_server, args=(args.sink_ip,), daemon=True).start()
    for port in (int(p) for p in args.ports.split(",") if p):
        threading.Thread(target=tcp_listener, args=(port,), daemon=True).start()
    print(f"sinkhole (fidelity: fake) on {args.sink_ip}, ports {args.ports}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
