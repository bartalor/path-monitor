"""Raw ICMP socket helpers. Requires CAP_NET_RAW (or root)."""
from __future__ import annotations

import select
import socket
import time
from dataclasses import dataclass

from .icmp_packet import build_echo_request, parse_ipv4_icmp


@dataclass(frozen=True)
class ProbeResult:
    identifier: int
    sequence: int
    rtt_us: int
    responder_ip: str
    icmp_type: int
    icmp_code: int


def open_icmp_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setblocking(False)
    return sock


def send_echo(sock: socket.socket, dest_ip: str, identifier: int, sequence: int,
              ttl: int, payload: bytes = b"\x00" * 16) -> bool:
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    pkt = build_echo_request(identifier, sequence, payload)
    try:
        sock.sendto(pkt, (dest_ip, 0))
        return True
    except OSError:
        return False


def recv_reply(sock: socket.socket, expected_identifier: int,
               timeout_s: float) -> ProbeResult | None:
    """Wait up to timeout_s for a reply matching `expected_identifier`.

    Replies that don't match (other concurrent probes' traffic) are
    discarded. Returns None on timeout.
    """
    deadline = time.monotonic() + timeout_s
    start = time.monotonic()

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([sock], [], [], remaining)
        if not ready:
            return None
        try:
            data, addr = sock.recvfrom(1500)
        except OSError:
            continue

        parsed = parse_ipv4_icmp(data)
        if parsed is None:
            continue
        ident = parsed.inner_echo.identifier if parsed.inner_echo else parsed.identifier
        if ident != expected_identifier:
            continue

        seq = parsed.inner_echo.sequence if parsed.inner_echo else parsed.sequence
        return ProbeResult(
            identifier=ident,
            sequence=seq,
            icmp_type=parsed.type,
            icmp_code=parsed.code,
            responder_ip=addr[0],
            rtt_us=int((time.monotonic() - start) * 1_000_000),
        )
