"""Raw ICMP socket wrapper. Requires CAP_NET_RAW (or root)."""
from __future__ import annotations

import select
import socket
import time
from dataclasses import dataclass

from .icmp_packet import build_echo_request, parse_ipv4_icmp


@dataclass
class ProbeResult:
    received: bool = False
    identifier: int | None = None
    sequence: int | None = None
    rtt_us: int = 0
    responder_ip: str = ""
    icmp_type: int = -1
    icmp_code: int = -1


class IcmpSocket:
    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self._sock.setblocking(False)

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "IcmpSocket":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def send_echo(self, dest_ip: str, identifier: int, sequence: int,
                  ttl: int, payload: bytes = b"\x00" * 16) -> bool:
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        pkt = build_echo_request(identifier, sequence, payload)
        try:
            self._sock.sendto(pkt, (dest_ip, 0))
            return True
        except OSError:
            return False

    def recv_reply(self, expected_identifier: int, timeout_s: float) -> ProbeResult:
        """Wait up to timeout_s for a reply matching `expected_identifier`.

        Replies that don't match (other concurrent probes' traffic) are
        discarded. Returns a ProbeResult with received=False on timeout.
        """
        deadline = time.monotonic() + timeout_s
        start = time.monotonic()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ProbeResult()
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                return ProbeResult()
            try:
                data, addr = self._sock.recvfrom(1500)
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
                received=True,
                identifier=ident,
                sequence=seq,
                icmp_type=parsed.type,
                icmp_code=parsed.code,
                responder_ip=addr[0],
                rtt_us=int((time.monotonic() - start) * 1_000_000),
            )
