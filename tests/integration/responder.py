"""Tiny ICMP echo responder.

Run as a child process inside a netns to act as the "target" for integration
tests. Reads echo requests off a raw socket, flips type+checksum, sends back.
"""
from __future__ import annotations

import signal
import socket
import struct
import sys

from prober.icmp_packet import IcmpType, checksum16, parse_ipv4_icmp


def _build_echo_reply(identifier: int, sequence: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", IcmpType.ECHO_REPLY, 0, 0, identifier, sequence)
    cks = checksum16(header + payload)
    return struct.pack("!BBHHH", IcmpType.ECHO_REPLY, 0, cks, identifier, sequence) + payload


def main() -> int:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    while True:
        ip_packet, src = sock.recvfrom(65535)
        parsed = parse_ipv4_icmp(ip_packet)
        if parsed is None or parsed.type != IcmpType.ECHO_REQUEST:
            continue
        ihl = (ip_packet[0] & 0x0F) * 4
        payload = ip_packet[ihl + 8:]
        reply = _build_echo_reply(parsed.identifier, parsed.sequence, payload)
        sock.sendto(reply, src)


if __name__ == "__main__":
    sys.exit(main())
