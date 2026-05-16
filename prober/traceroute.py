"""TTL-limited ICMP traceroute."""
from __future__ import annotations

import hashlib
import socket as _socket
from dataclasses import dataclass

from .icmp_packet import IcmpType
from .icmp_socket import recv_reply, send_echo


@dataclass(frozen=True)
class Hop:
    ttl: int
    ip: str = ""
    rtt_us: int = 0
    responded: bool = False
    is_destination: bool = False


@dataclass(frozen=True)
class TracerouteResult:
    hops: list[Hop]
    path_hash: str


def _hash_path(hops: list[Hop]) -> str:
    h = hashlib.sha256()
    for hop in hops:
        h.update(hop.ip.encode() + b"|")
    return h.hexdigest()[:16]


def run_traceroute(sock: _socket.socket, dest_ip: str, identifier: int,
                   max_hops: int, timeout_s: float) -> TracerouteResult:
    hops: list[Hop] = []
    for ttl in range(1, max_hops + 1):
        if not send_echo(sock, dest_ip, identifier, ttl, ttl):
            hops.append(Hop(ttl=ttl))
            continue
        reply = recv_reply(sock, identifier, timeout_s)
        if reply is None:
            hops.append(Hop(ttl=ttl))
            continue
        is_dest = reply.icmp_type == int(IcmpType.ECHO_REPLY)
        hops.append(Hop(
            ttl=ttl,
            ip=reply.responder_ip,
            rtt_us=reply.rtt_us,
            responded=True,
            is_destination=is_dest,
        ))
        if is_dest:
            break
    return TracerouteResult(hops=hops, path_hash=_hash_path(hops))
