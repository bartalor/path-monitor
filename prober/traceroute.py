"""TTL-limited ICMP traceroute."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .icmp_packet import IcmpType
from .icmp_socket import IcmpSocket


@dataclass
class Hop:
    ttl: int
    ip: str = ""
    rtt_us: int = 0
    responded: bool = False
    is_destination: bool = False


@dataclass
class TracerouteResult:
    hops: list[Hop] = field(default_factory=list)
    path_hash: str = ""


def _hash_path(hops: list[Hop]) -> str:
    h = hashlib.sha256()
    for hop in hops:
        h.update(hop.ip.encode() + b"|")
    return h.hexdigest()[:16]


def run_traceroute(sock: IcmpSocket, dest_ip: str, identifier: int,
                   max_hops: int, timeout_s: float) -> TracerouteResult:
    result = TracerouteResult()
    for ttl in range(1, max_hops + 1):
        seq = ttl
        hop = Hop(ttl=ttl)
        if not sock.send_echo(dest_ip, identifier, seq, ttl):
            result.hops.append(hop)
            continue
        reply = sock.recv_reply(identifier, timeout_s)
        if reply.received:
            hop.responded = True
            hop.ip = reply.responder_ip
            hop.rtt_us = reply.rtt_us
            hop.is_destination = reply.icmp_type == int(IcmpType.ECHO_REPLY)
        result.hops.append(hop)
        if hop.is_destination:
            break
    result.path_hash = _hash_path(result.hops)
    return result
