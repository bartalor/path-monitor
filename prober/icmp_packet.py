"""ICMP echo packet construction and parsing (RFC 792)."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


class IcmpType(IntEnum):
    ECHO_REPLY        = 0
    DEST_UNREACHABLE  = 3
    ECHO_REQUEST      = 8
    TIME_EXCEEDED     = 11


@dataclass(frozen=True)
class EchoHeader:
    type: int
    code: int
    checksum: int
    identifier: int
    sequence: int


@dataclass(frozen=True)
class ParsedReply:
    type: int
    code: int
    identifier: int
    sequence: int
    inner_echo: EchoHeader | None  # set for TimeExceeded / DestUnreachable


def checksum16(data: bytes) -> int:
    """RFC 1071 16-bit ones-complement checksum."""
    if len(data) & 1:
        data = data + b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_echo_request(identifier: int, sequence: int, payload: bytes = b"") -> bytes:
    header = struct.pack("!BBHHH", IcmpType.ECHO_REQUEST, 0, 0, identifier, sequence)
    pkt = header + payload
    cks = checksum16(pkt)
    return struct.pack("!BBHHH", IcmpType.ECHO_REQUEST, 0, cks, identifier, sequence) + payload


def _read_echo_header(buf: bytes) -> EchoHeader | None:
    if len(buf) < 8:
        return None
    t, c, ck, ident, seq = struct.unpack("!BBHHH", buf[:8])
    return EchoHeader(t, c, ck, ident, seq)


def parse_ipv4_icmp(ip_packet: bytes) -> ParsedReply | None:
    """Parse a raw IPv4 packet (kernel hands us the IP header on raw sockets)."""
    if len(ip_packet) < 20:
        return None
    ihl = (ip_packet[0] & 0x0F) * 4
    if ihl < 20 or len(ip_packet) < ihl + 8:
        return None
    icmp = ip_packet[ihl:]
    outer = _read_echo_header(icmp)
    if outer is None:
        return None

    inner: EchoHeader | None = None
    if outer.type in (IcmpType.TIME_EXCEEDED, IcmpType.DEST_UNREACHABLE):
        rest = icmp[8:]
        if len(rest) >= 20:
            inner_ihl = (rest[0] & 0x0F) * 4
            if len(rest) >= inner_ihl + 8:
                inner = _read_echo_header(rest[inner_ihl:inner_ihl + 8])

    return ParsedReply(
        type=outer.type,
        code=outer.code,
        identifier=outer.identifier,
        sequence=outer.sequence,
        inner_echo=inner,
    )
