"""ICMP echo packets (RFC 792). Pure bytes <-> tuples, no I/O."""
from __future__ import annotations

import struct
from enum import IntEnum
from typing import NamedTuple


class IcmpType(IntEnum):
    ECHO_REPLY        = 0
    DEST_UNREACHABLE  = 3
    ECHO_REQUEST      = 8
    TIME_EXCEEDED     = 11


# ICMP header: type, code, checksum, identifier, sequence -- 8 bytes
_HDR = "!BBHHH"
_ERROR_TYPES = (IcmpType.DEST_UNREACHABLE, IcmpType.TIME_EXCEEDED)


class ParsedReply(NamedTuple):
    type: int
    code: int
    identifier: int   # from the inner (quoted) echo if this is an error reply
    sequence: int     # same
    is_error: bool    # True for DEST_UNREACHABLE / TIME_EXCEEDED


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
    body = struct.pack(_HDR, IcmpType.ECHO_REQUEST, 0, 0, identifier, sequence) + payload
    cks  = checksum16(body)
    return struct.pack(_HDR, IcmpType.ECHO_REQUEST, 0, cks, identifier, sequence) + payload


def parse_ipv4_icmp(pkt: bytes) -> ParsedReply | None:
    """Parse a raw IPv4+ICMP packet. Returns None on truncation.

    For error replies (TIME_EXCEEDED / DEST_UNREACHABLE) the router quotes
    back the original IP+ICMP header that failed to deliver; the identifier
    and sequence we care about live in that inner echo, not the outer one.
    Those error replies are unwrapped here so callers always see the
    identifier/sequence of *their* probe.
    """
    if len(pkt) < 20:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl + 8:
        return None

    t, c, _, ident, seq = struct.unpack(_HDR, pkt[ihl:ihl + 8])

    if t in _ERROR_TYPES:
        rest = pkt[ihl + 8:]
        if len(rest) < 20:
            return None
        inner_ihl = (rest[0] & 0x0F) * 4
        if len(rest) < inner_ihl + 8:
            return None
        _, _, _, ident, seq = struct.unpack(_HDR, rest[inner_ihl:inner_ihl + 8])
        return ParsedReply(t, c, ident, seq, is_error=True)

    return ParsedReply(t, c, ident, seq, is_error=False)
