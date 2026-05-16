import struct

from prober.icmp_packet import (
    IcmpType,
    build_echo_request,
    checksum16,
    parse_ipv4_icmp,
)


def test_checksum_zeros_is_all_ones():
    assert checksum16(b"\x00" * 8) == 0xFFFF


def test_echo_request_header_fields():
    pkt = build_echo_request(0xABCD, 0x0102, b"\x01\x02\x03\x04")
    assert len(pkt) == 12
    assert pkt[0] == IcmpType.ECHO_REQUEST
    assert pkt[1] == 0
    assert pkt[4:6] == b"\xAB\xCD"
    assert pkt[6:8] == b"\x01\x02"


def test_built_packet_checksum_is_valid():
    # Re-checksumming a valid ICMP message yields 0.
    pkt = build_echo_request(0x1234, 0x5678, b"\xDE\xAD\xBE\xEF\x00\x00\x00\x00")
    assert checksum16(pkt) == 0


def test_parse_rejects_short():
    assert parse_ipv4_icmp(b"\x00" * 4) is None


def test_parse_echo_reply():
    # Synthesize an IPv4 (IHL=5) + ICMP echo reply.
    ip_header = bytes([0x45]) + b"\x00" * 19
    echo = build_echo_request(0xAAAA, 0x0007)
    echo_reply = bytes([IcmpType.ECHO_REPLY]) + echo[1:]
    parsed = parse_ipv4_icmp(ip_header + echo_reply)
    assert parsed is not None
    assert parsed.type == IcmpType.ECHO_REPLY
    assert parsed.identifier == 0xAAAA
    assert parsed.sequence == 0x0007
    assert parsed.is_error is False


def test_parse_time_exceeded_inner_echo():
    # Outer: IPv4 + ICMP TimeExceeded (type=11, code=0).
    # ICMP payload after the 8-byte outer header is the offending IPv4 header
    # plus first 8 bytes of the original ICMP echo.
    outer_ip = bytes([0x45]) + b"\x00" * 19
    outer_icmp = struct.pack("!BBHHH", IcmpType.TIME_EXCEEDED, 0, 0, 0, 0)
    inner_ip = bytes([0x45]) + b"\x00" * 19
    inner_echo = build_echo_request(0xBEEF, 0x0042)[:8]
    pkt = outer_ip + outer_icmp + inner_ip + inner_echo

    parsed = parse_ipv4_icmp(pkt)
    assert parsed is not None
    assert parsed.type == IcmpType.TIME_EXCEEDED
    assert parsed.is_error is True
    assert parsed.identifier == 0xBEEF
    assert parsed.sequence == 0x0042
