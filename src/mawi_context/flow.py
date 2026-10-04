"""Canonical TCP/UDP flows observed across one capture, without timeouts."""
from collections import Counter
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import struct

import pandas as pd

from mawi_context.capture import CaptureRecord, iter_capture_records


FLOW_COLUMNS = (
    'flow_id', 'ip_version', 'protocol', 'start_time', 'end_time', 'duration',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'packet_count',
    'captured_frame_bytes', 'original_frame_bytes', 'ip_bytes', 'transport_payload_bytes',
    'initial_syn_sender_ip', 'initial_syn_sender_port',
    'initial_syn_receiver_ip', 'initial_syn_receiver_port',
)


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int

    def __post_init__(self):
        object.__setattr__(self, 'ip', str(ipaddress.ip_address(self.ip)))
        if not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError('port must be an integer in [0, 65535]')

    @property
    def _order(self) -> tuple[int, int, int]:
        address = ipaddress.ip_address(self.ip)
        return address.version, int(address), self.port


@dataclass(frozen=True)
class FlowKey:
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: int

    def __post_init__(self):
        if self.protocol not in (6, 17):
            raise ValueError('only TCP/UDP flow keys are supported')
        if self.endpoint_a._order[0] != self.endpoint_b._order[0]:
            raise ValueError('flow endpoints must have the same IP version')
        if self.endpoint_a._order > self.endpoint_b._order:
            a, b = self.endpoint_a, self.endpoint_b
            object.__setattr__(self, 'endpoint_a', b)
            object.__setattr__(self, 'endpoint_b', a)

    @classmethod
    def from_packet(cls, src_ip: str, src_port: int, dst_ip: str,
                    dst_port: int, protocol: int) -> 'FlowKey':
        return cls(Endpoint(src_ip, src_port), Endpoint(dst_ip, dst_port), protocol)


@dataclass
class FlowParseResult:
    frame: pd.DataFrame
    skipped_packet_counts: dict[str, int]


class PacketDecodeError(ValueError):
    """Malformed packet facts in an otherwise complete capture record."""


class _SkipPacket(Exception):
    pass


@dataclass(frozen=True)
class _PacketFacts:
    ip_version: int
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_total_length: int
    transport_payload_length: int
    tcp_flags: int


def _decode(record: CaptureRecord) -> _PacketFacts:
    """Decode each frame once, validating declared bounds before using facts.

    Payload lengths are declarations from IP/transport headers, never the
    size of a captured payload slice. No application payload is retained.
    Fragments are excluded because no complete transport-length fact is
    safely available without reassembly.
    """
    frame = record.frame

    def need(end: int, limit: int | None = None) -> None:
        if end > record.original_length or (limit is not None and end > limit):
            raise PacketDecodeError('packet header exceeds declared length')
        if end > len(frame):
            if record.captured_length < record.original_length:
                raise _SkipPacket('capture_truncated_undecodable')
            raise PacketDecodeError('incomplete packet header')

    need(14)
    ethertype = struct.unpack_from('!H', frame, 12)[0]
    pos = 14
    while ethertype in (0x8100, 0x88a8, 0x9100):
        need(pos+4)
        ethertype = struct.unpack_from('!H', frame, pos+2)[0]
        pos += 4
    if ethertype not in (0x0800, 0x86dd):
        raise _SkipPacket('non_ip')
    ip_start = pos
    version = 4 if ethertype == 0x0800 else 6
    need(pos+1)
    if frame[pos] >> 4 != version:
        raise PacketDecodeError('Ethernet/IP version mismatch')
    if version == 4:
        need(pos+20)
        header_length = (frame[pos] & 15)*4
        total = struct.unpack_from('!H', frame, pos+2)[0]
        if header_length < 20 or total < header_length:
            raise PacketDecodeError('malformed IPv4 length')
        end = ip_start+total
        if end > record.original_length:
            raise PacketDecodeError('IPv4 length exceeds original frame length')
        need(pos+header_length, end)
        protocol = frame[pos+9]
        src = str(ipaddress.ip_address(frame[pos+12:pos+16]))
        dst = str(ipaddress.ip_address(frame[pos+16:pos+20]))
        if struct.unpack_from('!H', frame, pos+6)[0] & 0x3fff:
            raise _SkipPacket('ip_fragment')
        pos += header_length
    else:
        need(pos+40)
        payload_length = struct.unpack_from('!H', frame, pos+4)[0]
        total = 40+payload_length
        end = ip_start+total
        if end > record.original_length:
            raise PacketDecodeError('IPv6 length exceeds original frame length')
        protocol = frame[pos+6]
        src = str(ipaddress.ip_address(frame[pos+8:pos+24]))
        dst = str(ipaddress.ip_address(frame[pos+24:pos+40]))
        pos += 40
        # Walk extension headers in wire order; do not assume transport follows
        # the base header. ESP is opaque and remains a non-TCP/UDP protocol.
        while protocol in (0, 43, 44, 51, 60):
            need(pos+2, end)
            following = frame[pos]
            if protocol == 44:
                length = 8
                need(pos+length, end)
                fragment = struct.unpack_from('!H', frame, pos+2)[0]
                if fragment & 0xfff9:
                    raise _SkipPacket('ip_fragment')
            elif protocol == 51:
                length = (frame[pos+1]+2)*4
                if length < 12 or length % 8:
                    raise PacketDecodeError('malformed IPv6 authentication header length')
            else:
                length = (frame[pos+1]+1)*8
            need(pos+length, end)
            pos += length
            protocol = following
    if protocol not in (6, 17):
        raise _SkipPacket('non_tcp_udp')
    minimum = 20 if protocol == 6 else 8
    need(pos+minimum, end)
    sport, dport = struct.unpack_from('!HH', frame, pos)
    flags = 0
    if protocol == 6:
        header_length = (frame[pos+12] >> 4)*4
        if header_length < 20:
            raise PacketDecodeError('malformed TCP header length')
        need(pos+header_length, end)
        payload = end-pos-header_length
        flags = frame[pos+13]
    else:
        length = struct.unpack_from('!H', frame, pos+4)[0]
        if length < 8 or pos+length > end:
            raise PacketDecodeError('malformed UDP length')
        payload = length-8
    # A missing body without a snaplen-limited record is malformed, even if
    # all transport headers were captured. Snaplen does not invent bytes.
    if record.captured_length == record.original_length:
        need(end)
    return _PacketFacts(version, protocol, src, dst, sport, dport, total, payload, flags)


def parse_target_flows(path: Path) -> FlowParseResult:
    """Aggregate one observation window; src/dst retain capture-first direction.

    start_time/end_time are first/last observed timestamps in capture order,
    not full-communication boundaries. IDs are 1-based first-observation order.
    captured_frame_bytes/original_frame_bytes sum the separate record facts;
    ip_bytes sums declared IP total lengths (IPv6 includes its base header);
    transport_payload_bytes sums declared TCP/UDP payload lengths.
    """
    flows: dict[FlowKey, dict] = {}
    skipped: Counter[str] = Counter()
    for record in iter_capture_records(path):
        try:
            facts = _decode(record)
        except _SkipPacket as error:
            skipped[str(error)] += 1
            continue
        key = FlowKey.from_packet(facts.src_ip, facts.src_port, facts.dst_ip,
                                  facts.dst_port, facts.protocol)
        if key not in flows:
            flows[key] = dict(
                flow_id=len(flows)+1, ip_version=facts.ip_version, protocol=facts.protocol,
                start_time=record.timestamp, end_time=record.timestamp, duration=0.0,
                src_ip=facts.src_ip, src_port=facts.src_port,
                dst_ip=facts.dst_ip, dst_port=facts.dst_port, packet_count=0,
                captured_frame_bytes=0, original_frame_bytes=0, ip_bytes=0,
                transport_payload_bytes=0, initial_syn_sender_ip=None,
                initial_syn_sender_port=None, initial_syn_receiver_ip=None,
                initial_syn_receiver_port=None,
            )
        row = flows[key]
        row['end_time'] = record.timestamp
        row['duration'] = row['end_time']-row['start_time']
        row['packet_count'] += 1
        row['captured_frame_bytes'] += record.captured_length
        row['original_frame_bytes'] += record.original_length
        row['ip_bytes'] += facts.ip_total_length
        row['transport_payload_bytes'] += facts.transport_payload_length
        if facts.protocol == 6 and facts.tcp_flags & 2 and not facts.tcp_flags & 16 and row['initial_syn_sender_ip'] is None:
            row.update(initial_syn_sender_ip=facts.src_ip, initial_syn_sender_port=facts.src_port,
                       initial_syn_receiver_ip=facts.dst_ip, initial_syn_receiver_port=facts.dst_port)
    return FlowParseResult(pd.DataFrame(flows.values(), columns=FLOW_COLUMNS), dict(sorted(skipped.items())))
