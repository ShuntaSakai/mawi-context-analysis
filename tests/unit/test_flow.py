import struct
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import packet, pcap_bytes, write_capture, malformed_tcp_smoke_packet, malformed_udp_packet
from mawi_context.capture import CaptureError
from mawi_context.flow import Endpoint, FLOW_COLUMNS, FlowKey, PacketDecodeError, parse_target_flows

EXPECTED_COLUMNS = [
    'flow_id', 'ip_version', 'protocol', 'start_time', 'end_time', 'duration',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'packet_count',
    'captured_frame_bytes', 'original_frame_bytes', 'ip_bytes', 'transport_payload_bytes',
    'initial_syn_sender_ip', 'initial_syn_sender_port',
    'initial_syn_receiver_ip', 'initial_syn_receiver_port',
]


def parse(tmp_path, frames, timestamps=None, originals=None):
    timestamps = timestamps if timestamps is not None else range(len(frames))
    originals = originals if originals is not None else map(len, frames)
    return parse_target_flows(write_capture(tmp_path/'input', list(zip(timestamps, frames, originals))))


def test_flow_key_reverse_and_numeric_order():
    forward = FlowKey.from_packet('192.0.2.10', 1, '192.0.2.2', 2, 6)
    reverse = FlowKey.from_packet('192.0.2.2', 2, '192.0.2.10', 1, 6)
    assert forward == reverse
    assert forward.endpoint_a == Endpoint('192.0.2.2', 2)
    assert len({forward, reverse}) == 1
    assert FlowKey.from_packet('2001:0db8::1', 2, '2001:db8::1', 1, 17).endpoint_a == Endpoint('2001:db8::1', 1)


@pytest.mark.parametrize('protocol', [1, 58, 0])
def test_key_rejects_other_protocols(protocol):
    with pytest.raises(ValueError):
        FlowKey.from_packet('192.0.2.1', 1, '192.0.2.2', 2, protocol)


@pytest.mark.parametrize('src,dst,sport', [
    ('192.0.2.1', '::1', 1), ('bad', '192.0.2.2', 1),
    ('192.0.2.1', '192.0.2.2', -1), ('192.0.2.1', '192.0.2.2', 65536),
])
def test_key_rejects_invalid_endpoints(src, dst, sport):
    with pytest.raises(ValueError):
        FlowKey.from_packet(src, sport, dst, 2, 6)


def test_direction_gap_ids_intervals_and_counters(tmp_path):
    frames = [packet(flags=18), packet(src='2001:db8::2', dst='2001:db8::1', protocol=17, payload=b'abc'),
              packet(src='192.0.2.2', dst='192.0.2.10', sport=80, dport=1234, payload=b'hello'),
              packet(flags=16, payload=b'ab')]
    result = parse(tmp_path, frames, [10, 11, 500, 501])
    assert result.skipped_packet_counts == {}
    assert list(result.frame.columns) == EXPECTED_COLUMNS == list(FLOW_COLUMNS)
    a, b = result.frame.to_dict('records')
    assert [a['flow_id'], b['flow_id']] == [1, 2]
    assert (a['src_ip'], a['src_port'], a['dst_ip'], a['dst_port']) == ('192.0.2.10', 1234, '192.0.2.2', 80)
    assert (a['start_time'], a['end_time'], a['duration'], a['packet_count']) == (10, 501, 491, 3)
    assert (a['captured_frame_bytes'], a['original_frame_bytes'], a['ip_bytes'], a['transport_payload_bytes']) == (169, 169, 127, 7)
    assert (a['initial_syn_sender_ip'], a['initial_syn_sender_port'], a['initial_syn_receiver_ip'], a['initial_syn_receiver_port']) == ('192.0.2.2', 80, '192.0.2.10', 1234)
    assert (b['ip_version'], b['protocol'], b['packet_count'], b['duration']) == (6, 17, 1, 0)
    assert (b['captured_frame_bytes'], b['original_frame_bytes'], b['ip_bytes'], b['transport_payload_bytes']) == (65, 65, 51, 3)
    assert pd.isna(b['initial_syn_sender_ip'])
    pd.testing.assert_frame_equal(result.frame, parse(tmp_path, frames, [10, 11, 500, 501]).frame)


@pytest.mark.parametrize('flags,protocol', [(18, 6), (16, 6), (0, 17)])
def test_no_plain_syn_metadata(tmp_path, flags, protocol):
    row = parse(tmp_path, [packet(flags=flags, protocol=protocol)]).frame.iloc[0]
    for col in EXPECTED_COLUMNS[-4:]:
        assert pd.isna(row[col])


def test_first_plain_syn_candidate_is_preserved(tmp_path):
    row = parse(tmp_path, [packet(), packet(src='192.0.2.2', dst='192.0.2.10', sport=80, dport=1234)]).frame.iloc[0]
    assert row.initial_syn_sender_ip == '192.0.2.10'


def test_skips_are_deterministic_and_empty_schema_is_stable(tmp_path):
    arp = b'\x00'*12+b'\x08\x06'+b'\x00'*28
    frame = packet()
    frames = [arp, packet(protocol=1), frame[:36], frame[:12], packet(fragment=0x2000)]
    result = parse(tmp_path, frames, originals=[42, 42, 54, 54, 54])
    assert result.frame.empty
    assert list(result.frame.columns) == EXPECTED_COLUMNS
    assert result.skipped_packet_counts == {'non_ip': 1, 'non_tcp_udp': 1, 'capture_truncated_undecodable': 2, 'ip_fragment': 1}
    assert result.skipped_packet_counts == parse(tmp_path, frames, originals=[42, 42, 54, 54, 54]).skipped_packet_counts


@pytest.mark.parametrize('version,protocol,caplen,ip_bytes,payload_bytes', [(4, 6, 54, 50, 10), (6, 17, 62, 58, 10)])
def test_snaplen_payload_lengths_are_declared_header_facts(tmp_path, version, protocol, caplen, ip_bytes, payload_bytes):
    kwargs = {} if version == 4 else {'src': '2001:db8::1', 'dst': '2001:db8::2'}
    frame = packet(protocol=protocol, payload=b'0123456789', **kwargs)
    row = parse(tmp_path, [frame[:caplen]], originals=[len(frame)]).frame.iloc[0]
    assert row.captured_frame_bytes == caplen
    assert row.original_frame_bytes == len(frame)
    assert row.ip_bytes == ip_bytes
    assert row.transport_payload_bytes == payload_bytes


@pytest.mark.parametrize('frame,reason', [
    (b'\x00'*12, 'packet_header_exceeds_declared_length'),
    (packet()[:36], 'ipv4_length_exceeds_original_frame_length'),
    (packet()[:14]+b'\x65'+packet()[15:], 'ethernet_ip_version_mismatch'),
    (packet()[:16]+b'\x00\x10'+packet()[18:], 'malformed_ipv4_length'),
    (packet()[:46]+b'\x10'+packet()[47:], 'malformed_tcp_header_length'),
    (packet(protocol=17)[:38]+b'\x00\x07'+packet(protocol=17)[40:], 'malformed_udp_length'),
    (packet(src='::1', dst='::2')[:54], 'ipv6_length_exceeds_original_frame_length'),
])
def test_complete_record_with_malformed_packet_is_skipped(tmp_path, frame, reason):
    result = parse(tmp_path, [frame])
    assert result.frame.empty
    assert result.skipped_packet_counts == {reason: 1}


def test_container_failure_propagates(tmp_path):
    path = tmp_path/'bad'
    path.write_bytes(pcap_bytes([(1, packet(), 54)])+b'broken')
    with pytest.raises(CaptureError):
        parse_target_flows(path)


def test_ipv6_extension_header_and_vlan(tmp_path):
    frame = packet(src='2001:db8::1', dst='2001:db8::2', protocol=17, payload=b'ab')
    ip = bytearray(frame[14:54])
    ip[4:6] = struct.pack('!H', 18)
    ip[6] = 0
    extended = frame[:14]+ip+bytes([17, 0])+b'\x00'*6+frame[54:]
    vlan = extended[:12]+b'\x81\x00\x00\x01'+extended[12:]
    row = parse(tmp_path, [vlan]).frame.iloc[0]
    assert (row.protocol, row.ip_bytes, row.transport_payload_bytes) == (17, 58, 2)


@pytest.mark.parametrize('ah_length', [8, 12])
def test_malformed_ipv6_authentication_header_is_skipped(tmp_path, ah_length):
    frame = packet(src='2001:db8::1', dst='2001:db8::2', protocol=17)
    ip = bytearray(frame[14:54])
    ip[4:6] = struct.pack('!H', ah_length+8)
    ip[6] = 51
    ah = bytes([17, ah_length//4-2])+b'\x00'*(ah_length-2)
    result = parse(tmp_path, [frame[:14]+ip+ah+frame[54:]])
    assert result.skipped_packet_counts == {'malformed_ipv6_authentication_header_length': 1}


def test_valid_ipv6_authentication_header_payload_counter(tmp_path):
    frame = packet(src='2001:db8::1', dst='2001:db8::2', protocol=17)
    ip = bytearray(frame[14:54])
    ip[4:6] = struct.pack('!H', 24)
    ip[6] = 51
    row = parse(tmp_path, [frame[:14]+ip+bytes([17, 2])+b'\x00'*14+frame[54:]]).frame.iloc[0]
    assert (row.protocol, row.ip_bytes, row.transport_payload_bytes) == (17, 64, 0)


@pytest.mark.parametrize('frame,original,reason', [
    (malformed_tcp_smoke_packet(), 86, 'malformed_tcp_header_length'),
    (malformed_udp_packet(), 42, 'malformed_udp_length'),
])
def test_malformed_transport_skipped_between_valid_packets(tmp_path, frame, original, reason):
    result = parse(tmp_path, [packet(), frame, packet(flags=16)], originals=[54, original, 54])
    assert result.skipped_packet_counts == {reason: 1}
    row = result.frame.iloc[0]
    assert len(result.frame) == 1
    assert (row.packet_count, row.start_time, row.end_time) == (2, 0, 2)
    assert (row.src_port, row.dst_port, row.initial_syn_sender_ip) == (1234, 80, '192.0.2.10')


def test_real_smoke_structure_is_malformed_tcp_not_snaplen_skip(tmp_path):
    from mawi_context.capture import iter_capture_records
    from mawi_context.flow import _decode
    frame = malformed_tcp_smoke_packet()
    assert len(frame) == 54
    assert frame[14] == 0x45
    assert struct.unpack_from('!H', frame, 16)[0] == 72
    assert struct.unpack_from('!H', frame, 20)[0] == 0x4000
    assert frame[23] == 6
    assert struct.unpack_from('!HH', frame, 34) == (0, 0)
    assert frame[46:48] == b'\x00\x00'
    path = write_capture(tmp_path/'smoke', [(1775624416.966622, frame, 86)])
    record = next(iter_capture_records(path))
    assert (record.captured_length, record.original_length) == (54, 86)
    with pytest.raises(PacketDecodeError, match='malformed TCP header length') as raised:
        _decode(record)
    assert raised.value.reason == 'malformed_tcp_header_length'
    assert parse_target_flows(path).skipped_packet_counts == {'malformed_tcp_header_length': 1}


@pytest.mark.parametrize('module_name', ['flow', 'observations'])
def test_unrelated_value_error_is_not_a_packet_skip(tmp_path, monkeypatch, module_name):
    from mawi_context import flow, observations
    from mawi_context.cohort import ContextIndexes
    module = flow if module_name == 'flow' else observations
    def fail(record):
        raise ValueError('unrelated implementation failure')
    monkeypatch.setattr(module, '_decode', fail)
    path = write_capture(tmp_path/'capture', [(0, packet(), 54)])
    with pytest.raises(ValueError, match='unrelated implementation failure'):
        if module_name == 'flow':
            flow.parse_target_flows(path)
        else:
            stage = tmp_path/'stage'; stage.mkdir()
            observations._write_observations(path, ContextIndexes({}, frozenset()), stage)


def test_incomplete_header_error_keeps_stable_reason_and_message():
    from mawi_context.capture import CaptureRecord
    from mawi_context.flow import _decode
    # Defensive decoder branch: normal container reading guarantees frame len.
    record = CaptureRecord(1, 0, b'\x00'*12, 54, 54)
    with pytest.raises(PacketDecodeError, match='incomplete packet header') as raised:
        _decode(record)
    assert raised.value.reason == 'incomplete_packet_header'
