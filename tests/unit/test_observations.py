"""Packet facts and routing using tiny synthetic captures only."""
import struct
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import packet, pcap_bytes, write_capture
from mawi_context import observations as obs
from mawi_context.capture import CaptureError
from mawi_context.cohort import ContextIndexes
from mawi_context.flow import FlowKey, PacketDecodeError, parse_target_flows

A, B, C = '192.0.2.10', '192.0.2.2', '198.51.100.1'
FIELDS = [
    ('packet_index', pa.int64(), False), ('timestamp', pa.float64(), False),
    ('ip_version', pa.uint8(), False), ('protocol', pa.uint8(), False),
    ('src_ip', pa.string(), False), ('src_port', pa.uint16(), False),
    ('dst_ip', pa.string(), False), ('dst_port', pa.uint16(), False),
    ('captured_frame_length', pa.uint32(), False),
    ('original_frame_length', pa.uint32(), False),
    ('ip_total_length', pa.uint32(), False),
    ('transport_payload_length', pa.uint32(), False),
    ('tcp_flags_raw', pa.uint8(), True),
]


def indexes(protocols=(6, 17), candidates=(A,)):
    return ContextIndexes({FlowKey.from_packet(A, 1234, B, 80, p): 100+p
                           for p in protocols}, frozenset(candidates))


def write_rows(tmp_path, frames, *, lookup=None, originals=None, timestamps=None):
    originals = originals if originals is not None else map(len, frames)
    timestamps = timestamps if timestamps is not None else range(len(frames))
    capture = write_capture(tmp_path/'input', zip(timestamps, frames, originals))
    stage = tmp_path/'stage'
    stage.mkdir()
    counts = obs._write_observations(capture, lookup or indexes(), stage)
    target = pq.read_table(stage/'target_packets.parquet')
    source = pq.read_table(stage/'source_context_packets.parquet')
    assert counts == (target.num_rows, source.num_rows)
    return target, source


@pytest.mark.parametrize('target', [False, True])
def test_exact_schema_order_types_nullability(target):
    schema = obs.TARGET_PACKET_SCHEMA if target else obs.SOURCE_CONTEXT_SCHEMA
    expected = ([('target_flow_id', pa.int64(), False)] if target else []) + FIELDS
    assert schema.equals(pa.schema([pa.field(*f) for f in expected]), check_metadata=True)
    assert schema.names == [f[0] for f in expected]


@pytest.mark.parametrize('protocol,flags', [(17, 0), (6, 0), (6, 0xff), (6, 16)])
def test_target_forward_reverse_preserve_id_direction_and_raw_flags(tmp_path, protocol, flags):
    frames = [packet(protocol=protocol, flags=flags),
              packet(src=B, dst=A, sport=80, dport=1234, protocol=protocol, flags=flags)]
    target, _ = write_rows(tmp_path, frames)
    rows = target.to_pylist()
    assert [r['target_flow_id'] for r in rows] == [100+protocol]*2
    assert [(r['src_ip'], r['src_port'], r['dst_ip'], r['dst_port']) for r in rows] == [
        (A, 1234, B, 80), (B, 80, A, 1234)]
    assert [r['tcp_flags_raw'] for r in rows] == [None if protocol == 17 else flags]*2


def test_non_target_is_not_in_target_stream(tmp_path):
    target, source = write_rows(tmp_path, [packet(dport=443)])
    assert target.num_rows == 0
    assert source.num_rows == 1


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('flags,retained', [
    (2, True), (18, True), (4, True), (1, True), (17, True),
    (16, False), (24, False), (0, False),
])
def test_tcp_source_context_control_bits_in_either_direction(tmp_path, reverse, flags, retained):
    kwargs = {'src': C, 'dst': A} if reverse else {'src': A, 'dst': C}
    target, source = write_rows(tmp_path, [packet(flags=flags, payload=b'private', **kwargs)])
    assert target.num_rows == 0
    assert source.num_rows == int(retained)
    if retained:
        assert source.to_pylist()[0]['tcp_flags_raw'] == flags


def test_unrelated_tcp_control_is_excluded(tmp_path):
    target, source = write_rows(tmp_path, [packet(src=C, dst=B)])
    assert (target.num_rows, source.num_rows) == (0, 0)


@pytest.mark.parametrize('outbound', [True, False])
def test_udp_source_context_is_outbound_only(tmp_path, outbound):
    kwargs = {'src': A, 'dst': C} if outbound else {'src': C, 'dst': A}
    target, source = write_rows(tmp_path, [packet(protocol=17, payload=b'private', **kwargs)])
    assert target.num_rows == 0
    assert source.num_rows == int(outbound)
    if outbound:
        assert source.to_pylist()[0]['tcp_flags_raw'] is None


def test_shared_source_is_once_and_packet_can_enter_both_streams(tmp_path):
    lookup = indexes()
    lookup.target_flow_by_key[FlowKey.from_packet(A, 1234, C, 80, 6)] = 999
    target, source = write_rows(tmp_path, [packet()], lookup=lookup)
    assert (target.num_rows, source.num_rows) == (1, 1)
    assert {k: v for k, v in target.to_pylist()[0].items() if k != 'target_flow_id'} == source.to_pylist()[0]


def test_header_facts_timestamp_raw_index_and_snaplen(tmp_path):
    frame = packet(flags=18, payload=b'0123456789')
    target, source = write_rows(tmp_path, [packet(protocol=1), frame[:54]],
                              originals=[42, len(frame)], timestamps=[1, 10.125])
    row = source.to_pylist()[0]
    assert row == dict(packet_index=2, timestamp=10.125, ip_version=4, protocol=6,
                       src_ip=A, src_port=1234, dst_ip=B, dst_port=80,
                       captured_frame_length=54, original_frame_length=64,
                       ip_total_length=50, transport_payload_length=10, tcp_flags_raw=18)
    assert target.to_pylist()[0]['packet_index'] == 2


def test_no_payload_or_interpretation_columns(tmp_path):
    target, source = write_rows(tmp_path, [packet(payload=b'secret application payload')])
    assert target.schema.names == ['target_flow_id'] + [f[0] for f in FIELDS]
    assert source.schema.names == [f[0] for f in FIELDS]
    assert all(not isinstance(v, bytes) for row in target.to_pylist() + source.to_pylist() for v in row.values())


@pytest.mark.parametrize('frames', [[], [packet(src=C, dst=B)]])
def test_empty_files_are_readable_with_exact_schema(tmp_path, frames):
    target, source = write_rows(tmp_path, frames)
    assert (target.num_rows, source.num_rows) == (0, 0)
    assert target.schema.equals(obs.TARGET_PACKET_SCHEMA, check_metadata=True)
    assert source.schema.equals(obs.SOURCE_CONTEXT_SCHEMA, check_metadata=True)


def test_bounded_buffers_write_multiple_row_groups_and_decode_once(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, '_ROW_BUFFER_LIMIT', 3)
    decode = obs._decode
    calls = []
    def counted(record):
        calls.append(record.packet_index)
        return decode(record)
    monkeypatch.setattr(obs, '_decode', counted)
    target, source = write_rows(tmp_path, [packet()]*8)
    assert (target.num_rows, source.num_rows) == (8, 8)
    assert target.column('packet_index').to_pylist() == list(range(1, 9))
    assert source.column('packet_index').to_pylist() == list(range(1, 9))
    assert calls == list(range(1, 9))
    for name in ('target_packets', 'source_context_packets'):
        metadata = pq.ParquetFile(tmp_path/'stage'/f'{name}.parquet').metadata
        assert metadata.num_row_groups == 3
        assert [metadata.row_group(i).num_rows for i in range(3)] == [3, 3, 2]


@pytest.mark.parametrize('kind', ['packet', 'container'])
def test_malformed_complete_packet_or_late_container_is_fatal(tmp_path, kind):
    capture = tmp_path/'bad'
    capture.write_bytes(pcap_bytes([(1, packet(), 54)]) + b'broken' if kind == 'container'
                        else pcap_bytes([(1, b'\x00'*12, 12)]))
    stage = tmp_path/'stage'
    stage.mkdir()
    with pytest.raises(CaptureError if kind == 'container' else PacketDecodeError):
        obs._write_observations(capture, indexes(), stage)


def test_safely_undecodable_truncation_and_fragments_are_skipped(tmp_path):
    target, source = write_rows(tmp_path, [packet()[:36], packet(fragment=0x2000), packet()],
                              originals=[54, 54, 54])
    assert target.column('packet_index').to_pylist() == [3]
    assert source.column('packet_index').to_pylist() == [3]


def test_ipv6_vlan_extensions_share_task2_length_and_tuple_semantics(tmp_path):
    frame = packet(src='2001:db8::1', dst='2001:db8::2', protocol=17, payload=b'ab')
    ip = bytearray(frame[14:54])
    ip[4:6] = struct.pack('!H', 18)
    ip[6] = 0
    extended = frame[:14]+ip+bytes([17, 0])+b'\x00'*6+frame[54:]
    vlan = extended[:12]+b'\x81\x00\x00\x01'+extended[12:]
    key = FlowKey.from_packet('2001:db8::1', 1234, '2001:db8::2', 80, 17)
    target, source = write_rows(tmp_path, [vlan], lookup=ContextIndexes({key: 7}, frozenset({'2001:db8::1'})))
    flow = parse_target_flows(tmp_path/'input').frame.iloc[0]
    row = target.to_pylist()[0]
    assert row['target_flow_id'] == 7
    assert (row['ip_version'], row['ip_total_length'], row['transport_payload_length']) == (6, 58, 2)
    assert (row['ip_total_length'], row['transport_payload_length']) == (flow.ip_bytes, flow.transport_payload_bytes)
    assert source.num_rows == 1
