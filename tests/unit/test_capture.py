import gzip
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import block, packet, pcap_bytes, pcapng_bytes, write_capture
from mawi_context.capture import CaptureError, iter_capture_records


@pytest.mark.parametrize('ng,compressed,endian,nano', [
    (False, False, '<', False), (False, False, '>', False),
    (False, False, '<', True), (False, True, '<', False),
    (True, False, '<', False), (True, False, '>', False),
    (True, True, '<', False),
])
def test_records_preserve_order_timestamp_and_both_lengths(tmp_path, ng, compressed, endian, nano):
    frame = packet(payload=b'abcdefghij')
    kwargs = {'endian': endian} if ng else {'endian': endian, 'nano': nano}
    path = write_capture(tmp_path/'capture', [(10.125, frame, len(frame)), (500.5, frame[:54], len(frame))],
                         ng=ng, compressed=compressed, **kwargs)
    records = list(iter_capture_records(path))
    assert [r.packet_index for r in records] == [1, 2]
    assert [r.timestamp for r in records] == [10.125, 500.5]
    assert [r.captured_length for r in records] == [64, 54]
    assert [r.original_length for r in records] == [64, 64]
    assert [r.frame for r in records] == [frame, frame[:54]]


@pytest.mark.parametrize('ng', [False, True])
def test_rejects_non_ethernet(tmp_path, ng):
    path = write_capture(tmp_path/'bad', ng=ng, linktype=101)
    with pytest.raises(CaptureError, match='datalink'):
        list(iter_capture_records(path))


@pytest.mark.parametrize('data', [b'', b'bad header', pcap_bytes()[:23],
    pcap_bytes()+b'\x00'*15,
    pcap_bytes()+struct.pack('<IIII', 1, 0, 5, 5)+b'ab',
    pcap_bytes()+struct.pack('<IIII', 1, 0, 6, 5)+b'abcdef',
    pcap_bytes(snaplen=4)+struct.pack('<IIII', 1, 0, 5, 5)+b'abcde',
    pcap_bytes()+struct.pack('<IIII', 1, 1000000, 0, 0),
    pcapng_bytes()[:-1], pcapng_bytes()+struct.pack('<II', 6, 11),
    pcapng_bytes()+block(6, struct.pack('<IIIII', 0, 0, 0, 6, 5)+b'abcdef'),
    pcapng_bytes()+block(6, struct.pack('<IIIII', 0, 0, 0, 8, 8)+b'ab'),
    pcapng_bytes()+block(6, struct.pack('<IIIII', 7, 0, 0, 0, 0)),
    pcapng_bytes()[:-4]+b'\x00'*4,
])
def test_malformed_or_truncated_capture_is_fatal(tmp_path, data):
    path = tmp_path/'bad'
    path.write_bytes(data)
    with pytest.raises(CaptureError):
        list(iter_capture_records(path))


def test_pcapng_timestamp_resolution_and_offset(tmp_path):
    path = write_capture(tmp_path/'ng', [(12.5, packet(), 54)], ng=True, resolution=0x8a, offset=10)
    assert next(iter_capture_records(path)).timestamp == 12.5


def test_late_corruption_is_not_clean_eof(tmp_path):
    path = tmp_path/'late'
    path.write_bytes(pcap_bytes([(1, packet(), 54)]) + b'broken')
    records = iter_capture_records(path)
    assert next(records).packet_index == 1
    with pytest.raises(CaptureError):
        next(records)


def test_truncated_gzip_is_fatal(tmp_path):
    path = tmp_path/'bad.gz'
    path.write_bytes(gzip.compress(pcap_bytes())[:-5])
    with pytest.raises(CaptureError):
        list(iter_capture_records(path))


@pytest.mark.parametrize('section_length', [-2, 0, 1000])
def test_declared_pcapng_section_bounds_are_enforced(tmp_path, section_length):
    data = bytearray(pcapng_bytes([(1, packet(), 54)]))
    data[16:24] = struct.pack('<q', section_length)
    path = tmp_path/'section'
    path.write_bytes(data)
    with pytest.raises(CaptureError, match='section'):
        list(iter_capture_records(path))


def test_finite_pcapng_sections_preserve_global_packet_order(tmp_path):
    data = bytearray(pcapng_bytes([(1, packet(), 54)]))
    # IDB is 44 bytes; EPB is 88 bytes, excluding the 28-byte SHB.
    data[16:24] = struct.pack('<q', 132)
    path = tmp_path/'sections'
    path.write_bytes(data+pcapng_bytes([(2, packet(), 54)], endian='>'))
    records = list(iter_capture_records(path))
    assert [r.packet_index for r in records] == [1, 2]
    assert [r.timestamp for r in records] == [1, 2]
