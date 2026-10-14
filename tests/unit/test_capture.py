import gzip
from io import BytesIO
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import block, packet, pcap_bytes, pcapng_bytes, write_capture
from mawi_context.capture import CaptureError, CaptureRecord, iter_capture_records, _records


@pytest.mark.parametrize('ng,compressed,endian,nano', [
    (False, compressed, endian, nano)
    for compressed in (False, True) for endian in ('<', '>') for nano in (False, True)
] + [
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


@pytest.mark.parametrize('caplen,original', [(182, 1208), (118, 1272), (54, 1208)])
@pytest.mark.parametrize('endian', ['<', '>'])
@pytest.mark.parametrize('nano', [False, True])
@pytest.mark.parametrize('compressed', [False, True])
def test_classic_snaplen_is_not_a_record_boundary(tmp_path, caplen, original, endian, nano, compressed):
    # Distinct bytes detect clipping, record misalignment and extra body reads.
    frame = bytes(range(caplen))
    following = b'next record'
    path = write_capture(tmp_path/'classic', [(10.125, frame, original),
                                             (500.5, following, 20)],
                         snaplen=96, endian=endian, nano=nano, compressed=compressed)
    assert list(iter_capture_records(path)) == [
        CaptureRecord(1, 10.125, frame, caplen, original),
        CaptureRecord(2, 500.5, following, 11, 20),
    ]


@pytest.mark.parametrize('endian', ['<', '>'])
@pytest.mark.parametrize('nano', [False, True])
@pytest.mark.parametrize('damage', ['original', 'body', 'header', 'timestamp', 'version', 'snaplen'])
def test_classic_tolerance_does_not_accept_corruption(tmp_path, endian, nano, damage):
    header = pcap_bytes(snaplen=96, endian=endian, nano=nano)
    record = struct.pack(endian+'IIII', 10, 125000000 if nano else 125000, 182, 1208)
    body = bytes(range(182))
    message = 'malformed'
    if damage == 'original':
        record = struct.pack(endian+'IIII', 10, 0, 182, 181)
    elif damage == 'body':
        body = body[:-1]
        message = 'truncated'
    elif damage == 'header':
        # The overrun itself is complete; the following header is partial.
        body += b'\x00'*15
        message = 'truncated'
    elif damage == 'timestamp':
        record = struct.pack(endian+'IIII', 10, 10**9 if nano else 10**6, 182, 1208)
    elif damage == 'version':
        header = header[:4] + struct.pack(endian+'HH', 2, 3) + header[8:]
    elif damage == 'snaplen':
        header = pcap_bytes(snaplen=0, endian=endian, nano=nano)
    path = tmp_path/'bad'
    path.write_bytes(header+record+body)
    with pytest.raises(CaptureError, match=message):
        list(iter_capture_records(path))


@pytest.mark.parametrize('endian', ['<', '>'])
@pytest.mark.parametrize('kind', [2, 6])
@pytest.mark.parametrize('compressed', [False, True])
def test_pcapng_snaplen_overrun_remains_fatal(tmp_path, endian, kind, compressed):
    section = block(0x0a0d0d0a, struct.pack(endian+'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    interface = block(1, struct.pack(endian+'HHI', 1, 0, 96), endian)
    fields = 'IIIII' if kind == 6 else 'HHIIII'
    values = (0, 0, 10125000, 182, 1208) if kind == 6 else (0, 0, 0, 10125000, 182, 1208)
    data = section + interface + block(kind, struct.pack(endian+fields, *values)+bytes(range(182)), endian)
    path = tmp_path/'ng'
    path.write_bytes(gzip.compress(data) if compressed else data)
    with pytest.raises(CaptureError, match='captured/original'):
        list(iter_capture_records(path))


def test_classic_overrun_still_checks_gzip_trailer(tmp_path):
    data = pcap_bytes([(10.125, bytes(range(182)), 1208)], snaplen=96)
    path = tmp_path/'bad.gz'
    path.write_bytes(gzip.compress(data)[:-5])
    with pytest.raises(CaptureError, match='truncated'):
        list(iter_capture_records(path))


@pytest.mark.parametrize('caplen', [16*1024*1024 + 1, 0xffffffff])
def test_huge_classic_overrun_is_rejected_before_body_read(caplen):
    class HeaderOnly(BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 20, 'must reject the length before reading the body'
            return super().read(size)
    stream = HeaderOnly(pcap_bytes(snaplen=96)+struct.pack('<IIII', 1, 0, caplen, caplen))
    with pytest.raises(CaptureError, match='safety limit'):
        list(_records(stream))


@pytest.mark.parametrize('caplen,snaplen', [(16*1024*1024, 96),
                                           (16*1024*1024 + 1, 16*1024*1024 + 1)])
def test_classic_overrun_limit_preserves_boundary_and_prior_acceptance(caplen, snaplen):
    body = b'x'*caplen
    records = list(_records(BytesIO(pcap_bytes([(10.125, body, caplen)], snaplen=snaplen))))
    assert records == [CaptureRecord(1, 10.125, body, caplen, caplen)]
