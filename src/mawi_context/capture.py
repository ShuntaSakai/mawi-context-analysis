"""Strict, record-wise Ethernet PCAP/PCAPNG reading (including gzip)."""
from collections.abc import Iterator
from dataclasses import dataclass
import gzip
from pathlib import Path
import struct
from typing import BinaryIO


class CaptureError(ValueError):
    """Invalid, incomplete, or unsupported capture container."""


@dataclass(frozen=True)
class CaptureRecord:
    packet_index: int
    timestamp: float
    frame: bytes
    captured_length: int
    original_length: int


def _read(stream: BinaryIO, size: int, *, eof: bool = False) -> bytes:
    data = stream.read(size)
    if eof and not data:
        return data
    if len(data) != size:
        raise CaptureError('truncated capture header, record, or block')
    return data


def _lengths(caplen: int, original: int, snaplen: int) -> None:
    if caplen > original or (snaplen and caplen > snaplen):
        raise CaptureError('malformed captured/original record length')


def _ethernet(linktype: int) -> None:
    if linktype != 1:
        raise CaptureError(f'unsupported datalink: {linktype}')


_PCAP = {
    b'\xd4\xc3\xb2\xa1': ('<', 10**6), b'\xa1\xb2\xc3\xd4': ('>', 10**6),
    b'\x4d\x3c\xb2\xa1': ('<', 10**9), b'\xa1\xb2\x3c\x4d': ('>', 10**9),
}


def _pcap(stream: BinaryIO, magic: bytes) -> Iterator[CaptureRecord]:
    endian, scale = _PCAP[magic]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian+'HHIIII', _read(stream, 20))
    if (major, minor) != (2, 4) or snaplen == 0:
        raise CaptureError('malformed PCAP header')
    _ethernet(linktype)
    index = 0
    while header := _read(stream, 16, eof=True):
        seconds, fraction, caplen, original = struct.unpack(endian+'IIII', header)
        if fraction >= scale:
            raise CaptureError('malformed PCAP timestamp')
        _lengths(caplen, original, snaplen)
        frame = _read(stream, caplen)
        index += 1
        yield CaptureRecord(index, seconds+fraction/scale, frame, caplen, original)


def _options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos < len(data):
        if len(data)-pos < 4:
            raise CaptureError('truncated PCAPNG option')
        code, length = struct.unpack_from(endian+'HH', data, pos)
        pos += 4
        if code == 0:
            if length or any(data[pos:]):
                raise CaptureError('malformed PCAPNG option terminator')
            return
        padded = (length+3) & ~3
        if pos+padded > len(data):
            raise CaptureError('truncated PCAPNG option value')
        yield code, data[pos:pos+length]
        pos += padded


def _pcapng(stream: BinaryIO, magic: bytes) -> Iterator[CaptureRecord]:
    endian = '<'
    interfaces = []
    index = 0
    section_remaining: int | None = None
    while magic:
        raw_size = _read(stream, 4)
        if magic == b'\x0a\x0d\x0d\x0a':
            if section_remaining not in (None, 0):
                raise CaptureError('truncated declared PCAPNG section')
            bom = _read(stream, 4)
            if bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise CaptureError('malformed PCAPNG byte-order magic')
            size = struct.unpack(endian+'I', raw_size)[0]
            if size < 28 or size % 4:
                raise CaptureError('malformed PCAPNG section length')
            tail = _read(stream, size-12)
            body = bom + tail[:-4]
            interfaces = []
            if struct.unpack_from(endian+'HH', body, 4) != (1, 0):
                raise CaptureError('unsupported PCAPNG version')
            section_length = struct.unpack_from(endian+'q', body, 8)[0]
            if section_length < -1 or (section_length >= 0 and section_length % 4):
                raise CaptureError('malformed PCAPNG section length')
            section_remaining = None if section_length == -1 else section_length
            list(_options(body[16:], endian))
        else:
            size = struct.unpack(endian+'I', raw_size)[0]
            if size < 12 or size % 4:
                raise CaptureError('malformed PCAPNG block length')
            if section_remaining is not None:
                if size > section_remaining:
                    raise CaptureError('block exceeds declared PCAPNG section')
                section_remaining -= size
            tail = _read(stream, size-8)
            body = tail[:-4]
        if struct.unpack(endian+'I', tail[-4:])[0] != size:
            raise CaptureError('PCAPNG block length trailer mismatch')
        kind = struct.unpack(endian+'I', magic)[0]
        if kind == 1:
            if len(body) < 8:
                raise CaptureError('truncated PCAPNG interface')
            linktype, reserved, snaplen = struct.unpack_from(endian+'HHI', body)
            _ethernet(linktype)
            if reserved:
                raise CaptureError('malformed PCAPNG interface')
            scale, offset = 10**6, 0
            for code, value in _options(body[8:], endian):
                if code == 9:
                    if len(value) != 1:
                        raise CaptureError('malformed timestamp resolution')
                    scale = 2**(value[0] & 127) if value[0] & 128 else 10**value[0]
                elif code == 14:
                    if len(value) != 8:
                        raise CaptureError('malformed timestamp offset')
                    offset = struct.unpack(endian+'q', value)[0]
            interfaces.append((snaplen, scale, offset))
        elif kind in (2, 6):
            if len(body) < 20:
                raise CaptureError('truncated PCAPNG packet block')
            if kind == 6:
                interface, high, low, caplen, original = struct.unpack_from(endian+'IIIII', body)
            else:
                interface, _, high, low, caplen, original = struct.unpack_from(endian+'HHIIII', body)
            if interface >= len(interfaces):
                raise CaptureError('unknown PCAPNG interface')
            snaplen, scale, offset = interfaces[interface]
            _lengths(caplen, original, snaplen)
            end = 20 + ((caplen+3) & ~3)
            if end > len(body):
                raise CaptureError('truncated PCAPNG packet body')
            list(_options(body[end:], endian))
            index += 1
            yield CaptureRecord(index, ((high << 32) | low)/scale+offset,
                                body[20:20+caplen], caplen, original)
        elif kind == 3:
            # Simple Packet Blocks have no timestamp; do not invent one.
            raise CaptureError('unsupported timestamp-less PCAPNG Simple Packet Block')
        magic = _read(stream, 4, eof=True)
    if section_remaining not in (None, 0):
        raise CaptureError('truncated declared PCAPNG section at EOF')


def iter_capture_records(path: Path) -> Iterator[CaptureRecord]:
    """Stream records in capture order with 1-based indexes and both lengths.

    A complete snaplen-limited record is valid. Container truncation is fatal,
    including corruption encountered after earlier records have been yielded.
    """
    try:
        with Path(path).open('rb') as raw:
            compressed = raw.read(2) == b'\x1f\x8b'
            raw.seek(0)
            if compressed:
                with gzip.GzipFile(fileobj=raw) as stream:
                    yield from _records(stream)
            else:
                yield from _records(raw)
    except (EOFError, gzip.BadGzipFile, struct.error) as error:
        raise CaptureError(f'malformed or truncated capture: {error}') from error


def _records(stream: BinaryIO) -> Iterator[CaptureRecord]:
    magic = _read(stream, 4)
    if magic in _PCAP:
        yield from _pcap(stream, magic)
    elif magic == b'\x0a\x0d\x0d\x0a':
        yield from _pcapng(stream, magic)
    else:
        raise CaptureError('malformed capture header: unknown magic')
