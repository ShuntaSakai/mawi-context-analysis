"""Deterministic synthetic captures; independent of research implementation."""
import gzip
import ipaddress
import struct


def packet(src='192.0.2.10', dst='192.0.2.2', sport=1234, dport=80,
           protocol=6, flags=2, payload=b'', fragment=0):
    version = ipaddress.ip_address(src).version
    if protocol == 6:
        transport = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, flags, 4096, 0, 0) + payload
    elif protocol == 17:
        transport = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    else:
        transport = b'\x08\x00\x00\x00\x00\x00\x00\x00' + payload
    addresses = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    if version == 4:
        ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(transport), 0, fragment, 64, protocol, 0) + addresses
    else:
        ip = struct.pack('!IHBB', 6 << 28, len(transport), protocol, 64) + addresses
    return b'\x00' * 12 + struct.pack('!H', 0x0800 if version == 4 else 0x86dd) + ip + transport


def pcap_bytes(records=(), *, linktype=1, endian='<', nano=False, snaplen=65535):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    result = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, snaplen, linktype)
    scale = 10**9 if nano else 10**6
    for timestamp, frame, original in records:
        seconds = int(timestamp)
        result += struct.pack(endian + 'IIII', seconds, round((timestamp-seconds)*scale), len(frame), original)
        result += frame
    return result


def block(kind, body, endian='<'):
    body += b'\x00' * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def pcapng_bytes(records=(), *, linktype=1, endian='<', resolution=6, offset=0):
    result = block(0x0a0d0d0a, struct.pack(endian+'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    options = struct.pack(endian+'HH', 9, 1) + bytes([resolution]) + b'\x00'*3
    options += struct.pack(endian+'HHq', 14, 8, offset) + b'\x00'*4
    result += block(1, struct.pack(endian+'HHI', linktype, 0, 65535) + options, endian)
    scale = 2**(resolution & 127) if resolution & 128 else 10**resolution
    for timestamp, frame, original in records:
        ticks = round((timestamp-offset)*scale)
        result += block(6, struct.pack(endian+'IIIII', 0, ticks >> 32, ticks & 0xffffffff, len(frame), original) + frame, endian)
    return result


def write_capture(path, records=(), *, ng=False, compressed=False, **kwargs):
    data = (pcapng_bytes if ng else pcap_bytes)(records, **kwargs)
    path.write_bytes(gzip.compress(data, mtime=0) if compressed else data)
    return path
