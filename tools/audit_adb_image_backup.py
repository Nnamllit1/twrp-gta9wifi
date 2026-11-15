"""Verify a single uncompressed image in a TWRP v3 ADB backup without extracting it.

Checks protocol CRCs, image length, padding and stream MD5, then compares the
image SHA-256 with an independently obtained partition/firmware hash. This does
not restore anything or establish that file-based/data restores work.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

BLOCK = 512
CHUNK = 1048576


def exact(stream, count):
    body = stream.read(count)
    if len(body) != count:
        raise ValueError('Truncated ADB backup')
    return body


def record(stream, expected_type, crc_offset):
    body = exact(stream, BLOCK)
    if body[:8] != b'TWRP\0\0\0\0' or body[8:24].split(b'\0')[0] != expected_type:
        raise ValueError('Unexpected ADB backup record: expected ' + expected_type.decode())
    unsigned = bytearray(body)
    checksum = struct.unpack_from('<I', unsigned, crc_offset)[0]
    struct.pack_into('<I', unsigned, crc_offset, 0)
    if expected_type == b'md5trailer':
        struct.pack_into('<I', unsigned, 28, 0)
    if zlib.crc32(unsigned) != checksum:
        raise ValueError('ADB backup record CRC mismatch')
    return body


def audit(stream, expected_sha256, expected_bytes):
    if not re.fullmatch('[0-9a-f]{64}', expected_sha256) or not 0 < expected_bytes <= 4 * 1024**3:
        raise ValueError('Expected a partition SHA-256 and a bounded positive image size')
    header = record(stream, b'twstreamheader', 40)
    if struct.unpack_from('<QQ', header, 24) != (1, 3):
        raise ValueError('Only a single-image TWRP v3 stream is supported')
    image = record(stream, b'twimage', 40)
    if struct.unpack_from('<QQ', image, 24) != (expected_bytes, 0):
        raise ValueError('Image size differs or the stream is compressed')
    # Deliberately omit the full backup path, which can contain a device ID.
    name = image[44:].split(b'\0')[0].rsplit(b'/', 1)[-1].decode('ascii', 'strict')
    if not re.fullmatch(r'[A-Za-z0-9_-]+\.emmc\.win', name):
        raise ValueError('Expected a raw partition image name')
    remaining = expected_bytes
    image_sha = hashlib.sha256()
    stream_md5 = hashlib.md5()
    chunks = 0
    while remaining:
        record(stream, b'twdatablock', 24)
        data = exact(stream, CHUNK - BLOCK)
        used = min(remaining, len(data))
        image_sha.update(data[:used])
        stream_md5.update(data)
        if any(data[used:]):
            raise ValueError('Nonzero ADB backup padding')
        remaining -= used
        chunks += 1
    trailer = record(stream, b'md5trailer', 24)
    if trailer[32:72].split(b'\0')[0] != stream_md5.hexdigest().encode():
        raise ValueError('ADB image stream MD5 mismatch')
    # The trailer identifier covers its CRC-bearing header and declared size.
    identified = bytearray(trailer)
    ident = struct.unpack_from('<I', identified, 28)[0]
    struct.pack_into('<I', identified, 28, 0)
    if zlib.crc32(struct.pack('<Q', expected_bytes), zlib.crc32(identified)) != ident:
        raise ValueError('ADB image trailer identifier mismatch')
    record(stream, b'twendadb', 24)
    if stream.read(1):
        raise ValueError('Trailing data after completed ADB backup')
    if image_sha.hexdigest() != expected_sha256:
        raise ValueError('Received image does not match the expected partition SHA-256')
    return {'format': 'TWRP ADB v3', 'image_name': name, 'image_bytes': expected_bytes,
            'image_sha256': image_sha.hexdigest(), 'data_chunks': chunks,
            'protocol_CRCs_and_stream_MD5_verified': True,
            'image_matches_independent_partition_hash': True, 'restore_tested': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backup', type=Path, required=True)
    p.add_argument('--expected-sha256', required=True)
    p.add_argument('--expected-bytes', type=int, required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    if a.report.exists():
        p.error('Use a new report path')
    with a.backup.open('rb') as stream:
        result = audit(stream, a.expected_sha256.lower(), a.expected_bytes)
    a.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
