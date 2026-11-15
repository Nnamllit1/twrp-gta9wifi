# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only EROFS input inspection; never mounts or executes image files."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc


class Image:
    def __init__(self, path):
        self.path = path
        self.f = path.open('rb')
        self.size = path.stat().st_size
        b = self.at(1024, 3072)
        assert struct.unpack_from('<I', b)[0] == 0xe0f5e1e2
        assert b[12] == 12 and b[13] == 0
        self.compat = struct.unpack_from('<I', b, 8)[0]
        assert self.compat & ~7 == 0 and struct.unpack_from('<I', b, 80)[0] == 0
        if self.compat & 1:
            checksum = struct.unpack_from('<I', b, 4)[0]
            assert crc32c(b[:4] + bytes(4) + b[8:]) == checksum
        self.blocks, self.meta = struct.unpack_from('<II', b, 36)
        self.fs_size = self.blocks * 4096
        assert self.fs_size <= self.size
        self.nodes = {}
        self.walk('/', struct.unpack_from('<H', b, 14)[0], set(), 0)

    def at(self, offset, size):
        assert 0 <= offset <= self.size and 0 <= size <= 64*1024*1024
        assert offset + size <= self.size
        self.f.seek(offset)
        data = self.f.read(size)
        assert len(data) == size
        return data

    def node(self, nid):
        offset = self.meta * 4096 + nid * 32
        assert offset + 64 <= self.fs_size
        data = self.at(offset, 64)
        fmt, count, mode = struct.unpack_from('<3H', data)
        assert fmt < 16 and (fmt >> 1) in (0, 2)
        return {'nid': nid, 'offset': offset, 'format': fmt, 'mode': mode,
                'size': struct.unpack_from('<Q' if fmt & 1 else '<I', data, 8)[0],
                'rawblock': struct.unpack_from('<I', data, 16)[0],
                'isize': 64 if fmt & 1 else 32, 'xsize': 12+4*(count-1) if count else 0}

    def chunks(self, n):
        tail = n['size'] % 4096 if n['format'] >> 1 == 2 else 0
        assert not n['size'] or n['format'] >> 1 != 2 or tail
        whole = n['size'] - tail
        if whole:
            offset = n['rawblock'] * 4096
            assert offset + whole <= self.fs_size
            for pos in range(0, whole, 4*1024*1024):
                yield self.at(offset+pos, min(whole-pos, 4*1024*1024))
        if tail:
            offset = n['offset'] + n['isize'] + n['xsize']
            assert offset % 4096 + tail <= 4096
            yield self.at(offset, tail)

    def read(self, n):
        assert n['size'] <= 64*1024*1024
        return b''.join(self.chunks(n))

    def digest(self, n):
        h = hashlib.sha256()
        for data in self.chunks(n):
            h.update(data)
        return h.hexdigest()

    def walk(self, path, nid, seen, depth):
        assert depth <= 64 and len(self.nodes) < 65536 and path not in self.nodes
        n = self.node(nid)
        self.nodes[path] = n
        if n['mode'] & 0xf000 != 0x4000:
            return
        assert nid not in seen
        seen.add(nid)
        data = self.read(n)
        for offset in range(0, len(data), 4096):
            b = data[offset:offset+4096]
            start = struct.unpack_from('<H', b, 8)[0]
            assert start >= 12 and start % 12 == 0 and start <= len(b)
            count = start // 12
            for i in range(count):
                child, first, kind, _ = struct.unpack_from('<QHBB', b, i*12)
                last = struct.unpack_from('<H', b, (i+1)*12+8)[0] if i+1 < count else len(b)
                assert start <= first < last <= len(b)
                name = b[first:last].rstrip(b'\0').decode('utf8')
                assert name and '/' not in name and '\0' not in name
                if name not in ('.', '..'):
                    self.walk(('/' if path == '/' else path+'/')+name, child, seen, depth+1)
