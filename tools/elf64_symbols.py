# SPDX-License-Identifier: Apache-2.0
"""Read-only ELF64 dynamic-symbol inspection; never loads or executes binaries."""
from pathlib import Path
import struct


class Elf:
    def __init__(self, data):
        self.data = data
        assert data[:6] == b'\x7fELF\x02\x01'
        assert struct.unpack_from('<H', data, 18)[0] == 183
        off = struct.unpack_from('<Q', data, 40)[0]
        es, count, names = struct.unpack_from('<HHH', data, 58)
        assert es == 64 and count < 65536
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', data, off+i*es) for i in range(count)]
        strings = self.section_data(names)
        self.names = [self.string(strings, s[0]) for s in self.sections]
        self.symbols = []
        self.needed = []
        self.soname = None
        self.plt = {}
        for idx, sec in enumerate(self.sections):
            if sec[1] == 11:
                strings = self.section_data(sec[6])
                for pos in range(sec[4], sec[4]+sec[5], sec[9]):
                    name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, pos)
                    self.symbols.append(dict(name=self.string(strings, name), info=info,
                                             section=shndx, value=value, size=size))
            if sec[1] == 6:
                strings = self.section_data(sec[6])
                for pos in range(sec[4], sec[4]+sec[5], sec[9]):
                    tag, val = struct.unpack_from('<qQ', data, pos)
                    if tag == 1:
                        self.needed.append(self.string(strings, val))
                    elif tag == 14:
                        self.soname = self.string(strings, val)
        if '.rela.plt' in self.names and '.plt' in self.names:
            rel = self.sections[self.names.index('.rela.plt')]
            plt = self.sections[self.names.index('.plt')]
            for i, pos in enumerate(range(rel[4], rel[4]+rel[5], rel[9])):
                _, info, _ = struct.unpack_from('<QQq', data, pos)
                self.plt[plt[3]+32+16*i] = self.symbols[info >> 32]['name']

    @staticmethod
    def string(data, pos):
        return data[pos:data.index(0, pos)].decode('utf8', 'replace')

    def section_data(self, idx):
        sec = self.sections[idx]
        return self.data[sec[4]:sec[4]+sec[5]]

    def defined(self):
        return {s['name'] for s in self.symbols if s['section'] and s['info'] >> 4 in (1, 2)}

    def required(self):
        return {s['name'] for s in self.symbols if not s['section'] and s['info'] >> 4 == 1}

    def code(self, name):
        sym = next(s for s in self.symbols if s['name'] == name and s['section'])
        sec = self.sections[sym['section']]
        pos = sec[4] + sym['value'] - sec[3]
        return sym, self.data[pos:pos+sym['size']]



def versions(e):
    required = {}
    defined = {}
    for name, output, kind in (('.gnu.version_r', required, 'need'), ('.gnu.version_d', defined, 'def')):
        if name not in e.names:
            continue
        section = e.sections[e.names.index(name)]
        data = e.section_data(e.names.index(name))
        strings = e.section_data(section[6])
        pos = 0
        seen = set()
        while pos < len(data):
            assert pos not in seen
            seen.add(pos)
            if kind == 'need':
                version, count, filename, aux, nxt = struct.unpack_from('<HHIII', data, pos)
                assert version == 1
                ap = pos+aux
                for _ in range(count):
                    _, _, index, vn, step = struct.unpack_from('<IHHII', data, ap)
                    output[index & 0x7fff] = (e.string(strings, vn), e.string(strings, filename))
                    ap += step
            else:
                version, flags, index, count, _, aux, nxt = struct.unpack_from('<HHHHIII', data, pos)
                assert version == 1 and count
                vn, _ = struct.unpack_from('<II', data, pos+aux)
                output[index & 0x7fff] = (e.string(strings, vn), e.soname)
            if not nxt:
                break
            pos += nxt
    if '.gnu.version' in e.names:
        data = e.section_data(e.names.index('.gnu.version'))
        indices = struct.unpack('<'+'H'*(len(data)//2), data)
        assert len(indices) == len(e.symbols)
    else:
        indices = [1]*len(e.symbols)
    return indices, required, defined
