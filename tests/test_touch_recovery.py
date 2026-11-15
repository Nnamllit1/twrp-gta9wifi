"""Verify the actual AArch64 gate and its complete-binary patch boundary."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import touch_recovery as m


def execute_gate(mode):
    # Decode the assembled words rather than a second copy of patch intent.
    first, *conditional = struct.unpack('<III',m.AFTER)
    assert first == 0x71000004  # SUBS W4,W0,#0
    w4 = mode & 0xffffffff
    zero = w4 == 0
    for word in conditional:
        assert word & ~((31 << 16) | 15) == 0x7a401800  # CCMP W0,#imm,#nzcv,NE
        immediate, fallback = (word >> 16) & 31, word & 15
        zero = (w4 == immediate) if not zero else bool(fallback & 4)
    return zero, w4


class TouchRecoveryTests(unittest.TestCase):
    def test_gate_accepts_only_original_modes_and_recovery(self):
        for mode in (*range(65536),0x7fffffff,0x80000000,0xfffffffe,0xffffffff):
            accepted, error_argument = execute_gate(mode)
            self.assertEqual(accepted,mode in (0,2,7))
            self.assertEqual(error_argument,mode)

    def test_unknown_original_rejected(self):
        with self.assertRaises(ValueError):m.patch_original(bytes(m.MODULE_BYTES))

    def test_private_original_and_full_scope(self):
        path=Path(__file__).resolve().parents[1]/'device/samsung/gta9wifi/prebuilt/ramdisk/lib/modules/touch_common.ko'
        if not path.is_file():self.skipTest('Proprietary local input absent')
        original=path.read_bytes()
        if original[m.OFFSET:m.OFFSET+12] == m.AFTER:
            original=original[:m.OFFSET]+m.BEFORE+original[m.OFFSET+12:]
        patched, report=m.patch_original(original)
        self.assertEqual(patched[:m.OFFSET],original[:m.OFFSET])
        self.assertEqual(patched[m.OFFSET+12:],original[m.OFFSET+12:])
        self.assertTrue(m.verify_module(patched,report)['patch_applied'])
        for offset in (0,m.OFFSET,m.OFFSET+12,len(patched)-1):
            broken=bytearray(patched);broken[offset]^=1
            with self.assertRaises(ValueError):m.verify_module(bytes(broken),report)
        with self.assertRaises(ValueError):m.patch_original(patched)
        with self.assertRaises(ValueError):m.verify_module(patched,{**report,'file_offset':0})


if __name__=='__main__':unittest.main()
