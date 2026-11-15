import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]/'tools'))
import package_recovery as m


class VbmetaScope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=Path(__file__).parents[2]/'.work/twrp-sm-x110/original-vbmeta/vbmeta.img'
        if not cls.source.is_file():
            raise unittest.SkipTest('Local authenticated CYE5 vbmeta reference is required')
        cls.raw=cls.source.read_bytes()

    def test_exact_flags_field_only(self):
        patched,report=m.patch_vbmeta(self.raw)
        self.assertEqual(len(patched),len(self.raw))
        self.assertEqual(patched[:120],self.raw[:120])
        self.assertEqual(patched[124:],self.raw[124:])
        self.assertEqual(struct.unpack_from('>QII',patched,112),(0,2,0))
        self.assertEqual([i for i,(a,b) in enumerate(zip(self.raw,patched)) if a!=b],[123])

    def test_modified_source_refused(self):
        data=bytearray(self.raw);data[-1]^=1
        with self.assertRaises(ValueError):m.patch_vbmeta(data)

    def test_higher_original_index_refused(self):
        data=bytearray(self.raw);struct.pack_into('>Q',data,112,1)
        with self.assertRaises(ValueError):m.patch_vbmeta(data)

    def test_already_patched_source_refused(self):
        data,_=m.patch_vbmeta(self.raw)
        with self.assertRaises(ValueError):m.patch_vbmeta(data)


if __name__=='__main__':unittest.main()
