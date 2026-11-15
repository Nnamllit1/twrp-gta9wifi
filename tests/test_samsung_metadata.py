"""Recovery metadata regression on local authenticated build artifacts."""
from pathlib import Path
import os
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
FIXTURES=Path(os.environ.get('TWRP_TEST_FIXTURES', ROOT.parent/'.work'))
sys.path.insert(0,str(ROOT/'tools'))
from stock_recovery import samsung_signer_block


class SamsungMetadata(unittest.TestCase):
    def test_previous_image_missing_struct_is_rejected(self):
        path=FIXTURES/'twrp-sm-x110/build-10/recovery.img'
        if not path.is_file():self.skipTest('Local previous image required')
        with self.assertRaisesRegex(ValueError,'Samsung recovery metadata'):
            samsung_signer_block(path.read_bytes())

    def test_exact_original_block_and_footer_size_are_required(self):
        path=FIXTURES/'twrp-sm-x110/build-11/recovery.img'
        reference=ROOT/'device/samsung/gta9wifi/prebuilt/samsung-signer.bin'
        if not path.is_file() or not reference.is_file():self.skipTest('Local rebuilt image and stock metadata required')
        raw=path.read_bytes()
        self.assertEqual(samsung_signer_block(raw),reference.read_bytes())
        broken=bytearray(raw)
        offset=len(broken)-64+12
        size=struct.unpack_from('>Q',broken,offset)[0]
        struct.pack_into('>Q',broken,offset,size-512)
        with self.assertRaisesRegex(ValueError,'Samsung recovery metadata'):
            samsung_signer_block(broken)


if __name__=='__main__':unittest.main()
