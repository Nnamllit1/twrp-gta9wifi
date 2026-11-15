"""Regression against locally built recovery images; no device operations."""
import gzip
from pathlib import Path
import os
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=Path(os.environ.get('TWRP_TEST_FIXTURES', ROOT.parent/'.work'))
sys.path.insert(0,str(ROOT/'tools'))
from stock_recovery import parse_boot, read_newc
from recovery_startup import audit_startup


def entries(path):
    components,_=parse_boot(path.read_bytes())
    return {r['name']:r for r in read_newc(gzip.decompress(components['ramdisk']))}


class StartupDependencies(unittest.TestCase):
    def test_previous_image_rejected_for_actual_missing_library(self):
        path=FIXTURES/'twrp-sm-x110/build-final/recovery.img'
        if not path.is_file():self.skipTest('Original local test image required')
        with self.assertRaisesRegex(ValueError,'Missing startup library libresetprop.so'):
            audit_startup(entries(path))

    def test_fixed_image_and_removed_dependency_negative_control(self):
        path=FIXTURES/'twrp-sm-x110/build-10/recovery.img'
        if not path.is_file():self.skipTest('Rebuilt local test image required')
        archive=entries(path)
        self.assertFalse(audit_startup(archive)['runtime_verified'])
        del archive['system/lib64/libresetprop.so']
        with self.assertRaisesRegex(ValueError,'Missing startup library libresetprop.so'):
            audit_startup(archive)


if __name__=='__main__':unittest.main()
