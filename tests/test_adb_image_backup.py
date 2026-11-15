"""Corruption controls against an actual local TWRP boot-image stream."""
import io
from pathlib import Path
import os
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=Path(os.environ.get('TWRP_TEST_FIXTURES', ROOT.parent/'.work'))
sys.path.insert(0,str(ROOT/'tools'))
from audit_adb_image_backup import audit

FIXTURE=FIXTURES/'builds/SM-X110-CYE5-TWRP-maintenance-0.1.6-pass5/boot-stream-backup-2.ab'
EXPECTED='d50e78b8d4e6c9aeb5a7b849d7a71552c00e1636b7a444e073a7300944865784'


@unittest.skipUnless(FIXTURE.is_file(),'Requires the local verified boot-only backup fixture')
class AdbImageBackup(unittest.TestCase):
    def test_real_stream_matches_live_partition(self):
        with FIXTURE.open('rb') as stream:
            self.assertTrue(audit(stream,EXPECTED,67108864)['image_matches_independent_partition_hash'])

    def test_bad_record_crc_rejected(self):
        data=bytearray(FIXTURE.read_bytes());data[40]^=1
        with self.assertRaisesRegex(ValueError,'CRC mismatch'):
            audit(io.BytesIO(data),EXPECTED,67108864)

    def test_payload_corruption_rejected(self):
        data=bytearray(FIXTURE.read_bytes());data[4096]^=1
        with self.assertRaisesRegex(ValueError,'MD5 mismatch'):
            audit(io.BytesIO(data),EXPECTED,67108864)

    def test_truncated_stream_rejected(self):
        data=FIXTURE.read_bytes()
        with self.assertRaisesRegex(ValueError,'Truncated'):
            audit(io.BytesIO(data[:-512]),EXPECTED,67108864)


if __name__=='__main__':unittest.main()
