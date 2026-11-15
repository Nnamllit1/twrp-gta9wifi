import importlib.util
from pathlib import Path
import stat
import unittest

spec = importlib.util.spec_from_file_location('stock', Path(__file__).parents[1]/'tools/stock_recovery.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def entry(name, body=b'', mode=stat.S_IFREG|0o644, magic=b'070701', checksum=0):
    name = name.encode()+b'\0'
    fields = [1,mode,0,0,1,0,len(body),0,0,0,0,len(name),checksum]
    result = magic+b''.join(f'{v:08x}'.encode() for v in fields)+name
    result += bytes((-len(result))%4)
    result += body
    return result+bytes((-len(result))%4)


def archive(*entries):
    return b''.join(entries)+entry('TRAILER!!!')


class NewcTests(unittest.TestCase):
    def test_file_body_and_metadata(self):
        records=m.read_newc(archive(entry('lib/modules/driver.ko',b'bytes')))
        self.assertEqual(records[0]['name'],'lib/modules/driver.ko')
        self.assertEqual(records[0]['body'],b'bytes')
        self.assertTrue(stat.S_ISREG(records[0]['mode']))

    def test_links_are_metadata_only(self):
        records=m.read_newc(archive(entry('link',b'/outside',stat.S_IFLNK|0o777)))
        self.assertTrue(stat.S_ISLNK(records[0]['mode']))

    def test_normalize_relative_name(self):
        self.assertEqual(m.read_newc(archive(entry('./init.rc')))[0]['name'],'init.rc')

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):m.read_newc(archive(entry('a'),entry('./a')))

    def test_unsafe_paths_rejected(self):
        for name in ('../outside','/absolute','a/../b','a\\b','C:outside'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                m.read_newc(archive(entry(name)))

    def test_truncated_body_rejected(self):
        data=entry('name',b'test body')
        with self.assertRaises(ValueError):m.read_newc(data[:-5])

    def test_missing_trailer_rejected(self):
        with self.assertRaises(ValueError):m.read_newc(entry('name'))

    def test_crc_checked(self):
        self.assertEqual(m.read_newc(archive(entry('a',b'ab',magic=b'070702',checksum=195)))[0]['body'],b'ab')
        with self.assertRaises(ValueError):m.read_newc(archive(entry('a',b'ab',magic=b'070702')))

    def test_trailing_nonzero_data_rejected(self):
        with self.assertRaises(ValueError):m.read_newc(archive(entry('a'))+b'bad')

    def test_wrong_boot_input_rejected(self):
        with self.assertRaises(ValueError):m.parse_boot(b'ANDROID!'+bytes(2048))


if __name__=='__main__':unittest.main()
