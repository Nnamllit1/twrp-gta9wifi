"""Run the real updater against isolated Linux file fixtures, never a tablet.

Only absolute device paths and the block-file type check are remapped. The
production model/loader/hash/write/readback logic executes unchanged. A separate
device verify-only run is still required; these tests do not establish flashing.
"""
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
import zipfile
if os.name=='posix':
    import fcntl

IMAGE=os.environ.get('FWBLP_RECOVERY_FIXTURE_IMAGE')
UPDATER_SHELL=os.environ.get('FWBLP_RECOVERY_TEST_SHELL','bash')


@unittest.skipUnless(os.name=='posix' and IMAGE,'Requires Linux and FWBLP_RECOVERY_FIXTURE_IMAGE')
class RecoveryUpdaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=Path(IMAGE).resolve(strict=True)
        assert cls.image.is_file() and cls.image.stat().st_size==83886080
        with cls.image.open('rb') as stream:
            assert stream.read(8)==b'ANDROID!'
            stream.seek(0);cls.image_sha=hashlib.file_digest(stream,'sha256').hexdigest()
        cls.template=(Path(__file__).resolve().parents[1]/'tools/recovery-update-binary.sh.in').read_text()
        cls.zip_temp=tempfile.TemporaryDirectory(prefix='fwblp-updater-zips-')
        cls.good=Path(cls.zip_temp.name)/'valid.zip'
        with zipfile.ZipFile(cls.good,'w',compression=zipfile.ZIP_DEFLATED) as z:z.write(cls.image,'recovery.img')

    @classmethod
    def tearDownClass(cls):cls.zip_temp.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fwblp-updater-case-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.dev=self.root/'dev/block';(self.dev/'by-name').mkdir(parents=True)
        (self.root/'tmp').mkdir();self.bin=self.root/'bin';self.bin.mkdir()
        self.target=self.dev/'recovery-device'
        with self.target.open('wb') as stream:stream.truncate(83886080)
        (self.dev/'by-name/recovery').symlink_to(self.target)
        self.protected={}
        for name in ('boot','super','userdata','metadata','efs','sec_efs','dtbo','vbmeta','vbmeta_system'):
            path=self.dev/name;body=('preserve '+name+'\n').encode();path.write_bytes(body)
            (self.dev/'by-name'/name).symlink_to(path);self.protected[path]=body
        body=self.template.replace('@VERSION@','0.1.6').replace('@IMAGE_SHA256@',self.image_sha)
        assert body.count('test -b "$BLOCK"')==1
        body=body.replace('/dev/block/',str(self.dev)+'/').replace('test -b "$BLOCK"','test -f "$BLOCK"')
        body=body.replace('/tmp/twrp-recovery-update.XXXXXX',str(self.root/'tmp/stage.XXXXXX'))
        self.script=self.root/'update-binary';self.script.write_text(body)
        self.tool('id','printf "0\\n"\n')
        self.tool('getprop','''case "$1" in
ro.twrp.boot) echo "${FIXTURE_TWRP:-1}";;
ro.product.model) echo "${FIXTURE_MODEL:-SM-X110}";;
ro.bootloader) echo "${FIXTURE_LOADER:-X110XXU4CYE5}";;
*) exit 1;; esac
''')
        self.tool('blockdev','test "$1" = --getsize64 || exit 1\nstat -Lc %s "$2"\n')

    def tool(self,name,body):
        path=self.bin/name;path.write_text('#!/bin/sh\n'+body);path.chmod(0o755)

    def execute(self,archive=None,**variables):
        env={**os.environ,'PATH':str(self.bin)+':'+os.environ['PATH'],**variables}
        result=subprocess.run([UPDATER_SHELL,str(self.script),'3','1',str(archive or self.good)],
                              capture_output=True,text=True,env=env,timeout=45)
        for path,body in self.protected.items():self.assertEqual(path.read_bytes(),body,'protected file changed')
        return result

    def test_verify_only_writes_nothing(self):
        before=self.hash_target();r=self.execute(TWRP_RECOVERY_VERIFY_ONLY='1')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('Verify-only mode',r.stdout)
        self.assertEqual(self.hash_target(),before)

    def test_verify_only_accepts_socket_output_descriptor(self):
        # ADB shell v2 uses a socket descriptor that /proc/self/fd cannot reopen.
        # The updater must duplicate that descriptor instead, as it does for
        # the normal TWRP progress pipe. No partition writes in this test.
        before=self.hash_target()
        parent,child=socket.socketpair()
        with parent,child:
            env={**os.environ,'PATH':str(self.bin)+':'+os.environ['PATH'],
                 'TWRP_RECOVERY_VERIFY_ONLY':'1'}
            result=subprocess.run([UPDATER_SHELL,str(self.script),'3','1',str(self.good)],
                                  stdout=child,stderr=subprocess.PIPE,env=env,timeout=45)
            child.close();parent.settimeout(5);chunks=[]
            while True:
                block=parent.recv(4096)
                if not block:break
                chunks.append(block)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'Verify-only mode',b''.join(chunks))
        self.assertEqual(self.hash_target(),before)
        for path,body in self.protected.items():self.assertEqual(path.read_bytes(),body)

    def test_verify_only_accepts_TWRP_high_pipe_descriptor(self):
        before=self.hash_target();read_fd,write_fd=os.pipe()
        high_fd=fcntl.fcntl(write_fd,fcntl.F_DUPFD,28);os.close(write_fd)
        try:
            env={**os.environ,'PATH':str(self.bin)+':'+os.environ['PATH'],
                 'TWRP_RECOVERY_VERIFY_ONLY':'1'}
            result=subprocess.run([UPDATER_SHELL,str(self.script),'3',str(high_fd),str(self.good)],
                                  pass_fds=(high_fd,),capture_output=True,env=env,timeout=45)
        finally:
            os.close(high_fd)
        try:
            output=os.read(read_fd,8192)
        finally:
            os.close(read_fd)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'Verify-only mode',output)
        self.assertEqual(self.hash_target(),before)
        for path,body in self.protected.items():self.assertEqual(path.read_bytes(),body)

    def test_write_then_readback(self):
        r=self.execute();self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(self.hash_target(),self.image_sha);self.assertIn('readback verified',r.stdout)

    def test_already_installed_skips_writer(self):
        shutil.copyfile(self.image,self.target);self.tool('dd','echo unexpected-dd >&2; exit 9\n')
        r=self.execute();self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('already installed',r.stdout)

    def test_wrong_model_rejected(self):self.assert_rejected('SM-X110 only',FIXTURE_MODEL='SM-X210')
    def test_wrong_loader_rejected(self):self.assert_rejected('retained CYE5',FIXTURE_LOADER='X110XXU5CZA6')
    def test_not_recovery_rejected(self):self.assert_rejected('Run from TWRP',FIXTURE_TWRP='0')

    def test_wrong_size_rejected(self):
        with self.target.open('r+b') as stream:stream.truncate(1024)
        self.assert_rejected('partition size differs')

    def test_overlapping_alias_rejected(self):
        alias=self.dev/'by-name/boot';alias.unlink();alias.symlink_to(self.target)
        self.assert_rejected('overlaps another partition')

    def test_bad_image_hash_rejected_before_writer(self):
        empty=self.root/'wrong.img'
        with empty.open('wb') as stream:stream.truncate(83886080)
        bad=self.root/'corrupt.zip'
        with zipfile.ZipFile(bad,'w',compression=zipfile.ZIP_DEFLATED) as z:z.write(empty,'recovery.img')
        self.assert_rejected('SHA-256 mismatch',archive=bad)

    def test_write_failure_rejected(self):
        self.tool('dd','exit 7\n');self.assert_rejected('Recovery write failed')

    def test_readback_failure_rejected(self):
        self.tool('dd',f'/usr/bin/dd "$@"\nprintf X | /usr/bin/dd of="{self.target}" bs=1 conv=notrunc 2>/dev/null\n')
        r=self.execute();self.assertNotEqual(r.returncode,0);self.assertIn('readback failed',r.stdout)

    def test_broken_zip_rejected(self):
        broken=self.root/'broken.zip';broken.write_bytes(b'not a zip')
        self.assert_rejected('extraction failed',archive=broken)

    def hash_target(self):
        with self.target.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

    def assert_rejected(self,message,archive=None,**variables):
        before=self.hash_target();r=self.execute(archive,**variables)
        self.assertNotEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn(message,r.stdout)
        self.assertEqual(self.hash_target(),before)


if __name__=='__main__':unittest.main()
