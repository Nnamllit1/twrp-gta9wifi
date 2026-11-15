"""Package original CYE5 recovery, optionally with original stock vbmeta.

No device commands. Payloads are copied byte-for-byte from authenticated stock.
Use --recovery-only when vendor/system is modified: restoring stock vbmeta
would re-enable verification against those changed partitions.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

MEMBERS={
 'recovery.img.lz4':(41025586,'d1e204b463e52d0b14a315aa5f9a1cdb0dc1bfbb61c797a74054af778e9d345b'),
 'vbmeta.img.lz4':(3508,'c7841af8678c8337d0965be3161312a1980b500e0200be9d08a9ce07f78935e7'),
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock-ap',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--recovery-only',action='store_true',
                   help='Restore original recovery while leaving current vbmeta/vendor untouched')
    a=p.parse_args()
    if a.output.exists():p.error('Use a fresh output directory')
    payloads={}
    members={k:v for k,v in MEMBERS.items() if not a.recovery_only or k=='recovery.img.lz4'}
    with tarfile.open(a.stock_ap) as z:
        entries=z.getmembers()
        for name,(size,digest) in members.items():
            selected=[e for e in entries if e.name==name]
            if len(selected)!=1 or not selected[0].isfile() or selected[0].size!=size:
                raise ValueError('Missing, duplicate or unexpected original payload')
            body=z.extractfile(selected[0]).read()
            if hashlib.sha256(body).hexdigest()!=digest:raise ValueError('Original CYE5 hash mismatch')
            payloads[name]=body
    a.output.mkdir(parents=True)
    filename=('AP_CONTROL_SM-X110_CYE5_STOCK_RECOVERY_ONLY.tar.md5' if a.recovery_only
              else 'AP_RESTORE_SM-X110_CYE5_RECOVERY_VBMETA.tar.md5')
    partial=a.output/(filename+'.partial')
    with tarfile.open(partial,'w',format=tarfile.USTAR_FORMAT) as target:
        for name,body in payloads.items():
            entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o644;entry.mtime=0
            target.addfile(entry,io.BytesIO(body))
    tar_bytes=partial.stat().st_size
    with partial.open('rb') as f:md5=hashlib.file_digest(f,'md5').hexdigest()
    with partial.open('ab') as f:f.write((md5+'  '+filename.removesuffix('.md5')+'\n').encode())
    with tarfile.open(partial) as z:
        if [e.name for e in z.getmembers()]!=list(members):raise ValueError('Unexpected restore inventory')
        for name,(_,digest) in members.items():
            with z.extractfile(name) as f:
                if hashlib.file_digest(f,'sha256').hexdigest()!=digest:raise ValueError('Restore readback mismatch')
    with partial.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    manifest={'purpose':('Original CYE5 recovery-only control; current vbmeta/vendor preserved' if a.recovery_only
                         else 'Original CYE5 recovery and vbmeta restore for a stock-vendor environment'),
              'model':'SM-X110','build':'X110XXU4CYE5','filename':filename,'sha256':digest,
              'bytes':partial.stat().st_size,'tar_bytes':tar_bytes,'odin_md5':md5,
              'members':[{'name':n,'bytes':v[0],'sha256':v[1],'modified':False} for n,v in members.items()],
              'vbmeta_payload_included':not a.recovery_only,
              'BL_normal_boot_super_CSC_userdata_metadata_cache_payloads':False,
              'device_access':False,'runtime_restore_verified':False}
    (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (a.output/'SHA256SUMS.txt').write_text(digest+'  '+filename+'\n')
    (a.output/'README.txt').write_text(('ORIGINAL CYE5 RECOVERY-ONLY CONTROL, SM-X110 ONLY\n'
        'One unmodified original recovery payload. Current vbmeta and vendor are untouched.\n'
        'This restores STOCK recovery; it does not install or repair TWRP.\n' if a.recovery_only else
        'ORIGINAL CYE5 RECOVERY + VBMETA RESTORE, SM-X110 ONLY\n'
        'Use only with original stock vendor/system. This re-enables AVB verification.\n'
        'Do not use it with modified vendor from the persistence test.\n')+
        'No normal OS, BL, cache, userdata or metadata payload.\n'
        'When deliberately restoring after the recovery test, select this file only in AP, other slots empty.\n'
        'Re-Partition and NAND Erase stay off. Do not change the bootloader lock state.\n'
        'This tool does not flash, reboot or certify runtime hardware-counter behavior.\n')
    partial.rename(a.output/filename)
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
