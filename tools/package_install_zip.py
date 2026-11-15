"""Package an audited SM-X110 CYE5 recovery as a guarded TWRP install ZIP.

No device access or flashing. The generated updater verifies model, retained
loader, partition aliases, size and full image hash, writes recovery only and
verifies its readback. It also supports a device-side verify-only dry run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

from package_recovery import audit

TEMPLATE=Path(__file__).with_name('recovery-update-binary.sh.in')


def updater(image_sha256,version):
    if not re.fullmatch('[0-9a-f]{64}',image_sha256) or not re.fullmatch(r'\d+\.\d+\.\d+',version):
        raise ValueError('Expected an image SHA-256 and numeric version')
    body=TEMPLATE.read_text().replace('@IMAGE_SHA256@',image_sha256).replace('@VERSION@',version)
    if '@IMAGE_SHA256@' in body or '@VERSION@' in body or '\r' in body:raise ValueError('Invalid updater template')
    return body.encode()


def package(image,prebuilt,lz4,output,version):
    if output.exists():raise ValueError('Use a fresh ZIP output directory')
    raw=image.read_bytes()
    if len(raw)!=83886080:raise ValueError('Wrong recovery partition size')
    report=audit(raw,prebuilt,lz4)
    digest=hashlib.sha256(raw).hexdigest();script=updater(digest,version)
    filename=f'TWRP_SM-X110_CYE5_RECOVERY_ONLY_{version}.zip'
    payloads={'META-INF/com/google/android/update-binary':script,
      'META-INF/com/google/android/updater-script':b'# Shell update-binary performs the recovery-only update.\n',
      'recovery.img':raw}
    output.mkdir(parents=True)
    path=output/(filename+'.partial')
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,body in payloads.items():
            row=zipfile.ZipInfo(name,date_time=(2025,4,1,0,0,0));row.create_system=3
            row.compress_type=zipfile.ZIP_DEFLATED
            row.external_attr=(0o100755 if name.endswith('/update-binary') else 0o100644)<<16
            z.writestr(row,body,compresslevel=6)
    with zipfile.ZipFile(path) as z:
        if z.namelist()!=list(payloads) or z.testzip() is not None:raise ValueError('ZIP layout or CRC failed')
        for name,body in payloads.items():
            if z.read(name)!=body:raise ValueError('ZIP readback mismatch')
    with path.open('rb') as stream:zip_sha=hashlib.file_digest(stream,'sha256').hexdigest()
    manifest={'model':'SM-X110','base':'X110XXU4CYE5','version':version,'filename':filename,
      'sha256':zip_sha,'bytes':path.stat().st_size,'recovery_sha256':digest,'recovery_bytes':len(raw),
      'members':[{'name':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for n,b in payloads.items()],
      'writes_only':'/dev/block/by-name/recovery','development_ZIP_signature':'unsigned',
      'requires_existing_persistence_and_modified_vbmeta':True,
      'bootloader_secure_firmware_normal_boot_super_vbmeta_userdata_metadata_payloads':False,
      'runtime_update_or_new_image_boot_verified':False,'device_access':False}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'image-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    (output/'SHA256SUMS.txt').write_text(zip_sha+'  '+filename+'\n')
    path.rename(output/filename)
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','prebuilt','lz4','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--version',required=True);a=p.parse_args()
    print(json.dumps(package(a.image,a.prebuilt,a.lz4,a.output,a.version),indent=2))


if __name__=='__main__':main()
