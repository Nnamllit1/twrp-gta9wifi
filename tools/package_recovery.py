"""Audit a built SM-X110 recovery and original CYE5 vbmeta for an Odin test.

This has no device operations. A passing file audit does not certify boot,
decryption, or hardware rollback behavior.
"""
import argparse
import gzip
import hashlib
import io
import json
import re
from pathlib import Path
import stat
import struct
import subprocess
import tarfile

from stock_recovery import parse_boot, read_newc, sha, samsung_signer_block, MAX_RAMDISK
from recovery_startup import audit_startup
from touch_recovery import verify_module

VBMETA_SHA = '5bde91030560b6283d8e1d5bf13e3aea0b83e0146c1c5fe714078d51400770a0'


def patch_vbmeta(raw):
    if len(raw)!=7680 or sha(raw)!=VBMETA_SHA or raw[:4]!=b'AVB0':
        raise ValueError('Only the original hash-pinned CYE5 vbmeta is accepted')
    if struct.unpack_from('>QII',raw,112)!=(0,0,0):
        raise ValueError('Unexpected original vbmeta rollback/flags fields')
    result=bytearray(raw)
    struct.pack_into('>I',result,120,2)
    result=bytes(result)
    if result[:120]!=raw[:120] or result[124:]!=raw[124:] or struct.unpack_from('>QII',result,112)!=(0,2,0):
        raise ValueError('vbmeta mutation escaped its flags field')
    return result,{'original_sha256':sha(raw),'modified_sha256':sha(result),'bytes':len(raw),
                   'only_allowed_mutation':'big-endian flags u32 at offset 120: 0 -> 2',
                   'rollback_index_before_after':[0,0],'rollback_location_before_after':[0,0],
                   'descriptors_authentication_block_and_other_bytes_unchanged':True,
                   'original_signature_invalidated_by_flags_change':True,
                   'requires_unlocked_bootloader_accepting_modified_vbmeta':True,
                   'hardware_counter_behavior_verified':False}


def audit(raw, prebuilt, lz4):
    components, info = parse_boot(raw)
    source = json.loads((prebuilt/'inputs.json').read_text())
    original = source['source_recovery']
    for field in ('header_version','page_size','kernel_addr','ramdisk_addr','second_addr',
                  'tags_addr','dtb_addr','os_version_raw','board'):
        if info[field] != original[field]:
            raise ValueError('Recovery boot field differs from CYE5: '+field)
    for name in ('kernel','dtb.img','dtbo.img'):
        if sha(components[name]) != original['components'][name]['sha256']:
            raise ValueError('Original recovery component changed: '+name)
    if not info['avb_footer_present']:
        raise ValueError('Expected a bounded recovery AVB footer')
    for field in ('rollback_index','rollback_index_location','flags'):
        if info['avb'][field] != original['avb'][field]:
            raise ValueError('Recovery AVB field differs from CYE5: '+field)
    signer = samsung_signer_block(raw)
    original_signer = (prebuilt/'samsung-signer.bin').read_bytes()
    expected_signer = original.get('samsung_signer',{})
    if (signer != original_signer or len(signer) != 512
            or sha(signer) != expected_signer.get('sha256')):
        raise ValueError('Original CYE5 Samsung SignerVer02 block changed')
    allowed_cmdline = original['cmdline']+' androidboot.selinux=permissive buildvariant=eng'
    if info['cmdline'] != allowed_cmdline:
        raise ValueError('Unexpected recovery kernel command line')
    packed = components['ramdisk']
    if packed[:2] == b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as f:cpio=f.read(MAX_RAMDISK+1)
    elif packed[:4] in (b'\x02\x21\x4c\x18', b'\x04\x22\x4d\x18'):
        cpio=subprocess.run([str(lz4),'-d','-c','-q'],input=packed,capture_output=True,check=True).stdout
    else:raise ValueError('Unsupported built ramdisk compression')
    if len(cpio)>MAX_RAMDISK:raise ValueError('Excessive built ramdisk')
    entries={r['name']:r for r in read_newc(cpio)}
    startup = audit_startup(entries)
    loads=entries['lib/modules/modules.load.recovery']['body'].decode().splitlines()
    touch_modules=source.get('added_touch_modules',source.get('added_signed_modules',[]))
    if loads != source.get('first_stage_module_loads') or set(loads) & set(source.get('added_runtime_modules',touch_modules)):
        raise ValueError('Recovery first-stage modules must match the reviewed stock-only bootstrap set')
    for name in ('system/bin/recovery','system/bin/adbd'):
        record=entries.get(name)
        if not record or not stat.S_ISREG(record['mode']) or not record['mode'] & 0o111:
            raise ValueError('Missing executable '+name)
        elf=record['body']
        if elf[:6]!=b'\x7fELF\x02\x01' or elf[18:20]!=b'\xb7\x00':
            raise ValueError('Expected ARM64 executable '+name)
    if b'TWRP' not in entries['system/bin/recovery']['body']:
        raise ValueError('Built recovery has no TWRP identity')
    cache=entries.get('cache')
    if not cache or not stat.S_ISDIR(cache['mode']):
        raise ValueError('/cache must be a real recovery directory')
    for row in source['files']:
        if not row['path'].startswith('ramdisk/'):
            continue
        name=row['path'][len('ramdisk/'):]
        record=entries.get(name)
        if not record or sha(record['body'])!=row['sha256']:
            raise ValueError('Bundled reviewed module/firmware input differs: '+name)
    touch_patch=verify_module(entries['lib/modules/touch_common.ko']['body'],source.get('touch_recovery_patch'))
    for name in ('init.recovery.mt8781.rc','init.recovery.usb.rc','system/etc/twrp.fstab'):
        if name not in entries or b'\r' in entries[name]['body']:
            raise ValueError('Missing or non-Linux recovery configuration: '+name)
        if entries[name]['body']!=(prebuilt.parent/'recovery/root'/name).read_bytes():
            raise ValueError('Recovery configuration differs from reviewed source: '+name)
    # Android init reads this separately from TWRP's flags-rich partition table.
    # A TWRP-format recovery.fstab made init reject reboot,recovery before reset.
    fstab=entries.get('system/etc/recovery.fstab')
    if not fstab or fstab['body']!=(prebuilt.parent/'recovery.fstab').read_bytes():
        raise ValueError('Android init recovery fstab differs from reviewed source')
    if source.get('crypto_inputs'):
        profile=source['crypto_inputs']
        policy=entries.get('sepolicy')
        contexts=entries.get('vendor_file_contexts')
        if not policy or b'tee_efs_file' not in policy['body']:
            raise ValueError('Recovery policy lacks the original CYE5 TEE file type')
        if not contexts or any(rule not in contexts['body'] for rule in (
                b'/mnt/vendor/efs/tee(/.*)?',
                b'/tmp/gta9wifi-trusted-storage/efs/tee(/.*)?')):
            raise ValueError('Recovery lacks the TEE storage label rules')
        for pin in profile['files']:
            record=entries.get(pin['output_path'])
            if not record or sha(record['body'])!=pin['sha256']:
                raise ValueError('Original crypto provider differs: '+pin['output_path'])
            if pin['mode']=='0755' and not record['mode'] & 0o111:
                raise ValueError('Crypto provider lost execute permission: '+pin['output_path'])
        for path in (prebuilt.parent/'recovery/root').rglob('*'):
            if not path.is_file():continue
            name=path.relative_to(prebuilt.parent/'recovery/root').as_posix()
            if path.name=='.keep':
                directory=entries.get(str(Path(name).parent).replace('\\','/'))
                if not directory or not stat.S_ISDIR(directory['mode']):
                    raise ValueError('Missing placeholder directory: '+name)
                continue
            if name not in entries or entries[name]['body']!=path.read_bytes():
                raise ValueError('Integrated recovery source differs: '+name)
        thermal=entries.get('lib/modules/soc_temp_lvts.ko')
        if not thermal or sha(thermal['body'])!='aed316e6e878d622664b34647ebf1be28db56e2468bc417f1e903a24fac23ad0':
            raise ValueError('Original thermal backend missing or changed')
        for name in ('system/bin/resetprop','system/bin/logcat','system/bin/logd','system/bin/service'):
            if name not in entries or not entries[name]['mode'] & 0o111:
                raise ValueError('Integrated recovery utility missing: '+name)
    props={}
    for line in entries['prop.default']['body'].decode().splitlines():
        if '=' in line and not line.startswith('#'):
            key,_,value=line.partition('=');props[key]=value
    required={'ro.secure':'0','ro.debuggable':'1','ro.adb.secure':'0',
              'ro.build.version.security_patch':'2025-04-01'}
    if any(props.get(k)!=value for k,value in required.items()):
        raise ValueError('Unexpected recovery root/development properties')
    info.update(status='offline_recovery_audit_passed',ramdisk_entries=len(entries),
                authenticated_original_inputs_verified=True,boot_touch_root_ADB_decryption_verified=False,
                root_development_properties=required,Samsung_recovery_marker_present=True,
                hardware_rollback_verified=False,device_access=False)
    info['startup_dependencies'] = startup
    info['first_stage_modules']={'count':len(loads),'stock_bootstrap_only':True,'touch_load_stage':source['touch_load_stage']}
    info['touch_recovery_patch']=touch_patch
    info['crypto_provider_inputs']=source.get('crypto_inputs')
    info['samsung_signer'] = {'bytes':512,'sha256':sha(signer),'original_CYE5_block_retained_exactly':True,
                              'modified_image_has_valid_Samsung_signature':False}
    return info


def package(image, prebuilt, stock_vbmeta, output, lz4, recovery_only=False, version='0.1.0', compress_recovery=False):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):raise ValueError('Expected a numeric package version')
    if output.exists():raise ValueError('Use a fresh output directory')
    if image.stat().st_size!=83886080:raise ValueError('Recovery size differs from partition bound')
    raw=image.read_bytes()
    report=audit(raw,prebuilt,lz4)
    payloads=[('recovery.img',raw)]
    if compress_recovery:
        packed=subprocess.run([str(lz4),'-c','--content-size',str(image)],capture_output=True,check=True).stdout
        decoded=subprocess.run([str(lz4),'-d','-c','-q'],input=packed,capture_output=True,check=True).stdout
        if decoded!=raw:raise ValueError('Recovery delivery LZ4 round-trip failed')
        payloads=[('recovery.img.lz4',packed)]
    vbmeta_audit=None
    if not recovery_only:
        if stock_vbmeta is None:raise ValueError('Original vbmeta is required unless --recovery-only is selected')
        vbmeta,vbmeta_audit=patch_vbmeta(stock_vbmeta.read_bytes())
        payloads.append(('vbmeta.img',vbmeta))
    output.mkdir(parents=True)
    kind='RECOVERY_ONLY' if recovery_only else 'TEST'
    filename=f'AP_TWRP_SM-X110_CYE5_{kind}_{version}.tar.md5'
    partial=output/(filename+'.partial')
    with tarfile.open(partial,'w',format=tarfile.USTAR_FORMAT) as target:
        for name,body in payloads:
            entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o644;entry.mtime=0
            target.addfile(entry,io.BytesIO(body))
    tar_bytes=partial.stat().st_size
    with partial.open('rb') as f:md5=hashlib.file_digest(f,'md5').hexdigest()
    with partial.open('ab') as f:f.write((md5+'  '+filename.removesuffix('.md5')+'\n').encode())
    with tarfile.open(partial) as z:
        rows=z.getmembers()
        if [r.name for r in rows]!=[n for n,_ in payloads] or not all(r.isfile() for r in rows):
            raise ValueError('Unexpected packaged payload')
        for row,(_,body) in zip(rows,payloads):
            with z.extractfile(row) as f:
                if hashlib.file_digest(f,'sha256').hexdigest()!=sha(body):raise ValueError('Packaged image mismatch')
    with partial.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    manifest={'model':'SM-X110','base':'X110XXU4CYE5','filename':filename,'sha256':digest,
              'bytes':partial.stat().st_size,'tar_bytes':tar_bytes,'odin_md5':md5,
              'members':[{'name':n,'bytes':len(b),'sha256':sha(b)} for n,b in payloads],
              'recovery_only':recovery_only,'requires_existing_modified_vbmeta':recovery_only,
              'recovery_delivery_compression':'lz4' if compress_recovery else 'none',
              'bootloader_secure_firmware_standalone_DTBO_normal_boot_super_userdata_metadata_payloads':False,
              'runtime_verified':False,'hardware_rollback_verified':False,'device_access':False}
    (output/'image-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    if vbmeta_audit is not None:
        (output/'vbmeta-audit.json').write_text(json.dumps(vbmeta_audit,indent=2)+'\n')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'SHA256SUMS.txt').write_text(digest+'  '+filename+'\n')
    partial.rename(output/filename)
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--prebuilt',type=Path,required=True)
    p.add_argument('--stock-vbmeta',type=Path)
    p.add_argument('--recovery-only',action='store_true',help='Keep already-installed vbmeta and vendor; recovery image only')
    p.add_argument('--version',default='0.1.0')
    p.add_argument('--compress-recovery',action='store_true',help='Wrap recovery in Samsung-style LZ4 for TAR delivery')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--lz4',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(package(a.image,a.prebuilt,a.stock_vbmeta,a.output,a.lz4,a.recovery_only,a.version,a.compress_recovery),indent=2))


if __name__=='__main__':main()
