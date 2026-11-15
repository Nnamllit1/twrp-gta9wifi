"""Prepare authenticated CYE5 prebuilts for the SM-X110 source port.

Requires the stock_recovery.py output and original extracted vendor partitions.
The pinned shared touch module receives a recovery-only boot-mode fix.
No device commands or firmware packaging.
"""
import argparse
import hashlib
import erofs_image as erofs
import json
from pathlib import Path
import shutil
import stat

from touch_recovery import patch_original

VENDOR_SHA = '79de66ffd17edeaf28ef00d527ca440d2bdc079c9d660f9842c1fd58cd03532d'
DLKM_SHA = '0a3293741c1e0f172639ffb759c72bcf8c13b7848ef46e4d74462ff333bda9d0'
TOUCH = ('touch_common.ko', 'jdchipset.ko', 'novatek.ko', 'hxchipset.ko', 'chipone.ko')
RUNTIME = (*TOUCH, 'soc_temp_lvts.ko')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock', type=Path, required=True)
    p.add_argument('--vendor', type=Path, required=True)
    p.add_argument('--vendor-dlkm', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    a = p.parse_args()
    out = a.device/'prebuilt'
    if out.exists():
        p.error('Prebuilt directory already exists; refusing replacement')
    if erofs.sha(a.vendor) != VENDOR_SHA or erofs.sha(a.vendor_dlkm) != DLKM_SHA:
        p.error('Only hash-pinned original CYE5 vendor inputs are accepted')
    stock = json.loads((a.stock/'stock-recovery.json').read_text())
    if stock['source_member_sha256'] != 'd1e204b463e52d0b14a315aa5f9a1cdb0dc1bfbb61c797a74054af778e9d345b':
        p.error('Unexpected stock recovery provenance')
    for name in ('kernel','dtb.img','dtbo.img'):
        data = (a.stock/'prebuilt'/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != stock['components'][name]['sha256']:
            p.error('Stock recovery component changed')
    signer = (a.stock/'prebuilt/samsung-signer.bin').read_bytes()
    if len(signer) != 512 or not signer.startswith(b'SignerVer02') or hashlib.sha256(signer).hexdigest() != stock['samsung_signer']['sha256']:
        p.error('Original Samsung SignerVer02 metadata changed')
    vendor, dlkm = erofs.Image(a.vendor), erofs.Image(a.vendor_dlkm)
    modules = {path.rsplit('/',1)[-1]: dlkm.read(node) for path,node in dlkm.nodes.items()
               if path.endswith('.ko') and stat.S_ISREG(node['mode'])}
    dep = dlkm.read(dlkm.nodes['/lib/modules/modules.dep']).decode()
    dependencies = {}
    for line in dep.splitlines():
        name, _, rest = line.partition(':')
        dependencies[Path(name).name] = [Path(n).name for n in rest.split()]
    selected = set()
    stock_modules = a.stock/'stock-files/lib/modules'
    def visit(name, stack=()):
        if name in stack:
            raise ValueError('Kernel module dependency cycle')
        if name in selected or (stock_modules/name).is_file():
            return
        if name not in modules or name not in dependencies:
            raise ValueError('Missing original dependency '+name)
        for child in dependencies[name]:
            visit(child, (*stack,name))
        selected.add(name)
    for name in RUNTIME:
        visit(name)
    out.mkdir(parents=True)
    for name in ('kernel','dtb.img','dtbo.img','samsung-signer.bin'):
        shutil.copyfile(a.stock/'prebuilt'/name, out/name)
    ramdisk = out/'ramdisk'
    dest_modules = ramdisk/'lib/modules'
    shutil.copytree(stock_modules, dest_modules)
    for name in sorted(selected):
        (dest_modules/name).write_bytes(modules[name])
    patched_touch, touch_patch = patch_original((dest_modules/'touch_common.ko').read_bytes())
    (dest_modules/'touch_common.ko').write_bytes(patched_touch)
    # Rewrite module paths. Only the explicit shared touch guard above changes
    # module code; the other 207 original module binaries remain byte-identical.
    original_dep = (stock_modules/'modules.dep').read_text()
    additions = ''.join('/lib/modules/'+n+':'+''.join(' /lib/modules/'+d for d in dependencies[n])+'\n'
                        for n in sorted(selected))
    (dest_modules/'modules.dep').write_text(original_dep.rstrip()+'\n'+additions, newline='\n')
    # Only the stock bootstrap set belongs in init's fatal first-stage loader.
    # Touch probes run later through TWRP's TW_LOAD_VENDOR_MODULES path, after
    # the USB/init foundation exists. Keep their binaries/dependencies bundled.
    loads = list(dict.fromkeys(n.strip() for n in (stock_modules/'modules.load.recovery').read_text().splitlines()
                              if n.strip() and not n.startswith('#')))
    (dest_modules/'modules.load.recovery').write_text('\n'.join(loads)+'\n', newline='\n')
    firmware = []
    for name,node in vendor.nodes.items():
        if name.startswith('/firmware/') and any(x in Path(name).name for x in ('hx83102','jd9366','nt36523','nl9951')):
            target = ramdisk/'vendor'/name.lstrip('/')
            target.parent.mkdir(parents=True,exist_ok=True)
            data = vendor.read(node)
            target.write_bytes(data)
            # Kernel direct firmware requests can precede ueventd, whose
            # vendor search directories are not available at that point.
            direct = ramdisk/'lib/firmware'/Path(name).name
            direct.parent.mkdir(parents=True,exist_ok=True)
            direct.write_bytes(data)
            firmware.append(name)
    for name in ('fstab.mt8781','fstab.mt6789'):
        target = out/'reference'/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(vendor.read(vendor.nodes['/etc/'+name]))
        vold_fstab=ramdisk/'system/etc'/name
        vold_fstab.parent.mkdir(parents=True,exist_ok=True)
        vold_fstab.write_bytes(target.read_bytes())
    inventory = []
    for path in sorted(out.rglob('*')):
        if path.is_file():
            with path.open('rb') as f:
                inventory.append({'path':path.relative_to(out).as_posix(),'bytes':path.stat().st_size,
                                  'sha256':hashlib.file_digest(f,'sha256').hexdigest()})
    result = {'model':'SM-X110','build':'X110XXU4CYE5','source_recovery':stock,
              'vendor_sha256':VENDOR_SHA,'vendor_dlkm_sha256':DLKM_SHA,
              'added_touch_modules':sorted(n for n in selected if n in TOUCH),
              'added_runtime_modules':sorted(selected),'touch_firmware':firmware,
              'first_stage_module_loads':loads,'touch_load_stage':'TWRP_userspace',
              'module_code_or_signatures_modified':True, 'touch_recovery_patch':touch_patch,
              'device_access':False,
              'flashable_image_created':False,'files':inventory}
    (out/'inputs.json').write_text(json.dumps(result,indent=2)+'\n')
    vendor.f.close(); dlkm.f.close()
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','source_recovery')},indent=2))


if __name__ == '__main__':
    main()
