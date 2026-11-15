"""Independently check the generated CYE5 module/kernel input set."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

from touch_recovery import verify_module


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prebuilt',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args()
    manifest=json.loads((a.prebuilt/'inputs.json').read_text())
    if manifest['model']!='SM-X110' or manifest['build']!='X110XXU4CYE5':
        raise ValueError('Wrong input identity')
    listed={x['path']:x for x in manifest['files']}
    actual={x.relative_to(a.prebuilt).as_posix() for x in a.prebuilt.rglob('*') if x.is_file()}-{'inputs.json'}
    if actual != set(listed):raise ValueError('Unexpected or missing input files')
    for name,info in listed.items():
        path=a.prebuilt/name
        with path.open('rb') as f:
            digest=hashlib.file_digest(f,'sha256').hexdigest()
        if path.stat().st_size!=info['bytes'] or digest!=info['sha256']:
            raise ValueError('Changed input '+name)
    with gzip.GzipFile(fileobj=(a.prebuilt/'kernel').open('rb')) as f:
        kernel=f.read(128*1024*1024+1)
    if len(kernel)>128*1024*1024:raise ValueError('Kernel size bound')
    # The kernel also contains the printk format string "Linux version %s".
    release=re.search(rb'Linux version (\d+\.\d+\.\d+[^\s]*)',kernel)
    if not release:raise ValueError('Missing kernel release')
    release=release.group(1).decode()
    module_dir=a.prebuilt/'ramdisk/lib/modules'
    touch_patch=verify_module((module_dir/'touch_common.ko').read_bytes(),manifest.get('touch_recovery_patch'))
    verified=[]
    for path in module_dir.glob('*.ko'):
        data=path.read_bytes()
        match=re.search(rb'(?:^|\x00)vermagic=([^\x00]+)',data)
        if not match or match.group(1).split()[0].decode()!=release:
            raise ValueError('Kernel ABI mismatch '+path.name)
        verified.append(path.name)
    deps={}
    for name in ('modules.dep','modules.load.recovery'):
        if b'\r' in (module_dir/name).read_bytes():
            raise ValueError('Non-Linux line endings in '+name)
    for line in (module_dir/'modules.dep').read_text().splitlines():
        name,_,children=line.partition(':')
        deps[Path(name).name]=[Path(s).name for s in children.split()]
    missing=[]
    loads=(module_dir/'modules.load.recovery').read_text().splitlines()
    if loads != manifest.get('first_stage_module_loads'):
        raise ValueError('First-stage module list differs from the reviewed stock bootstrap set')
    touch_modules=manifest.get('added_touch_modules',manifest.get('added_signed_modules',[]))
    if set(loads) & set(manifest.get('added_runtime_modules',touch_modules)):
        raise ValueError('Added runtime modules must load later in TWRP, not in first-stage init')
    for name,children in deps.items():
        if not (module_dir/name).is_file():continue
        missing += [(name,child) for child in children if not (module_dir/child).is_file()]
    if missing:raise ValueError('Missing recovery module dependencies '+str(missing[:8]))
    result={'status':'offline_input_audit_passed','kernel_release':release,'modules_verified':len(verified),
            'first_stage_module_count':len(loads),'touch_load_stage':manifest['touch_load_stage'],
            'all_listed_file_hashes_verified':True,'module_dependency_closure_verified':True,
            'touch_modules':touch_modules,'touch_recovery_patch':touch_patch,
            'runtime_boot_touch_USB_or_decryption_verified':False,'device_access':False}
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
