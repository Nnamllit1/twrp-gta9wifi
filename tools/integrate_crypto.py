"""Integrate authenticated CYE5 providers and thermal/vold inputs into recovery.

Consumes prepare_crypto output and original vendor_dlkm. No device access,
service startup or firmware packaging. Existing inputs are checked before edits.
"""
import argparse
import hashlib
import erofs_image as erofs
import json
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
DLKM_SHA='0a3293741c1e0f172639ffb759c72bcf8c13b7848ef46e4d74462ff333bda9d0'
THERMAL_SHA='aed316e6e878d622664b34647ebf1be28db56e2468bc417f1e903a24fac23ad0'


def sha(body):return hashlib.sha256(body).hexdigest()


def integrate(prebuilt, providers, dlkm):
    manifest=json.loads((prebuilt/'inputs.json').read_text())
    if manifest['model']!='SM-X110' or manifest['build']!='X110XXU4CYE5':
        raise ValueError('Only prepared SM-X110 CYE5 inputs are supported')
    listed={r['path']:r for r in manifest['files']}
    for name,row in listed.items():
        body=(prebuilt/name).read_bytes()
        if len(body)!=row['bytes'] or sha(body)!=row['sha256']:
            raise ValueError('Prepared input changed: '+name)
    if {p.relative_to(prebuilt).as_posix() for p in prebuilt.rglob('*') if p.is_file()} != set(listed)|{'inputs.json'}:
        raise ValueError('Unexpected prepared input files')
    profile_raw=(ROOT/'device/samsung/gta9wifi/crypto-inputs.json').read_bytes()
    profile=json.loads(profile_raw)
    staged=json.loads((providers/'inputs.json').read_text())
    if (staged['profile_sha256']!=sha(profile_raw) or staged['files']!=profile['files']
            or staged['vendor_sha256']!=manifest['vendor_sha256']):
        raise ValueError('Crypto staging provenance differs from the pinned CYE5 profile')
    changes={}
    for row in profile['files']:
        name=PurePosixPath(row['output_path'])
        if name.is_absolute() or '..' in name.parts or not str(name).startswith('vendor/'):
            raise ValueError('Unsafe provider path')
        body=(providers/str(name)).read_bytes()
        if len(body)!=row['bytes'] or sha(body)!=row['sha256']:
            raise ValueError('Provider hash differs: '+str(name))
        changes['ramdisk/'+str(name)]=body
    with dlkm.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=DLKM_SHA:raise ValueError('Wrong vendor_dlkm')
    image=erofs.Image(dlkm)
    try:body=image.read(image.nodes['/lib/modules/soc_temp_lvts.ko'])
    finally:image.f.close()
    if sha(body)!=THERMAL_SHA:raise ValueError('Wrong thermal backend')
    changes['ramdisk/lib/modules/soc_temp_lvts.ko']=body
    dep_name='ramdisk/lib/modules/modules.dep'
    dep=(prebuilt/dep_name).read_bytes()
    thermal_dep=b'/lib/modules/soc_temp_lvts.ko:\n'
    if thermal_dep not in dep:dep=dep.rstrip()+b'\n'+thermal_dep
    changes[dep_name]=dep
    for name in ('fstab.mt8781','fstab.mt6789'):
        changes['ramdisk/system/etc/'+name]=(prebuilt/'reference'/name).read_bytes()
    # Authenticate everything before writing; never replace a different provider.
    for name,body in changes.items():
        target=prebuilt/name
        if target.exists() and name!=dep_name and target.read_bytes()!=body:
            raise ValueError('Conflicting existing integration input: '+name)
    for name,body in changes.items():
        target=prebuilt/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
        listed[name]={'path':name,'bytes':len(body),'sha256':sha(body)}
    manifest['files']=[listed[n] for n in sorted(listed)]
    manifest['added_runtime_modules']=sorted(set(manifest.get('added_runtime_modules',manifest['added_touch_modules']))|{'soc_temp_lvts.ko'})
    manifest['crypto_inputs']={'firmware':profile['firmware'],'profile_sha256':sha(profile_raw),
        'files':profile['files'],'runtime_OS_release':'15','runtime_security_patch':'2025-04-01',
        'trusted_storage_mount':'ro,noload','new_key_provisioning_requested':False,
        'runtime_decryption_verified':False}
    (prebuilt/'inputs.json').write_text(json.dumps(manifest,indent=2)+'\n',newline='\n')
    return {'providers_verified':len(profile['files']),'thermal_module_sha256':THERMAL_SHA,
            'vold_fstabs':'Original CYE5','device_access':False,'decryption_verified':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prebuilt',type=Path,required=True);p.add_argument('--providers',type=Path,required=True)
    p.add_argument('--vendor-dlkm',type=Path,required=True);a=p.parse_args()
    print(json.dumps(integrate(a.prebuilt,a.providers,a.vendor_dlkm),indent=2))


if __name__=='__main__':main()
