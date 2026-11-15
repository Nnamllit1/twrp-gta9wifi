"""Copy bounded recovery diagnostics to the PC over an existing root ADB shell.

Requires an SM-X110 running TWRP. Never invokes adb root, a mount, reboot,
flash, format, settings change or unlock command. No key/data/EFS files read.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess

FILES={
 '/tmp/recovery.log':4*1024*1024,
 '/proc/last_kmsg':4*1024*1024,
 '/proc/sec_log':4*1024*1024,
 '/proc/reset_reason':4096,
 '/cache/recovery/last_kernel':2*1024*1024,
 '/cache/recovery/last_kmsg':2*1024*1024,
 '/cache/recovery/last_log':2*1024*1024,
 '/sys/fs/pstore/console-ramoops':2*1024*1024,
 '/sys/fs/pstore/console-ramoops-0':2*1024*1024,
 **{f'/cache/recovery/last_fwblp_early_{i}.log':4*1024*1024 for i in range(4)},
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('Use a fresh private output directory')
    r=subprocess.run([str(a.adb),'devices'],capture_output=True,timeout=10)
    rows=[s.split() for s in r.stdout.decode(errors='replace').splitlines()
          if len(s.split())==2 and s.split()[1] in ('device','recovery')]
    if r.returncode or len(rows)!=1:
        p.error('Exactly one authorized recovery ADB device is required')
    serial=rows[0][0]
    def run(*command):
        args=[str(a.adb),'-s',serial,*command]
        try:
            return subprocess.run(args,capture_output=True,timeout=20)
        except subprocess.TimeoutExpired as error:
            # Retain earlier diagnostics and partial output if USB disappears
            # or a diagnostic tool stays attached to its event stream.
            return subprocess.CompletedProcess(args,124,error.stdout or b'',
                (error.stderr or b'')+b'\nPC diagnostic command timed out after 20 seconds.\n')
    def prop(name):
        r=run('shell','getprop',name)
        if r.returncode:raise RuntimeError('Recovery property read failed')
        return r.stdout.decode(errors='replace').strip()
    properties={name:prop(name) for name in ('ro.product.model','ro.twrp.boot','ro.twrp.version')}
    uid=run('shell','id','-u')
    if (properties['ro.product.model']!='SM-X110' or properties['ro.twrp.boot']!='1'
            or not properties['ro.twrp.version'] or uid.returncode or uid.stdout.strip()!=b'0'):
        p.error('SM-X110 TWRP root shell was not verified; no diagnostic files read')
    a.output.mkdir(parents=True)
    report={'captured_utc':datetime.now(timezone.utc).isoformat(),'properties':properties,'uid':0,
            'device_mutations_issued':False,'mounts_issued':False,'files':[],'commands':[]}
    for name,command in (
        ('kernel-early',['dmesg']),('recovery-log-early',['head','-c','4194304','/tmp/recovery.log']),
        ('kernel-release',['uname','-r']),('selinux',['getenforce']),
        ('mounts',['cat','/proc/mounts']),('modules',['cat','/proc/modules']),
        ('input-capabilities',['getevent','-lp']),
        ('tee-device-permissions',['ls','-l','/dev/tzdev','/dev/tziwsock','/dev/tziwshmem','/dev/grdm']),
        ('binder-services',['service','list'])):
        r=run('shell',*command)
        (a.output/(name+'.txt')).write_bytes(r.stdout[:256*1024])
        (a.output/(name+'.stderr.txt')).write_bytes(r.stderr[:4096])
        report['commands'].append({'name':name,'command':command,'exit_code':r.returncode})
    report['runtime_properties']={}
    for name in ('ro.hardware','ro.board.platform','ro.build.version.release',
            'ro.build.version.security_patch','ro.vendor.build.security_patch',
            'ro.vndk.version','vendor.tzdaemon','vendor.tzts_daemon',
            'init.svc.keystore2','init.svc.servicemanager','init.svc.hwservicemanager',
            'init.svc.adbd','sys.usb.config','sys.usb.state',
            'ro.bootloader','ro.boot.mode','ro.boot.bootreason'):
        r=run('shell','getprop',name)
        report['runtime_properties'][name]={
            'value':r.stdout.decode(errors='replace').strip()[:1024],
            'exit_code':r.returncode}
    for index,(path,limit) in enumerate(FILES.items()):
        # ADB exec-out does not reliably propagate the remote command status.
        # Shell v2 without a PTY preserves these text logs and reports failures,
        # rather than saving a missing-file error as a successful capture.
        r=run('shell','head','-c',str(limit+1),path)
        row={'source':path,'exit_code':r.returncode,'stderr':r.stderr.decode(errors='replace')[:512]}
        if path.startswith('/cache/recovery/last_'):
            row['may_be_from_an_older_boot']=True
        if not r.returncode:
            data=r.stdout[:limit]
            name=f'{index:02d}-'+Path(path).name
            (a.output/name).write_bytes(data)
            row.update(file=name,bytes=len(data),truncated=len(r.stdout)>limit,
                       sha256=hashlib.sha256(data).hexdigest())
        report['files'].append(row)
    (a.output/'capture.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Recovery diagnostics saved privately to '+str(a.output))
    print('No mounts, reboots, root commands, flashing or device changes issued.')


if __name__=='__main__':main()
