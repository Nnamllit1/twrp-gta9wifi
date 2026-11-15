"""Check/apply recovery patches only to their pinned source revisions.

No device or firmware operations. Existing unrelated edits are left untouched.
All patches are checked before any are applied; --check performs no edits.
"""
import argparse
from pathlib import Path
import subprocess

PATCHES = Path(__file__).resolve().parents[1] / 'patches'
REQUIRED = (
    ('system/vold', 'a164ba05c5fef288059774a776b2e6e1119957cf',
     'samsung-metadata-rot.patch'),
    ('system/vold', 'a164ba05c5fef288059774a776b2e6e1119957cf',
     'vold-optional-upgrade.patch'),
    ('system/vold', 'a164ba05c5fef288059774a776b2e6e1119957cf',
     'gatekeeper-auth-result.patch'),
    ('bootable/recovery', '5c3d206a5eeb3d446bcda8248a405a4b278bab5c',
     'mount-crypto-before-metadata.patch'),
    ('bootable/recovery', '5c3d206a5eeb3d446bcda8248a405a4b278bab5c',
     'recovery-timezone-setting.patch'),
    ('bootable/recovery', '5c3d206a5eeb3d446bcda8248a405a4b278bab5c',
     'recovery-adb-stream-storage.patch'),
    ('bootable/recovery', '5c3d206a5eeb3d446bcda8248a405a4b278bab5c',
     'recovery-full-battery-indicator.patch'),
)
EXPERIMENTAL_BINDER = (
    'frameworks/native', '89c808424fbce9e40c0d4e0d1920b3c64a191b7f',
    'experimental/binder-cye5-compat.patch',
)


def git(repository, *args):
    return subprocess.run(['git', '-C', str(repository), *args],
                          capture_output=True, text=True)


def apply(source, check=False, binder_compat=False):
    plan = []
    for relative, revision, filename in (*REQUIRED, *((EXPERIMENTAL_BINDER,) if binder_compat else ())):
        repository = source / relative
        head = git(repository, 'rev-parse', 'HEAD')
        if head.returncode or head.stdout.strip() != revision:
            raise ValueError('Source revision differs: ' + relative)
        patch = (PATCHES / filename).resolve(strict=True)
        forward = git(repository, 'apply', '--check', str(patch))
        if forward.returncode == 0:
            plan.append((repository, patch, filename))
        elif git(repository, 'apply', '--reverse', '--check', str(patch)).returncode == 0:
            print('Already applied:', filename)
        else:
            raise ValueError('Patch conflicts with current sources: ' + filename + '\n' + forward.stderr)
    for repository, patch, filename in plan:
        if check:
            print('Can apply:', filename)
        else:
            result = git(repository, 'apply', str(patch))
            if result.returncode:
                raise RuntimeError('Failed applying ' + filename + '\n' + result.stderr)
            print('Applied:', filename)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--check', action='store_true')
    p.add_argument('--binder-compat', action='store_true',
                   help='Also build experimental CYE5 Binder diagnostics; does not install stock Keystore')
    a = p.parse_args()
    apply(a.source.resolve(strict=True), a.check, a.binder_compat)


if __name__ == '__main__':
    main()
