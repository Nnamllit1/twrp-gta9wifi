"""Stage original SM-X110 CYE5 crypto-provider files for recovery development.

Authenticates the complete original vendor image and every selected file.
Does not access a device, modify a build tree, start services or create firmware.
The staged bundle is not proof that decryption works.
"""
import argparse
import hashlib
import erofs_image as erofs
import json
from pathlib import Path, PurePosixPath
import stat

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT/'device/samsung/gta9wifi/crypto-inputs.json'
VENDOR_SHA = '79de66ffd17edeaf28ef00d527ca440d2bdc079c9d660f9842c1fd58cd03532d'


def prepare(vendor, output):
    if output.exists():
        raise ValueError('Output already exists; refusing replacement')
    with vendor.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != VENDOR_SHA:
            raise ValueError('Only the original hash-pinned CYE5 vendor image is accepted')
    profile_raw = PROFILE.read_bytes()
    profile = json.loads(profile_raw)
    if (profile['schema_version'] != 1 or profile['model'] != 'SM-X110'
            or profile['firmware'] != 'X110XXU4CYE5' or profile['vendor_sha256'] != VENDOR_SHA):
        raise ValueError('Unexpected crypto input profile')
    image = erofs.Image(vendor)
    payloads, seen = [], set()
    try:
        for pin in profile['files']:
            source, target = pin['source_path'], PurePosixPath(pin['output_path'])
            if (not source.startswith(('/bin/', '/lib64/', '/tee/'))
                    or str(target) != 'vendor'+source or target.is_absolute()
                    or '..' in target.parts or '\\' in str(target) or ':' in str(target)
                    or str(target) in seen):
                raise ValueError('Unsafe or duplicate provider path')
            seen.add(str(target))
            node = image.nodes.get(source)
            if node is None or not stat.S_ISREG(node['mode']):
                raise ValueError('Provider input is missing or is not a regular file: '+source)
            data = image.read(node)
            if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
                raise ValueError('Provider file hash mismatch: '+source)
            if pin['mode'] not in ('0644', '0755'):
                raise ValueError('Unexpected output file mode')
            payloads.append((target, data))
    finally:
        image.f.close()
    # Validate every input before creating an output directory.
    output.mkdir(parents=True, exist_ok=False)
    for relative, data in payloads:
        target = output/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    inventory = {
        'schema_version': 1, 'model': 'SM-X110', 'firmware': 'X110XXU4CYE5',
        'vendor_sha256': VENDOR_SHA, 'profile_sha256': hashlib.sha256(profile_raw).hexdigest(),
        'files': profile['files'], 'device_access_performed': False,
        'services_started': False, 'build_tree_modified': False,
        'flashable_image_created': False, 'runtime_or_decryption_verified': False,
    }
    (output/'inputs.json').write_text(json.dumps(inventory, indent=2)+'\n', newline='\n')
    (output/'README.txt').write_text(
        'Private original CYE5 provider inputs for recovery development.\n'
        'Not a firmware image or an installable package. No services are started.\n'
        'Intended Linux modes are recorded in inputs.json.\n'
        'Do not redistribute proprietary firmware files.\n'
        'Runtime namespace, TEE startup, EFS access and data decryption remain unverified.\n',
        newline='\n')
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.vendor, args.output)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"Staged {len(result['files'])} original provider files; no device or build-tree changes.")


if __name__ == '__main__':
    main()
