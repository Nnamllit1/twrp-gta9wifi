"""Read the hash-pinned SM-X110 CYE5 recovery; never access a device.

Extracted stock binaries are private build inputs. No flashable image is made.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import tarfile

MEMBER = 'recovery.img.lz4'
PAYLOAD_SHA = 'd1e204b463e52d0b14a315aa5f9a1cdb0dc1bfbb61c797a74054af778e9d345b'
KERNEL_SHA = '1b921c55d8335eb7e78c02a40e6f29b494009527371ec0289f62f7badcf5889a'
VBMETA_PACKED_SHA = 'c7841af8678c8337d0965be3161312a1980b500e0200be9d08a9ce07f78935e7'
VBMETA_RAW_SHA = '5bde91030560b6283d8e1d5bf13e3aea0b83e0146c1c5fe714078d51400770a0'
MAX_RAMDISK = 192 * 1024 * 1024
SIGNER_BYTES = 512


def sha(data):
    return hashlib.sha256(data).hexdigest()


def align(value, block=4):
    return (value + block - 1) // block * block


def read_newc(data):
    """Parse metadata without following or creating links from the archive."""
    pos, seen, result = 0, set(), []
    while pos < len(data):
        if pos + 110 > len(data) or data[pos:pos + 6] not in (b'070701', b'070702'):
            raise ValueError('Invalid newc header')
        fields = [int(data[pos + 6 + 8*i:pos + 14 + 8*i], 16) for i in range(13)]
        ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor, rmajor, rminor, namesize, check = fields
        if not 1 <= namesize <= 4096 or pos + 110 + namesize > len(data):
            raise ValueError('Invalid newc name size')
        raw = data[pos + 110:pos + 110 + namesize]
        if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
            raise ValueError('Invalid newc name')
        name = raw[:-1].decode('utf8', 'strict')
        start = align(pos + 110 + namesize)
        end = start + size
        if end > len(data):
            raise ValueError('Truncated newc body')
        body = data[start:end]
        if data[pos:pos+6] == b'070702' and sum(body) & 0xffffffff != check:
            raise ValueError('newc CRC mismatch')
        pos = align(end)
        if name == 'TRAILER!!!':
            if size or any(data[pos:]):
                raise ValueError('Unexpected data after newc trailer')
            return result
        if name == '.':
            continue
        if name.startswith('./'):
            name = name[2:]
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or name in seen:
            raise ValueError('Unsafe or duplicate newc path')
        seen.add(name)
        result.append({'name': name, 'mode': mode, 'uid': uid, 'gid': gid,
                       'nlink': nlink, 'mtime': mtime, 'ino': ino, 'body': body})
        if len(result) > 20000:
            raise ValueError('Excessive newc entries')
    raise ValueError('Missing newc trailer')


def parse_boot(raw):
    if len(raw) != 83886080 or raw[:8] != b'ANDROID!':
        raise ValueError('Unexpected stock recovery size or magic')
    u32 = lambda p: struct.unpack_from('<I', raw, p)[0]
    u64 = lambda p: struct.unpack_from('<Q', raw, p)[0]
    if u32(40) != 2 or u32(36) != 4096 or u32(1644) != 1660 or u32(24):
        raise ValueError('Unexpected stock boot header')
    page = u32(36)
    kstart, ksize = page, u32(8)
    rstart, rsize = page + align(ksize, page), u32(16)
    ostart, osize = u64(1636), u32(1632)
    if ostart != rstart + align(rsize, page):
        raise ValueError('Unexpected stock overlay position')
    dstart, dsize = ostart + align(osize, page), u32(1648)
    if dstart + dsize > len(raw) - 64:
        raise ValueError('Stock sections exceed image')
    components = {'kernel': raw[kstart:kstart+ksize], 'ramdisk': raw[rstart:rstart+rsize],
                  'dtbo.img': raw[ostart:ostart+osize], 'dtb.img': raw[dstart:dstart+dsize]}
    if sha(components['kernel']) != KERNEL_SHA:
        raise ValueError('Stock kernel hash mismatch')
    metadata = {'image_sha256': sha(raw), 'header_version': 2, 'page_size': page,
                'kernel_addr': u32(12), 'ramdisk_addr': u32(20), 'second_addr': u32(28),
                'tags_addr': u32(32), 'dtb_addr': u64(1652), 'os_version_raw': u32(44),
                'board': raw[48:64].split(b'\0')[0].decode('ascii'),
                'cmdline': (raw[64:576] + raw[608:1632]).split(b'\0')[0].decode('ascii'),
                'avb_footer_present': raw[-64:-60] == b'AVBf',
                'components': {n: {'bytes': len(b), 'sha256': sha(b)} for n, b in components.items()}}
    if metadata['avb_footer_present']:
        original_size, vbmeta_off, vbmeta_size = struct.unpack_from('>QQQ', raw, len(raw)-52)
        if vbmeta_off + vbmeta_size > len(raw)-64 or raw[vbmeta_off:vbmeta_off+4] != b'AVB0':
            raise ValueError('Invalid original AVB footer')
        metadata['avb'] = {'original_image_bytes': original_size, 'vbmeta_offset': vbmeta_off,
                           'vbmeta_bytes': vbmeta_size,
                           'rollback_index': struct.unpack_from('>Q', raw, vbmeta_off+112)[0],
                           'flags': struct.unpack_from('>I', raw, vbmeta_off+120)[0],
                           'rollback_index_location': struct.unpack_from('>I', raw, vbmeta_off+124)[0]}
    return components, metadata


def samsung_signer_block(raw):
    """Read the original block at its structural location, never a string scan."""
    _, info = parse_boot(raw)
    if not info['avb_footer_present']:
        raise ValueError('Samsung recovery AVB footer is required')
    overlay = struct.unpack_from('<Q',raw,1636)[0]
    overlay_size = struct.unpack_from('<I',raw,1632)[0]
    dtb_size = struct.unpack_from('<I',raw,1648)[0]
    marker = overlay + align(overlay_size,4096) + align(dtb_size,4096)
    end = marker + 16 + SIGNER_BYTES
    if (end != info['avb']['original_image_bytes'] or end > info['avb']['vbmeta_offset']
            or raw[marker:marker+16] != b'SEANDROIDENFORCE'):
        raise ValueError('Missing or misplaced Samsung recovery metadata')
    block = raw[marker+16:end]
    if len(block) != SIGNER_BYTES or not block.startswith(b'SignerVer02'):
        raise ValueError('Missing Samsung SignerVer02 block')
    return block


def extract(stock_ap, output, lz4):
    if output.exists():
        raise ValueError('Use a fresh output directory')
    with tarfile.open(stock_ap) as archive:
        all_entries = archive.getmembers()
        entries = [e for e in all_entries if e.name == MEMBER]
        if len(entries) != 1 or not entries[0].isfile() or entries[0].size != 41025586:
            raise ValueError('Expected exactly the original recovery payload')
        payload = archive.extractfile(entries[0]).read()
        vbmeta_entries = [e for e in all_entries if e.name == 'vbmeta.img.lz4']
        if len(vbmeta_entries)!=1 or not vbmeta_entries[0].isfile() or vbmeta_entries[0].size!=3508:
            raise ValueError('Expected the original CYE5 vbmeta payload')
        packed_vbmeta = archive.extractfile(vbmeta_entries[0]).read()
    if sha(payload) != PAYLOAD_SHA:
        raise ValueError('Only the pinned SM-X110 CYE5 recovery is accepted')
    if sha(packed_vbmeta)!=VBMETA_PACKED_SHA:
        raise ValueError('Original CYE5 vbmeta payload hash mismatch')
    vbmeta = subprocess.run([str(lz4),'-d','-c','-q'],input=packed_vbmeta,
                            capture_output=True,check=True).stdout
    if sha(vbmeta)!=VBMETA_RAW_SHA:
        raise ValueError('Original decoded CYE5 vbmeta hash mismatch')
    r = subprocess.run([str(lz4), '-d', '-c', '-q'], input=payload, capture_output=True, check=True)
    components, metadata = parse_boot(r.stdout)
    signer = samsung_signer_block(r.stdout)
    compressed = components['ramdisk']
    if compressed.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as f:
            cpio = f.read(MAX_RAMDISK + 1)
        metadata['ramdisk_compression'] = 'gzip'
    elif compressed[:4] in (b'\x02\x21\x4c\x18', b'\x04\x22\x4d\x18'):
        cpio = subprocess.run([str(lz4), '-d', '-c', '-q'], input=compressed,
                              capture_output=True, check=True).stdout
        metadata['ramdisk_compression'] = 'lz4'
    else:
        raise ValueError('Unrecognized stock ramdisk compression')
    if len(cpio) > MAX_RAMDISK:
        raise ValueError('Excessive stock ramdisk')
    records = read_newc(cpio)
    output.mkdir(parents=True)
    (output/'reference').mkdir()
    (output/'reference/vbmeta.img').write_bytes(vbmeta)
    (output/'prebuilt').mkdir()
    for name in ('kernel', 'dtb.img', 'dtbo.img'):
        (output/'prebuilt'/name).write_bytes(components[name])
    (output/'prebuilt/samsung-signer.bin').write_bytes(signer)
    inventory = []
    for entry in records:
        name, body = entry['name'], entry['body']
        info = {k: v for k, v in entry.items() if k != 'body'}
        info.update(bytes=len(body), sha256=sha(body))
        inventory.append(info)
        # No archive symlinks, special nodes, init binaries, or stock policy are
        # installed into the source tree by this extraction tool.
        if not stat.S_ISREG(entry['mode']):
            continue
        if not (name.startswith(('lib/modules/', 'vendor/firmware/', 'vendor/etc/', 'system/etc/'))
                or name.endswith('.rc') or name in ('default.prop', 'prop.default')):
            continue
        target = output/'stock-files'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    metadata.update(source_member_sha256=PAYLOAD_SHA, ramdisk_cpio_sha256=sha(cpio),
                    original_top_vbmeta_sha256=sha(vbmeta),
                    source_member_authenticated=True, device_access=False,
                    samsung_signer={'bytes':len(signer),'sha256':sha(signer)},
                    flashable_image_created=False, entries=len(inventory))
    (output/'inventory.json').write_text(json.dumps(inventory, indent=2)+'\n')
    (output/'stock-recovery.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return metadata


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock-ap', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--lz4', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(extract(a.stock_ap, a.output, a.lz4), indent=2))


if __name__ == '__main__':
    main()
