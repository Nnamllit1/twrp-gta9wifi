"""Offline ELF closure check for recovery startup; never executes image code."""
from pathlib import Path, PurePosixPath
import stat

import elf64_symbols as _elf


def audit_startup(entries):
    """Check the ARM64 linker and every transitive startup DT_NEEDED library.

    This port's recovery linker searches /system/lib64 and /vendor/lib64/hw.
    Providers elsewhere in the archive do not satisfy those dependencies.
    """
    def resolve(path):
        for _ in range(32):
            record = entries.get(path)
            if record is None:
                raise ValueError('Missing recovery startup file: ' + path)
            if not stat.S_ISLNK(record['mode']):
                if not stat.S_ISREG(record['mode']):
                    raise ValueError('Startup file is not regular: ' + path)
                return path, record
            target = record['body'].decode('utf8')
            path = str(PurePosixPath(target.lstrip('/')) if target.startswith('/')
                       else PurePosixPath(path).parent / target)
            if '..' in PurePosixPath(path).parts:
                raise ValueError('Unsupported startup symlink traversal: ' + path)
        raise ValueError('Startup symlink loop: ' + path)

    linker_path, linker = resolve('system/bin/linker64')
    _elf.Elf(linker['body'])
    if not linker['mode'] & 0o111:
        raise ValueError('Recovery linker is not executable')
    result = {'linker': linker_path, 'entrypoints': {}}
    for start in ('system/bin/init', 'system/bin/adbd', 'system/bin/recovery'):
        queue, visited, defined, required = [start], set(), set(), set()
        while queue:
            path, record = resolve(queue.pop())
            if path in visited:
                continue
            visited.add(path)
            if path == start and not record['mode'] & 0o111:
                raise ValueError('Recovery startup executable has no execute bit: ' + path)
            image = _elf.Elf(record['body'])
            defined.update(image.defined())
            required.update(image.required())
            for name in image.needed:
                if '/' in name:
                    raise ValueError('Unexpected library path in ' + path + ': ' + name)
                choices = [directory + '/' + name for directory in
                           ('system/lib64', 'vendor/lib64/hw')]
                provider = next((p for p in choices if p in entries), None)
                if provider is None:
                    raise ValueError('Missing startup library ' + name + ' required by ' + path)
                queue.append(provider)
        missing = sorted(required - defined)
        if missing:
            raise ValueError('Unresolved startup symbols in ' + start + ': ' + ', '.join(missing[:12]))
        result['entrypoints'][start] = {'libraries_and_executable': sorted(visited),
                                        'missing_libraries': [], 'missing_strong_symbols': []}
    result['runtime_verified'] = False
    return result
