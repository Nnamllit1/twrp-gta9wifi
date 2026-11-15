"""Exact CYE5 recovery-only touch boot-mode fix; no device operations.

tp_detect_panel in touch_common rejects recovery boot mode 2 before checking
the panel name. Replace its {0, 7} gate with {0, 2, 7}, keeping w0, the error
argument w4, the following branch and all panel matching/relocations intact.
This applies only to the private recovery ramdisk, never installed vendor.
"""
import hashlib

ORIGINAL_SHA256 = 'bf7ea1457112cc57c1042f5ff249bfd63487565a37b167d17164598fe530d3c4'
MODULE_BYTES = 69592
# .text file offset 0x1000 + tp_detect_panel 0x1f8c + function offset 0xa0.
OFFSET = 0x302c
BEFORE = bytes.fromhex('80000034 e403002a 1f1c0071')
# Assembled and independently disassembled with the pinned build Clang:
# subs w4,w0,#0; ccmp w0,#2,#4,ne; ccmp w0,#7,#4,ne
# NZCV=4 preserves Z when an earlier comparison accepted the mode.
AFTER = bytes.fromhex('04000071 0418427a 0418477a')
FOLLOWING = bytes.fromhex('c1040054 340200b4')  # b.ne reject; cbz x20,no-panel


def digest(body):
    return hashlib.sha256(body).hexdigest()


def patch_original(body):
    if len(body) != MODULE_BYTES or digest(body) != ORIGINAL_SHA256:
        raise ValueError('Touch fix requires the exact original SM-X110 CYE5 touch_common.ko')
    if body[OFFSET:OFFSET+12] != BEFORE or body[OFFSET+12:OFFSET+20] != FOLLOWING:
        raise ValueError('Unexpected CYE5 touch detection instructions')
    result = body[:OFFSET] + AFTER + body[OFFSET+12:]
    report = {
        'module': 'touch_common.ko', 'scope': 'recovery_ramdisk_only',
        'original_sha256': ORIGINAL_SHA256, 'patched_sha256': digest(result),
        'bytes': MODULE_BYTES, 'file_offset': OFFSET, 'instruction_bytes': 12,
        'original_hex': BEFORE.hex(), 'patched_hex': AFTER.hex(),
        'original_allowed_modes': [0, 7], 'patched_allowed_modes': [0, 2, 7],
        'panel_matching_and_other_module_bytes_unchanged': True,
        'ELF_layout_symbols_modversions_and_relocations_unchanged': True,
        'original_module_has_appended_kernel_signature': False,
        'modified_module_is_Samsung_signed': False,
        'requires_kernel_without_module_signature_enforcement': True,
    }
    return result, report


def verify_module(body, report=None):
    """Reconstruct and authenticate the complete original, not just a window."""
    if report is None:
        if len(body) != MODULE_BYTES or digest(body) != ORIGINAL_SHA256:
            raise ValueError('Unexpected original touch_common module')
        return {'patch_applied': False, 'sha256': digest(body)}
    if body[OFFSET:OFFSET+12] != AFTER:
        raise ValueError('Missing reviewed recovery touch instructions')
    original = body[:OFFSET] + BEFORE + body[OFFSET+12:]
    expected, expected_report = patch_original(original)
    if body != expected or report != expected_report:
        raise ValueError('Touch patch or its manifest differs from reviewed scope')
    return {'patch_applied': True, **expected_report}
