# TWRP for Samsung Galaxy Tab A9 SM-X110

Development source port targeting the original `X110XXU4CYE5` recovery kernel,
device trees and kernel modules. SM-X115 and SM-X210 require separate validation.
Recovery boot, root ADB and the NT36523D touchscreen have been tested on CYE5.
Fresh encrypted data created under rooted CYE5 Android has passed no-lock
decryption in 0.1.10 and PIN/pattern/password decryption with subsequent Android
unlock in 0.1.12. Password testing also verified that the same CE test file was
unreadable before entry and readable afterward within one boot. Data created
under unrooted stock Android remains unsupported. Backups and other panel
variants require separate device tests.

The recovery has its own kernel and bundled CYE5 hardware modules, so bringing
up USB and touch does not require the installed Android vendor image. The data
configuration uses the stock FBE v2 algorithms and metadata key-directory path.
Samsung KeyMint/Gatekeeper support is validated only within that tested scope.

`tools/prepare_crypto.py` separately stages hash-pinned CYE5 KeyMint,
Gatekeeper and TEEGRIS providers, their private vendor libraries and original
TEE resources. It authenticates the complete vendor image and every selected
file before writing output. Staging does not start services or access a device:

```text
python tools/prepare_crypto.py --vendor ORIGINAL_VENDOR --output PRIVATE_PROVIDER_DIRECTORY
python tools/integrate_crypto.py --prebuilt device/samsung/gta9wifi/prebuilt --providers PRIVATE_PROVIDER_DIRECTORY --vendor-dlkm ORIGINAL_VENDOR_DLKM
```

The integration includes original TEE/KeyMint/Gatekeeper providers, a crypto
manifest and the original vold fstabs. Recovery requests the matched CYE5
OS/patch tuple and uses a private journaled EFS mount with a read-only public
root and a writable TEE subtree for normal provider updates. The separate
sec_efs filesystem stays read-only. Original CYE5 TEE labels are restored before
providers start; existing keys and counter contents are not manually replaced.
The boot header and AVB fields retain their original values. Provider readiness
alone does not establish that existing keys can be opened.

Android init and TWRP use separate partition tables. `recovery.fstab` uses
Android's five-column syntax, including the exact `/misc` mapping required by
init's recovery reboot. `/etc/twrp.fstab` carries TWRP's UI and backup flags;
substituting it for the init table prevents the reboot. The host-only
`gta9wifi_fstab_check` target validates the init table with the pinned Android
`libfstab` parser. Crypto setup also grants only the system UID/group access to
the GRDM transport before starting the original system-UID KeyMint provider.

Recovery USB initially exposes ADB. Its root shell is available only while this
recovery is running. Normal Android root is a separate change. The recovery
ramdisk uses development SELinux and ADB settings; these do not install a root
service into normal Android.

## Build inputs

Use the original CYE5 AP and the original vendor/vendor_dlkm images extracted
from its super image. The input tools authenticate exact SHA-256 values and
refuse another firmware version. They do not read a device, flash or make an
Odin package. Preparation applies the pinned recovery touch fix described below.
Proprietary firmware inputs remain outside published source.

```text
python tools/stock_recovery.py --stock-ap ORIGINAL_CYE5_AP --output STOCK_OUTPUT --lz4 LZ4_EXECUTABLE
python tools/prepare_inputs.py --stock STOCK_OUTPUT --vendor ORIGINAL_VENDOR --vendor-dlkm ORIGINAL_VENDOR_DLKM --device device/samsung/gta9wifi
python tools/audit_inputs.py --prebuilt device/samsung/gta9wifi/prebuilt --report INPUT_AUDIT.json
python tests/test_stock_recovery.py
python tests/test_vbmeta_scope.py
```

The audit checks file hashes, kernel/module release compatibility, complete
module dependencies and Linux module-list line endings. First-stage init uses
only the stock bootstrap module set; five touch modules remain
bundled for TWRP's later userspace loader. The exact CYE5 `touch_common.ko`
rejects recovery boot mode `2` before panel detection. `touch_recovery.py`
changes three instructions to accept modes `0`, `2` and `7`, retaining both
previously accepted modes, panel matching and the module ABI. The audit
reconstructs and hashes the complete original module. This modified module is
not Samsung-signed; the retained CYE5 kernel has module signature enforcement
disabled. All other 208 module binaries remain original. This patch is confined
to the recovery ramdisk. Novatek, Chipone, Himax and Jadard candidates remain
available for their respective panel variants; variant support needs live tests.
USB is requested in the fs phase
rather than the boot phase, and the platform init file retains stock's softdog setting.
The original `soc_temp_lvts.ko` sensor backend is loaded by TWRP as well; without
it the CPU/SOC temperature nodes return errors.
Battery status uses the kernel's standard `/sys/class/power_supply/battery`
interface. This avoids a background wait for a health HAL that is not registered
in recovery. The full-battery indicator patch keeps a connected, full battery
marked the same way as the health-service reader.

Track feature acceptance using [the validation checklist](validation.md).
The [support status](status.md) separates installed-image results,
temporary userspace tests and remaining limitations.

Boot and recovery images can be streamed to the PC with TWRP's ADB backup
protocol. The maintenance patch removes its unnecessary local-storage mount
requirement. `tools/audit_adb_image_backup.py` verifies a single uncompressed
image stream against an independently obtained partition hash, without
extracting a flashable image. Data archives and restoration need separate tests.

## Linux compilation

`tools/setup-linux-build.sh` installs build prerequisites into the chosen Linux
environment. `tools/sync-linux-source.sh` fetches a pinned minimal TWRP manifest
and saves the resolved source revisions after synchronization.

Copy `device/samsung/gta9wifi` into the source checkout at the same relative
path, including locally prepared prebuilts. Then:

```bash
python3 /path/to/twrp-gta9wifi/tools/apply-source-patches.py --source "$PWD" --check
python3 /path/to/twrp-gta9wifi/tools/apply-source-patches.py --source "$PWD"
source build/envsetup.sh
export ALLOW_MISSING_DEPENDENCIES=true
lunch twrp_gta9wifi-eng
mka -j4 recoveryimage
m gta9wifi_fstab_check
out/host/linux-x86/bin/gta9wifi_fstab_check device/samsung/gta9wifi/recovery.fstab
```

The [source patch notes](../patches/README.md) describe each pinned change and the
optional Binder compatibility diagnostic. Building that diagnostic is separate
from enabling existing-data decryption.

The minimal manifest omits CTS/VTS projects, so the upstream build requires
`ALLOW_MISSING_DEPENDENCIES`. A requested target with an unresolved dependency
still fails its build rule; successful image compilation remains required.


## Image acceptance

Before packaging a test image, verify its original kernel, base DTB and embedded
DTBO hashes, its 80 MiB partition bound, header version and patch fields, and AVB
rollback index/location `0/0`. The upstream example's future patch date and
nonzero recovery index are not used. A development image uses a test signature;
it is not Samsung-signed. File checks do not certify hardware rollback behavior.

The packager also checks ARM64 startup dependencies for init, adbd and recovery.
It rejects missing libraries and unresolved strong symbols in their transitive
library closures. The device configuration explicitly includes
`libresetprop.recovery`, which TWRP needs for FBE support.

Preserve the original CYE5 512-byte `SignerVer02` block immediately after
`SEANDROIDENFORCE`, before adding the recovery AVB footer. The stock extractor
authenticates the firmware and saves this block as a private build input;
the build and packaging checks retain all its bytes, including opaque version
fields. This follows [Magisk's preservation fix](https://github.com/topjohnwu/Magisk/commit/0265698).
Retaining the block does not give a modified image a valid Samsung signature.
The device must already be unlocked. The block is not generated with a new
version, and recovery AVB index/location remain zero.

For an incremental recovery test on an already configured device,
`package_recovery.py --recovery-only --version VERSION` creates an archive with
only recovery.img. This mode requires modified vbmeta to be installed already;
it neither installs the vendor persistence fix nor changes verification flags.
Add `--compress-recovery` to deliver the same raw recovery bytes as
`recovery.img.lz4`, matching the compressed payload form used by Samsung's AP.

Original CYE5 vbmeta authenticates recovery. The test packager therefore also
includes the exact original CYE5 vbmeta with only its four-byte verification
flags field changed from `0` to `2`. Its index, index location, descriptors and
all other bytes are preserved. This invalidates its original signature and
requires an already-unlocked loader accepting modified vbmeta. It does not
include a bootloader, secure-platform firmware, normal boot image or super image.

An initial device test should establish recovery boot, root ADB and input
devices before testing decryption. A decryption error is not a reason to format
data. No automatic wipe, unlock/relock, flashing or normal-Android modification
is included in the build tools.

For updates from an already working TWRP, `tools/package_install_zip.py` creates
a recovery-only development ZIP from the same audited raw image. It checks the
model, CYE5 loader, partition size and aliases, and image hash before writing;
it then verifies the complete readback. `TWRP_RECOVERY_VERIFY_ONLY=1` runs only
the checks when the extracted updater is invoked directly in recovery. This
environment flag must not be assumed to reach TWRP's Install/Sideload process.
The ZIP is unsigned and requires the installed persistence/modified-vbmeta
configuration. Direct Install has passed a recovery-only update and full
readback check; Sideload needs its own device validation.

`tools/stock_restore.py` prepares a small fallback with only the two original
CYE5 recovery/vbmeta payloads. With a patched vendor/system, use
`--recovery-only` instead: it restores stock recovery while leaving the current
verification flags and modified vendor untouched. Restoring original vbmeta
would re-enable verification against modified partition data.
`tools/capture-recovery.py` copies bounded logs
over a verified SM-X110 TWRP root shell; it issues no mount or reboot commands.

## Upstream references

- [TeamWin recovery source](https://github.com/TeamWin/android_bootable_recovery),
  Android 12.1 reference commit `5c3d206a5eeb3d446bcda8248a405a4b278bab5c`.
- [Minimal TWRP manifest](https://github.com/minimal-manifest-twrp/platform_manifest_twrp_aosp),
  commit `6dc117d9cbd08430daa16db2013560e1c4017fa8`.
- [Earlier gta9wifi recovery work](https://github.com/samsung-mediatek/android_recovery_device_samsung_gta9wifi),
  reviewed at `a086a00d0da6762ee056ac7903fc07ec8ee97804`.

Upstream framework, kernel and firmware components retain their respective
licenses and notices. This is an unofficial development port.
