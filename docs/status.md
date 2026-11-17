# Support and limitations

This community port targets Galaxy Tab A9 **SM-X110**, firmware
**X110XXU4CYE5**, and the **Novatek NT36523D** touchscreen. Latest tested
recovery: **0.1.14**. It is not an official TeamWin release.

## Working

- Recovery boot, touchscreen and root ADB.
- PIN, pattern and password decryption on the tested encrypted-data setup.
- Internal Boot, Recovery and Data backup/restore, including internal-media
  preservation during Data restore.
- ADB image backups, Boot image restore, recovery ZIP updates and sideload.
- MTP file transfers with Windows.
- Brightness, screen off/wake, battery/charging and CPU temperature.
- Clock, timezone and saved settings.

## Limitations

- **Decryption without Android root is not yet verified.** The passing setup
  used data created during rooted CYE5 testing. Recovery does not call Android's
  Magisk service; that test setup does not establish a root requirement.
  Compatibility with existing stock-created data needs further validation.
- Password-encrypted backup archives are not included in the current build.
- microSD, USB-OTG and other external accessories have not been tested.
- Filesystem conversion, all wipe/format options and backup restore across
  credential, key or firmware changes have not been fully validated.
- SM-X115, SM-X210 and other panel variants require separate device support.

First installation requires a compatible unlocked device, verification
configuration and recovery-persistence setup. Recovery-only updates assume
those prerequisites. See [the build guide](build.md) and the
[contributor acceptance checklist](validation.md).
