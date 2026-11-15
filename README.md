# Community TWRP for Galaxy Tab A9 (SM-X110)

An unofficial community port for `gta9wifi`, targeting the retained
`X110XXU4CYE5` firmware baseline. This project is independent of Samsung and
TeamWin and is not an official TeamWin release or maintainer appointment.

## Tested support

- Recovery boot, root ADB and touch on the Novatek NT36523D panel variant.
- CPU/SOC temperature, battery percentage and full-battery charging indication.
- Fresh encrypted data created under rooted CYE5 Android: no-lock, PIN,
  pattern and alphanumeric-password decryption.
- Matching Android/recovery synthetic-file hashes, with normal Android unlock
  afterward for each tested credential type.
- Password test: CE file unreadable before entry and readable afterward in the
  same recovery boot.
- Boot and Data backup creation, with the Boot image matching the live partition
  and synthetic local/CE files present in the Data archive. Restore is pending.

The tested decryption scope is fresh data created under the rooted CYE5 boot
baseline. Existing data created under unrooted stock Android is unsupported.
SM-X115, SM-X210 and other panel variants require separate device validation.
See [support status](docs/status.md) and the [acceptance checklist](docs/validation.md)
for remaining tests, including restore, sideload, MTP and external storage.

## Build and installation

This repository contains source, pinned patches and input-preparation tools.
Obtain the exact original CYE5 firmware separately; proprietary firmware,
kernels/modules, device dumps and signing keys are not distributed here.

Follow [the build guide](docs/build.md). A Linux Android build environment,
Python 3.11+, the authenticated firmware inputs and the pinned upstream TWRP
checkout are required. Input tools reject different firmware components.

Installation requires an already unlocked compatible device and the tested
verification/persistence configuration. Recovery-only updates preserve the
installed bootloader and rooted BOOT payloads; this does not certify arbitrary
mixed firmware or hardware rollback behavior. The source tools do not
supply an automatic flashing or data-format workflow. Do not use a wipe as a
substitute for investigating an existing-data decryption failure.

## Contributing

Community testing and fixes are welcome. Report the exact model, panel,
firmware and recovery version, plus the operation and observed result. Keep
credentials, device identifiers, keys and raw device data out of public reports.
See [contribution guidelines](CONTRIBUTING.md).

Device/tooling sources are Apache-2.0 unless otherwise marked. Recovery patches
retain TeamWin's GPL-3.0-or-later terms; platform patches retain their upstream
licenses. See [license scope](LICENSE) and [upstream notices](NOTICE.md).
