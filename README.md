# Community TWRP for Galaxy Tab A9 (SM-X110)

An unofficial community port for `gta9wifi`, targeting the retained
`X110XXU4CYE5` firmware baseline. This project is independent of Samsung and
TeamWin and is not an official TeamWin release or maintainer appointment.

Original repository: [Nnamllit1/twrp-gta9wifi](https://github.com/Nnamllit1/twrp-gta9wifi).
Community forks and build experiments are welcome; check which repository and
image a report refers to before applying its results to this port.

## What works

Results apply to **SM-X110**, **X110XXU4CYE5** and the **Novatek NT36523D** panel.
Latest tested recovery: **0.1.14**.

| Feature | Status |
| --- | --- |
| Recovery boot, root ADB and touchscreen | Working |
| CPU temperature, battery and charging indication | Working |
| PIN, pattern and password decryption | Working on the tested setup |
| Internal Boot, Recovery and Data backup/restore | Working; Data restore preserves internal media |
| ADB image backup and Boot restore | Working |
| Recovery ZIP installation and sideload | Working |
| Clock, timezone and saved settings | Working |
| Command-line operations | Working |
| Screen colours, off/wake and brightness | Working |
| MTP file transfer | Working with Windows |
| Other maintenance operations | Not fully verified |
| Password-encrypted backup archives | Not included |
| microSD and USB-OTG | Untested |
| Data created under unrooted stock Android | Not yet verified |
| Other models and panel variants | Untested |

Normal Android root is not an established requirement. The passing decryption
tests used fresh data created during rooted CYE5 testing; removing root or
using stock-created data needs separate validation. Recovery includes its own
privileged shell and does not call Android's Magisk service to decrypt data.
SM-X115, SM-X210 and other panel variants require separate device validation.
See [support status](docs/status.md) for detailed limits and the
[acceptance checklist](docs/validation.md) for completed and remaining tests.

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
