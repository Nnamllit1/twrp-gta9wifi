# Community TWRP for Galaxy Tab A9 (SM-X110)

An unofficial community port for `gta9wifi`, targeting the retained
`X110XXU4CYE5` firmware baseline. This project is independent of Samsung and
TeamWin and is not an official TeamWin release or maintainer appointment.

Original repository: [Nnamllit1/twrp-gta9wifi](https://github.com/Nnamllit1/twrp-gta9wifi).
Community forks and build experiments are welcome; check which repository and
image a report refers to before applying its results to this port.

## What works

Results apply to recovery **0.1.12**, **SM-X110**, **X110XXU4CYE5** and the
**Novatek NT36523D** panel. A passing build alone does not establish device support.

| Feature | Status | Scope |
| --- | --- | --- |
| Recovery boot, root ADB, touch | Working | Tested on the NT36523D panel variant |
| CPU/SOC temperature, battery and charging indication | Working | Sensor display and full-battery charging indicator confirmed |
| Data decryption | Working with prerequisites | Fresh encrypted data created under rooted CYE5; no lock, PIN, pattern and alphanumeric password tested, with normal Android unlock afterward |
| Boot and Data backups | Creation verified | Boot image hash and synthetic files in the Data archive checked; restore not yet verified |
| Recovery-only ZIP installation | Earlier updates verified | Guarded write/readback path; latest 0.1.12 was installed through AP |
| Clock and timezone | Partly verified | Clock readable and timezone refresh works; persistent settings pending |
| Sideload, MTP, encrypted backup and other maintenance operations | Untested | See the acceptance checklist for individual checks |
| microSD and USB-OTG | Untested | No physical media available for validation |
| Existing data created under unrooted stock Android | Unsupported | Metadata key rejected in the modified boot state |
| Other models and panel variants | Untested | SM-X115 and SM-X210 are not covered by these results |

The tested decryption scope is fresh data created under the rooted CYE5 boot
baseline. Existing data created under unrooted stock Android is unsupported.
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
