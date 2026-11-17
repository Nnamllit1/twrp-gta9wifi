# SM-X110 recovery validation

Use TeamWin's [maintainer checklist](https://twrp.me/faq/OfficialMaintainer.html)
as the acceptance list. A development port remains unofficial until TeamWin
accepts its device tree. Reproducible source must not contain proprietary
firmware binaries, device identifiers, user data or encryption keys.

Record each result against an exact image SHA-256, firmware build and storage
target. Separate a cold boot from a temporary userspace probe. Use `passed`,
`failed`, `untested` or `not applicable`; simulated storage does not establish
microSD or OTG hardware support.

| Area | Verification |
| --- | --- |
| Screen/input | Full layout, correct colors, touch edges/scrolling, physical keys, sleep/wake and brightness |
| ADB | Root recovery shell, reconnect, command interface and retained diagnostics |
| Data | Existing metadata-encrypted F2FS, DE/CE unlock, internal storage and normal Android boot afterward |
| Internal backups | Boot/recovery/data backup, checksums, archive contents, controlled restore and content checks after boot |
| Backup options | Compression, encrypted backup, space checks, cancel/retry and ADB backup/restore |
| External storage | Physical microSD/OTG mount, read/write, backup/restore, removal and supported filesystem formats |
| Partitions | Correct mount/backup list, EROFS read-only mounts, F2FS/ext4, dynamic partitions and correct aliases |
| Installation | Recovery ZIP preflight, full image hash, write/readback verification, direct install and sideload |
| Reboots | Android, recovery, Download Mode, poweroff and recovery persistence across Android |
| Telemetry | Battery, charging indication, CPU/SOC temperature, RTC and timezone |
| Maintenance | Wipe/format/restore on an agreed test state; distinguish restoring files from restoring encryption keys |
| Device-dependent | Vibration, USB input, MTP, mass-storage export, screenshots and SD partitioning |

Recovery updates must preserve the retained loader and original rollback fields.
They must not silently add bootloader, secure firmware, root vbmeta, super,
userdata or metadata payloads. An old data archive restored after Android has
advanced its keys needs a separate compatibility test.

Keep detailed test evidence private. Public bug reports should describe the
operation and observed result without credentials, device identifiers or raw
user data. Use a dedicated test dataset and verify its content; a completed
progress bar alone does not establish a working backup and restore.
