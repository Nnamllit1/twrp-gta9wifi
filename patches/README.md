# Pinned recovery source changes

Run `python3 twrp/tools/apply-source-patches.py --source TWRP_CHECKOUT --check`,
then repeat without `--check` before compiling. The helper checks every target
revision and patch before applying changes. It also recognizes patches already
applied. Copy this directory and the helper alongside your prepared device tree.

The required patches perform seven separate changes:

- Mount the read-only vendor/ODM crypto prerequisites before metadata unlock.
- Add CYE5 vold's metadata-key operation parameter behind an explicit device
  property. This preserves the original KeyMint implementation and does not
  make an invalid key acceptable.
- Handle a successful key operation that has no upgraded blob, avoiding a null
  optional dereference. An upgraded blob, when present, remains staged in RAM
  by the existing recovery implementation.
- Refresh the recovery clock's timezone when its setting changes through the
  command interface as well as the settings page.
- Stream ADB backups directly to the host without requiring mounted local
  backup storage or creating/cleaning local backup directories. File-based
  partition backups still need their source filesystem to be accessible.
- Show the charger indicator for a full battery in the legacy sysfs reader,
  matching the health-service reader's full-battery behavior.
- Require an accepted Gatekeeper response, a complete authentication token and
  successful Keystore authorization before attempting credential-protected key
  operations. Failed and rate-limited replies return immediately; hardware
  retry delays are reported rather than appearing as a later Keystore failure.

`--binder-compat` additionally applies the experimental Binder API backport for
the CYE5 Keystore diagnostic. It preserves this branch's Binder stability/wire
code, adds real unlink-recipient cleanup, checks unconsumed Parcel data and
implements status replacement and tracing. The callback, Parcel and Status
implementations come from AOSP `android-13.0.0_r1` under Apache-2.0. The original
AOSP notices remain in the affected source files.

This option does not bundle or start stock Keystore. Its purpose is to make
the compatibility experiment reproducible. Service startup and ABI checks do
not establish that an existing metadata key can be opened.
