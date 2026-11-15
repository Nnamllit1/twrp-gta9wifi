# SM-X110 CYE5 support status

Unofficial community port, tested on Galaxy Tab A9 SM-X110 (`gta9wifi`) with
`X110XXU4CYE5` and a Novatek NT36523D panel. SM-X115, SM-X210 and other panels
need their own validation. Latest tested recovery: 0.1.12.

## Verified scope

| Feature | Result and limits |
| --- | --- |
| Recovery boot / root ADB | Passed; installed recovery and startup-script hashes match the reviewed 0.1.12 build |
| Touch | Physically confirmed on the NT36523D variant; bundled modules retained |
| CPU/SOC temperature | Original CYE5 thermal module loads; sensor/UI previously confirmed |
| Battery and charger indication | Percentage and full-battery plus indicator previously confirmed |
| RTC / timezone | Clock readable; timezone refresh passed; persistent timezone settings need further checks |
| Fresh encrypted rooted CYE5 data | Metadata and user-0 file decryption passed |
| No-lock decryption | Passed in 0.1.10 with exact Android/recovery media-file hash |
| PIN | 0.1.12 UI acceptance, exact CE-file readback and subsequent Android unlock passed |
| Pattern | Separate 0.1.12 boot; same file readback and Android return control passed |
| Alphanumeric password | CE file unreadable before entry and readable with identical Android SHA256 after entry in the same boot; Android unlock afterward passed |
| Trusted storage | Private journaled backing, read-only public EFS, writable existing TEE subtree and separate read-only sec_efs observed; all 23 inspected TEE entries correctly labeled |
| Boot / Data backup creation | Passed; saved Boot SHA256 matches live rooted BOOT; completed Data TAR lists both synthetic local and CE test files |
| Restore | Untested; archive creation and checksums are not proof of restoration |
| Direct recovery ZIP updates | Earlier installed update/readback passed; final 0.1.12 installation used a recovery-only AP |
| Sideload / MTP | Untested |
| microSD / USB-OTG | Untested; no physical media available |
| Wipe/format variants, encrypted archives, cancel/retry, filesystem changes | Further acceptance testing required |

The exact 0.1.12 recovery SHA256 is:

`c0f5e8d2523f9ababf12ec26223ad2da8cd1b274de65d0ccd369226f2220afe4`

## Constraints

Decryption results apply to fresh encrypted data created under rooted CYE5
Android. Data created under original unrooted stock Android is unsupported:
the existing metadata key was rejected with `INVALID_KEY_BLOB` / authenticated
unwrapping error `-33` in the modified boot state. Observed integrity flags
`0x6` and `0x7` are separate from bootloader rollback revisions. Whether root
must remain installed permanently is not settled by these tests.

PIN and pattern were entered before their diagnostic captures, so those boots
do not establish pre-authentication CE inaccessibility. The password boot does.
Repeated PIN boots and independent new-file SELinux inheritance still need
separate checks. No credential guessing or manual secure-counter reset is part
of this port. An active hardware retry delay must be respected.

0.1.11 install packages were withdrawn after incorrect trusted-storage labels
broke normal Android authentication. 0.1.12 adds the original TEE file type and
path rules, restores that subtree's labels before provider startup, and keeps
normal counter writes scoped to the existing TEE subtree. The passing credential
tests followed fresh setup; this image does not clear a secure timeout.

First installation still requires a compatible unlocked baseline, verification
configuration and stock-recovery persistence fix. Recovery-only updates assume
those prerequisites; a complete first-install persistence workflow is not
packaged in this source repository. No binary firmware is distributed here.

Use the [acceptance checklist](validation.md) before claiming broader support
or official maintainer status. Report actual hardware results separately from
builds, protocol simulations and file audits.
