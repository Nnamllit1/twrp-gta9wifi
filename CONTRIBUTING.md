# Contributing

This is a community project. Contributions do not require claiming an official
TeamWin maintainer role. Keep public issues and pull requests focused on
reproducible device behavior and source changes.

Use the pinned firmware/source inputs and follow `docs/build.md`. Run:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

Firmware/image fixture tests skip when their private inputs are absent. Set
`TWRP_TEST_FIXTURES` to a private fixture directory when available. The Linux
installer controls also require their explicitly documented fixture environment.
Keep proprietary inputs, built images, keys, logs and device backups out of Git.

Record each device result against its model, panel, firmware, recovery hash and
storage/credential type. Do not post credentials, identifiers, raw EFS, keys or
user-data archives. Decryption, backup creation and successful restoration are
separate acceptance results. Never label a simulation as hardware validation.

Review `docs/validation.md` before claiming broader support. Add focused
regressions for changed parsing, image-scope or installer behavior. Kernel,
module and trusted-provider changes need component provenance and device tests.
