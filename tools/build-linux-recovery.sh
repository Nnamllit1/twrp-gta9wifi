#!/usr/bin/env bash
# Android's envsetup intentionally reads unset optional shell variables.
set -eo pipefail
cd "$HOME/twrp-build"
export PATH="$HOME/bin:$PATH"
export GOMAXPROCS=6
# The upstream minimal manifest omits CTS/VTS source. Soong still scans their
# references; missing dependencies of a requested target remain build errors.
export ALLOW_MISSING_DEPENDENCIES=true
source build/envsetup.sh
lunch twrp_gta9wifi-eng
m -j4 recoveryimage host_init_verifier
out/host/linux-x86/bin/avbtool verify_image --image out/target/product/gta9wifi/recovery.img \
  --key external/avb/test/data/testkey_rsa4096.pem
sha256sum out/target/product/gta9wifi/recovery.img
printf 'Recovery source build finished; image still requires the host audit\n'
