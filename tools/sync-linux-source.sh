#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/bin:$PATH"
cd "$HOME/twrp-build"
repo init -u https://github.com/minimal-manifest-twrp/platform_manifest_twrp_aosp.git \
  -b 6dc117d9cbd08430daa16db2013560e1c4017fa8 --depth=1 --no-clone-bundle
repo sync --current-branch --no-tags --no-clone-bundle --fail-fast -j6
repo manifest -r -o source-manifest.xml
printf 'TWRP sources synchronized and revision manifest saved\n'
