#!/usr/bin/env bash
# Run inside the dedicated Linux build VM or a chosen Linux build host.
set -euo pipefail
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git gnupg flex bison build-essential zip curl zlib1g-dev libc6-dev-i386 \
  libncurses-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils \
  xsltproc unzip fontconfig python3 python-is-python3 bc libssl-dev rsync lz4 ccache ca-certificates
mkdir -p "$HOME/bin" "$HOME/twrp-build"
if [[ ! -e "$HOME/bin/repo" ]]; then
  curl --fail --location https://storage.googleapis.com/git-repo-downloads/repo \
    --output "$HOME/bin/repo"
  chmod 0755 "$HOME/bin/repo"
fi
printf 'Linux build prerequisites ready\n'
