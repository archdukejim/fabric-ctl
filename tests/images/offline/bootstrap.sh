#!/bin/bash
# Inside the box: install fabricctl from an offline bundle's own packages, exactly as the manual's procedure does
# (3.14.2.2, step 2; a copy of its commands, so a change there must be made here too).
#   bash bootstrap.sh <bundle>
set -euo pipefail
BUNDLE="$1"
sudo mkdir -m 755 /var/tmp/fabric-apt && cd /var/tmp/fabric-apt
sudo tar -xf "$BUNDLE" ubuntu deb
for d in ubuntu/dists/*; do
  echo "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] file:/var/tmp/fabric-apt/ubuntu ${d##*/} main universe"
done | sudo tee bundle.list
sudo mkdir -p lists/partial cache/archives/partial parts sources.d
printf '%s "%s";\n' Dir::Etc::SourceList "$PWD/bundle.list" Dir::Etc::SourceParts "$PWD/sources.d" \
  Dir::Etc::Parts "$PWD/parts" Dir::State::Lists "$PWD/lists" Dir::Cache "$PWD/cache" \
  Acquire::By-Hash no Acquire::Languages none | sudo tee apt.conf
sudo env APT_CONFIG="$PWD/apt.conf" apt-get update
sudo env APT_CONFIG="$PWD/apt.conf" apt-get install -y --no-install-recommends ./deb/fabricctl_*_all.deb
cd / && sudo rm -rf /var/tmp/fabric-apt
