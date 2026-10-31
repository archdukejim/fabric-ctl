#!/usr/bin/env bash
# Writes the lab's unattended-install media into D:\Hyper-V\fabric-lab\seed (manual 3.1.5.3, decision 2.1.1.65).
# Run in WSL (Ubuntu): scripts/lab/make_seeds.sh [--only g23-vm-rtr-1,g23-vm-ub24-1]
# Needs xorriso and openssl (sudo apt-get install -y xorriso). The original ISOs are only read.
# Passwords (Windows' labadmin, Proxmox's root) are generated once into %USERPROFILE%\fabric-lab\ (owner-only) and
# never printed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
for t in xorriso openssl python3 icacls.exe cmd.exe wslpath; do
    command -v "$t" >/dev/null || { echo "make_seeds: $t is missing (apt-get install -y xorriso openssl)" >&2; exit 1; }
done
win_profile="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
owner="$(cmd.exe /c 'echo %USERDOMAIN%\%USERNAME%' 2>/dev/null | tr -d '\r')"
profile="$(wslpath "$win_profile")"
key="${LAB_KEY:-$profile/.ssh/g23_lab.pub}"
[ -f "$key" ] || { echo "make_seeds: no lab key at $key" >&2; exit 1; }
cd /                                    # nothing is imported from the current folder
exec python3 -I -B "$here/seeds/make_seeds.py" \
    --inventory "$here/lab_vms.json" --key "$key" \
    --iso-dir "${LAB_ISO_DIR:-/mnt/d/os/AMD64-x86}" --seed-dir "${LAB_SEED_DIR:-/mnt/d/Hyper-V/fabric-lab/seed}" \
    --secrets-dir "$profile/fabric-lab" --secrets-win "$win_profile\\fabric-lab" --owner "$owner" "$@"
