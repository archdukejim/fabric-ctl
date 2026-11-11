#!/usr/bin/env bash
# Writes the lab's unattended-install media into ~/fabric-lab/seed on the build VM (manual 3.1.5.3, decisions
# 2.1.1.65, 2.1.1.99.2); 3.1.5.3 copies the installer ISOs in from D:\os\AMD64-x86 and the media out to
# D:\Hyper-V\fabric-lab\seed. Run on g23-vm-dev-1, signed in with ssh -A: scripts/lab/make_seeds.sh [--only a,b]
# Needs xorriso and openssl (sudo apt-get install -y xorriso). The original ISOs are only read.
# Passwords (Windows' labadmin, Proxmox's root) are generated once into ~/fabric-lab (folder 0700, files 0600) and
# never printed. The lab public key is $LAB_KEY, or else the one key the forwarded agent holds.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
for t in xorriso openssl python3 ssh-add; do
    command -v "$t" >/dev/null || { echo "make_seeds: $t is missing (apt-get install -y xorriso openssl)" >&2; exit 1; }
done
lab="$HOME/fabric-lab"
mkdir -p "$lab"
chmod 0700 "$lab"
key="${LAB_KEY:-}"
if [ -z "$key" ]; then
    keys="$(ssh-add -L 2>/dev/null || true)"
    case "$keys" in
        ssh-*) ;;
        *) echo "make_seeds: no lab key: set LAB_KEY to its .pub file, or sign in with ssh -A (the agent holds none)" >&2
           exit 1 ;;
    esac
    [ "$(printf '%s\n' "$keys" | wc -l)" -eq 1 ] || {
        echo "make_seeds: the agent holds more than one key; set LAB_KEY to the lab key's .pub file" >&2; exit 1; }
    key="$lab/lab-key.pub"
    printf '%s\n' "$keys" > "$key"
fi
[ -f "$key" ] || { echo "make_seeds: no lab key at $key" >&2; exit 1; }
cd /                                    # nothing is imported from the current folder
exec python3 -I -B "$here/seeds/make_seeds.py" \
    --inventory "$here/lab_vms.json" --key "$key" \
    --iso-dir "${LAB_ISO_DIR:-$HOME/lab-iso}" --seed-dir "${LAB_SEED_DIR:-$lab/seed}" \
    --secrets-dir "$lab" "$@"
