"""Writes every lab VM's unattended-install media into the seed folder (manual 3.1.5.3, decision 2.1.1.65).

Purpose: the entry point make_seeds.sh runs in WSL; it only routes each VM to its installer's seed writer.
Inputs: --inventory, --key (the lab public key), --iso-dir, --seed-dir, --secrets-dir (WSL path of
  %USERPROFILE%\\fabric-lab), --secrets-win (its Windows path), --owner (DOMAIN\\user), --only (names, comma-separated).
Returns: exit 0 with one line per written file; passwords are never printed.
Fails: exit non-zero on the first failing VM (its writer's exception).
Feeds: install_vm.ps1, which attaches what this writes.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import proxmox_seed  # noqa: E402
import ubuntu_seed  # noqa: E402
import windows_seed  # noqa: E402
from lab_inventory import load_inventory  # noqa: E402
from lab_secret import lab_password  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    for a in ("--inventory", "--key", "--iso-dir", "--seed-dir", "--secrets-dir", "--secrets-win", "--owner"):
        ap.add_argument(a, required=True)
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    inv = load_inventory(args.inventory)
    with open(args.key, encoding="utf-8") as f:
        key = f.read().strip()
    if not key.startswith("ssh-") or "\n" in key:
        raise SystemExit(f"{args.key}: not one OpenSSH public key")
    only = [n.strip() for n in args.only.split(",") if n.strip()]
    vms = [v for v in inv["vms"] if not only or v["name"] in only]
    if only and len(vms) != len(only):
        raise SystemExit("unknown VM name in --only; known: " + ", ".join(v["name"] for v in inv["vms"]))
    os.makedirs(args.seed_dir, exist_ok=True)

    def password(name):
        return lab_password(os.path.join(args.secrets_dir, name), args.secrets_win + "\\" + name, args.owner)

    for vm in vms:
        kind = vm["installer"]
        if kind == "ubuntu-server":
            print("  installer", ubuntu_seed.write_installer(args.iso_dir, vm["iso"], args.seed_dir))
            print("  seed     ", ubuntu_seed.write_seed(inv, vm, key, args.seed_dir))
        elif kind in ("windows-server", "windows-client"):
            print("  seed     ", windows_seed.write_seed(inv, vm, key, password("windows-admin.txt"), args.seed_dir))
        elif kind == "proxmox":
            print("  installer", proxmox_seed.write_seed(inv, vm, key, password("pve-root.txt"),
                                                         args.iso_dir, args.seed_dir))
        else:
            raise SystemExit(f'{vm["name"]}: unknown installer {kind}')


if __name__ == "__main__":
    main()
