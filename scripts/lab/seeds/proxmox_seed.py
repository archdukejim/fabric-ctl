"""Proxmox VE's automated installation: the installer ISO prepared with answer.toml, the auto-installer mode file
(`mode = "iso"`, what `proxmox-auto-install-assistant prepare-iso --fetch-from iso` writes) and a first-boot hook.

Purpose: manual 3.1.5.3's Proxmox install: FQDN g23-vm-pve9-1.lab.test, static 10.88.0.22, root with the lab key
  (its required password generated, hashed into the answer, kept only in %USERPROFILE%\\fabric-lab\\pve-root.txt),
  then on first boot labadmin with sudo and the key, root's SSH sign-in by key only, password sign-in off.
Inputs: the inventory, the VM, the lab key, the root password, the ISO and seed folders.
Returns: the prepared ISO's path.
Fails: CalledProcessError from openssl or xorriso; RuntimeError if the ISO is not auto-install capable.
Feeds: make_seeds.py; install_vm.ps1 boots the VM from the prepared ISO.
"""
import json
import os
import subprocess
import tempfile

from build_iso import extract, remaster
from lab_inventory import mac

_FIRST_BOOT = r"""#!/bin/sh
# fabric lab (manual 3.1.5.3): Proxmox's first boot: labadmin with sudo and the lab key, key sign-in only
set -eu
for f in /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/ceph.sources; do
    [ -f "$f" ] && { grep -q '^Enabled:' "$f" || echo 'Enabled: no' >> "$f"; }
done
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y sudo
id labadmin >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo -c 'fabric lab admin' labadmin
passwd -l labadmin
install -d -m 0700 -o labadmin -g labadmin /home/labadmin/.ssh
printf '%s\n' @KEY@ > /home/labadmin/.ssh/authorized_keys
chown labadmin:labadmin /home/labadmin/.ssh/authorized_keys
chmod 0600 /home/labadmin/.ssh/authorized_keys
printf 'labadmin ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/labadmin
chmod 0440 /etc/sudoers.d/labadmin
visudo -cf /etc/sudoers.d/labadmin
printf '# fabric lab (manual 3.1.5.3): key sign-in only\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' \
    > /etc/ssh/sshd_config.d/10-fabric-lab.conf
systemctl reload ssh
"""


def _hash(password):
    """SHA-512 crypt, the password given on stdin (never on a command line)."""
    r = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=password + "\n",
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def _toml(value):
    return json.dumps(value)        # a TOML basic string or array of them is JSON's syntax


def answer(inv, vm, key, password):
    net = inv["network"]
    return f"""# fabric lab (manual 3.1.5.3): Proxmox VE automated installation
[global]
keyboard = "en-us"
country = "us"
fqdn = {_toml(vm["name"] + "." + net["domain"])}
mailto = "root@{net["domain"]}"
timezone = "UTC"
root-password-hashed = {_toml(_hash(password))}
root-ssh-keys = [{_toml(key)}]
reboot-on-error = false

[network]
source = "from-answer"
cidr = {_toml(vm["ip"] + "/24")}
dns = {_toml(net["dns"])}
gateway = {_toml(net["gateway"])}
filter.ID_NET_NAME_MAC = {_toml("enx" + mac(vm, 1, ""))}

[disk-setup]
filesystem = "ext4"
disk-list = ["sda"]

[first-boot]
source = "from-iso"
ordering = "fully-up"
"""


def write_seed(inv, vm, key, password, iso_dir, seed_dir):
    iso = os.path.join(iso_dir, vm["iso"])
    out = os.path.join(seed_dir, vm["name"] + ".iso")
    with tempfile.TemporaryDirectory() as d:
        probe = os.path.join(d, "capable")
        extract(iso, "/auto-installer-capable", probe)      # fails loudly if this ISO cannot auto-install
        files = {}
        for name, text, mode in (("answer.toml", answer(inv, vm, key, password), 0o600),
                                 ("auto-installer-mode.toml", 'mode = "iso"\n', 0o644),
                                 ("proxmox-first-boot", _FIRST_BOOT.replace("@KEY@", _shq(key)), 0o755)):
            p = os.path.join(d, name)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "w") as f:
                f.write(text)
            files["/" + name] = p
        remaster(iso, out, files, append=True)
    return out


def _shq(s):
    return "'" + s.replace("'", "'\\''") + "'"
