"""Ubuntu Server's unattended install (subiquity autoinstall): a per-VM NoCloud seed ISO labelled CIDATA, and per
installer ISO a remastered copy whose GRUB entry boots with `autoinstall ds=nocloud` (subiquity otherwise asks to
confirm before it writes the disk).

Purpose: manual 3.1.5.3's Linux installs: labadmin with no password (locked), the lab key, passwordless sudo in
  /etc/sudoers.d/labadmin (0440), OpenSSH with password sign-in off, the static address; the router's extras.
Inputs: the inventory, the VM, the lab public key, the seed folder, the ISO folder.
Returns: the paths written.
Fails: CalledProcessError from xorriso.
Feeds: make_seeds.py; install_vm.ps1 attaches what it writes.
"""
import base64
import json
import os
import re
import tempfile

from build_iso import data_iso, extract, remaster
from lab_inventory import mac
from router_files import router_config

_SUDOERS = "labadmin ALL=(ALL) NOPASSWD:ALL\n"
_SSHD = ("# fabric lab (manual 3.1.5.3): key sign-in only\n"
         "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n")


def user_data(inv, vm, key):
    net = inv["network"]
    if vm["name"] == "g23-vm-rtr-1":
        network, packages, extra_late = router_config(inv, vm)
    else:
        network = {"version": 2, "ethernets": {"lab": {
            "match": {"macaddress": mac(vm, 1)}, "set-name": "lab",
            "addresses": [vm["ip"] + "/24"],
            "routes": [{"to": "default", "via": net["gateway"]}],
            "nameservers": {"addresses": [net["dns"]]}}}}
        packages, extra_late = [], []
    packages = packages + vm.get("packages", [])
    late = []
    for path, text, mode in (("/etc/sudoers.d/labadmin", _SUDOERS, "0440"),
                             ("/etc/ssh/sshd_config.d/10-fabric-lab.conf", _SSHD, "0644")):
        b64 = base64.b64encode(text.encode()).decode()
        late += [f"echo {b64} | base64 -d > /target{path}", f"chmod {mode} /target{path}"]
    late += ["curtin in-target -- visudo -cf /etc/sudoers.d/labadmin"]
    late += extra_late
    auto = {
        "version": 1,
        "interactive-sections": [],
        "locale": "en_US.UTF-8",
        "keyboard": {"layout": "us"},
        "timezone": "Etc/UTC",
        "refresh-installer": {"update": False},
        "network": network,
        "storage": {"layout": {"name": "lvm"}},
        "ssh": {"install-server": True, "allow-pw": False, "authorized-keys": []},
        "packages": packages,
        # the account comes from cloud-init on first boot: locked password, the lab key only
        "user-data": {
            "hostname": vm["name"],
            "fqdn": f'{vm["name"]}.{net["domain"]}',
            "preserve_hostname": False,
            "ssh_pwauth": False,
            "users": [{"name": "labadmin", "gecos": "fabric lab admin", "shell": "/bin/bash",
                       "groups": ["sudo"], "lock_passwd": True, "ssh_authorized_keys": [key]}],
        },
        "late-commands": late,
        "shutdown": "reboot",
    }
    # JSON is valid YAML, and quotes every value safely (1.1.5.7)
    return "#cloud-config\n" + json.dumps({"autoinstall": auto}, indent=2) + "\n"


def write_seed(inv, vm, key, seed_dir):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "user-data"), "w") as f:
            f.write(user_data(inv, vm, key))
        with open(os.path.join(d, "meta-data"), "w") as f:
            f.write(f'instance-id: {vm["name"]}\nlocal-hostname: {vm["name"]}\n')
        out = os.path.join(seed_dir, vm["name"] + ".iso")
        data_iso(d, "CIDATA", out)
    return out


def installer_iso_name(iso):
    return os.path.splitext(iso)[0] + "-autoinstall.iso"


def write_installer(iso_dir, iso, seed_dir):
    """The installer with `autoinstall ds=nocloud` on its first GRUB entry and a short timeout; made once per ISO."""
    out = os.path.join(seed_dir, installer_iso_name(iso))
    if os.path.exists(out):
        return out
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "grub.cfg")
        extract(os.path.join(iso_dir, iso), "/boot/grub/grub.cfg", cfg)
        with open(cfg) as f:
            text = f.read()
        text, n = re.subn(r"(linux\s+/casper/vmlinuz)(\s+)---", r"\1 autoinstall ds=nocloud\2---", text, count=1)
        if n != 1:
            raise RuntimeError(f"{iso}: no casper linux line in its grub.cfg to add autoinstall to")
        text = re.sub(r"^set timeout=\d+", "set timeout=3", text, count=1, flags=re.M)
        with open(cfg, "w") as f:
            f.write(text)
        remaster(os.path.join(iso_dir, iso), out, {"/boot/grub/grub.cfg": cfg})
    return out
